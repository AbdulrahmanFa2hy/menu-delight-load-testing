import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import { sessionAllowed, aggregateSummaries, transportFailureKind, transportErrorCodes, workloadThresholds, sanitizeDiagnostic, diagnosticBodyKind, diagnosticPeerClass } from './contracts.mjs';
import {capacityPlan, capacityStages} from './capacity-plan.mjs';

test('transport categories distinguish DNS, TCP, TLS, HTTP/2 and deadlines', () => {
  for (const [code, kind] of [[1050, 'timeout'], [1100, 'dns'], [1199, 'dns'],
    [1201, 'tcp'], [1220, 'tcp'], [1300, 'tls'], [1311, 'tls'],
    [1600, 'http2'], [1633, 'http2'], [1669, 'http2'], [1701, 'decompression']]) {
    assert.equal(transportFailureKind(0, code), kind);
  }
  assert.equal(transportFailureKind(200, 1220), null);
  assert.equal(transportFailureKind(503, 1503), null);
  assert.equal(transportFailureKind(0, 1000), 'other');
});
test('EOF labels cannot contain an error string or private URL', () => {
  const secret = 'https://private.example/asset?token=never-publish-this';
  for (const ending of ['EOF', 'unexpected EOF']) {
    const label = transportFailureKind(0, 1000, `Post "${secret}": ${ending}`);
    assert.equal(label, 'eof');
    assert.ok(!label.includes(secret));
  }
  assert.equal(transportFailureKind(0, 1000, secret), 'other');
});
test('HTTP 200 unavailable does not count as successful admission', () => {
  assert.equal(sessionAllowed(200, { status: 'unavailable' }), false);
  assert.equal(sessionAllowed(200, { status: 'allowed' }), false);
  assert.equal(sessionAllowed(200, { status: 'allowed', session_id: 'id', session_token: 'token' }), true);
});
function summary(node, positive = 1, negative = 1, ok = true) {
  const rates = Object.fromEntries(['errors', 'journey_success', 'tracking_admission_success', 'game_admission_success', 'asset_success', 'analytics_delivery_success', 'http_req_failed', 'menu_edge_hit', 'asset_edge_hit']
    .map(name => [name, { values: { rate: positive / (positive + negative), passes: positive, fails: negative }, thresholds: { 'rate>0': { ok: name === 'errors' ? ok : true } } }]));
  for (const name of ['menu_read_duration', 'tracking_session_duration', 'tracking_asset_duration', 'game_session_duration'])
    rates[name] = { values: { 'p(95)': 10 }, thresholds: { 'p(95)<2500': { ok: true } } };
  return { meta: { node_index: node, run_id: 'run', configured_vus: 10, duration_ms: 10000, finished_at: '2026-10-02T20:00:00Z' }, metrics: { ...rates, http_reqs: { values: { count: 50 } } } };
}
test('aggregation rejects missing, duplicate and mixed run summaries', () => {
  assert.throws(() => aggregateSummaries([], 2));
  assert.throws(() => aggregateSummaries([summary(1), summary(1)], 2));
  const mixed = summary(2); mixed.meta.run_id = 'other';
  assert.throws(() => aggregateSummaries([summary(1), mixed], 2));
});
test('rates are weighted by samples and a failed node fails the aggregate', () => {
  const result = aggregateSummaries([summary(1, 1, 0), summary(2, 0, 9, false)], 2);
  assert.equal(result.checked_errors.rate, 0.1);
  assert.equal(result.passed, false);
  assert.equal(result.average_requests_per_second, 10);
  assert.equal(result.nodes[1].failed_thresholds.length, 1);
});
test('aggregation retains numeric transport codes and failed thresholds', () => {
  const data = summary(1, 1, 1, false);
  data.metrics.transport_code_1633 = { values: { count: 2 } };
  data.metrics.transport_http2_errors = { values: { count: 2 } };
  const result = aggregateSummaries([data], 1);
  assert.deepEqual(result.transport_error_codes, {1633: 2});
  assert.equal(result.diagnostics.transport_http2_errors, 2);
  assert.equal(result.passed, false);
  assert.equal(new Set(transportErrorCodes).size, transportErrorCodes.length);
});
test('missing metrics, omitted thresholds and empty traffic cannot pass', () => {
  const missing = summary(1); delete missing.metrics.game_session_duration;
  assert.throws(() => aggregateSummaries([missing], 1));
  const omitted = summary(1); omitted.metrics.http_req_failed.thresholds = {};
  assert.throws(() => aggregateSummaries([omitted], 1));
  const empty = summary(1); empty.metrics.http_reqs.values.count = 0;
  assert.throws(() => aggregateSummaries([empty], 1));
});

test('isolated workloads enforce their exercised operations and cannot mix summaries', () => {
  for (const mode of ['tracking', 'games']) {
    const data = summary(1);data.meta.workload_mode = mode;
    for (const metric of Object.keys(data.metrics)) if (!(metric in workloadThresholds(mode)) && metric !== 'http_reqs') delete data.metrics[metric];
    assert.equal(aggregateSummaries([data], 1).passed, true);
    delete data.metrics[mode === 'tracking' ? 'tracking_admission_success' : 'game_admission_success'];
    assert.throws(() => aggregateSummaries([data], 1));
  }
  const data = summary(2);data.meta.workload_mode = 'games';
  assert.throws(() => aggregateSummaries([summary(1), data], 2));
  data.meta.workload_mode = 'mixed';data.meta.backend_route = 'backend_origin';
  assert.throws(() => aggregateSummaries([summary(1), data], 2));
  assert.throws(() => workloadThresholds('skip-all-checks'));
});

test('mixed workload retains every existing error, admission and latency gate', () => {
  assert.deepEqual(workloadThresholds(), {
    http_req_failed: ['rate<0.01'], errors: ['rate<0.01'], journey_success: ['rate>0.99'],
    tracking_admission_success: ['rate>0.99'], asset_success: ['rate>0.99'], analytics_delivery_success: ['rate>0.99'],
    tracking_session_duration: ['p(95)<2500'], tracking_asset_duration: ['p(95)<1000'],
    game_admission_success: ['rate>0.99'], game_session_duration: ['p(95)<2500'], menu_read_duration: ['p(95)<1000'],
  });
});

test('diagnostics reject unknown identities and never export URL, body or header secrets', () => {
  const secret = 'https://private.example/?token=never-log';
  const tags = {run_id: '37072786956-1', request_id: '7f84ce1a-8c12-4e56-9abc-0123456789ab', service: 'entertainment-session',
    status: '503', error_code: '0', started_ms: '1', duration_ms: '1200', body_kind: 'empty', proto: 'HTTP/2.0',
    cf_ray: secret, url: secret, error: secret, body: secret, authorization: secret};
  const result = sanitizeDiagnostic(tags, '2026-10-03T12:00:00Z');
  assert.equal(result.cf_ray, null);assert.ok(!JSON.stringify(result).includes(secret));
  assert.throws(() => sanitizeDiagnostic({...tags, service: secret}, result.utc));
  assert.throws(() => sanitizeDiagnostic({...tags, duration_ms: secret}, result.utc));
  assert.throws(() => sanitizeDiagnostic({...tags, run_id: secret}, result.utc));
  assert.equal(sanitizeDiagnostic({...tags, tls_handshaking_ms: '15000'}, result.utc).tls_handshaking_ms, 15000);
  assert.throws(() => sanitizeDiagnostic({...tags, waiting_ms: secret}, result.utc));
  assert.throws(() => sanitizeDiagnostic({...tags, connecting_ms: '-1'}, result.utc));
  assert.equal(diagnosticBodyKind(503, ''), 'empty');
  assert.equal(diagnosticBodyKind(503, '{"error":"temporarily_unavailable"}'), 'json_unavailable');
  assert.equal(diagnosticBodyKind(0, secret), 'transport');
});

test('network verification counts distinct actual exit IP fingerprints without raw IPs', () => {
  const a = summary(1), b = summary(2);
  a.meta.generator_network = b.meta.generator_network = {ip_fingerprint: 'a'.repeat(64), colo: 'IAD'};
  const r = aggregateSummaries([a,b], 2);
  assert.equal(r.generator_network.verified_nodes, 2);
  assert.equal(r.generator_network.distinct_exit_ips, 1);
});

test('public exporter keeps failed request correlation but drops raw metric secrets', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'benchmark-export-'));
  try {
    const secret = 'https://private.example/?token=never-export';
    const tags = {run_id: '37100000000-1', request_id: '7f84ce1a-8c12-4e56-9abc-0123456789ab', service: 'entertainment-session',
      status: '503', error_code: '0', started_ms: '1', duration_ms: '1200', body_kind: 'empty', proto: 'HTTP/2.0', cf_ray: '', url: secret};
    const network = {ip_fingerprint: 'a'.repeat(64), colo: 'IAD', cpu_count: 4, ipv6_available: false, proxy_configured: false};
    fs.writeFileSync(path.join(directory, 'generator-network.json'), JSON.stringify(network));
    fs.writeFileSync(path.join(directory, 'summary-node-1.json'), JSON.stringify({meta: {}}));
    const rows = [
      {type: 'Point', metric: 'http_req_duration', data: {tags: {url: secret}}},
      {type: 'Point', metric: 'generator_exit_probe', data: {tags: network}},
      {type: 'Point', metric: 'request_diagnostic', data: {time: '2026-10-03T12:00:00Z', tags}},
    ];
    fs.writeFileSync(path.join(directory, 'benchmark-private-metrics.json'), rows.map(x => JSON.stringify(x)).join('\n'));
    execFileSync(process.execPath, [fileURLToPath(new URL('./collect-diagnostics.mjs', import.meta.url))], {
      cwd: directory, env: {...process.env, RUNNER_TEMP: directory, NODE_INDEX: '1'}, stdio: 'pipe',
    });
    const output = fs.readFileSync(path.join(directory, 'diagnostics-node-1.json'), 'utf8');
    assert.ok(!output.includes(secret));
    const data = JSON.parse(output); assert.equal(data.failures, 1); assert.equal(data.records[0].request_id, tags.request_id);
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory, 'summary-node-1.json'))).meta.generator_network.k6_verified, true);
  } finally { fs.rmSync(directory, {recursive: true, force: true}); }
});

test('larger stages require verified concurrent generator capacity and bounded diagnostics', () => {
  const nodes = [10, 10, 10, 10, 20, 30, 50, 75, 100];
  capacityStages.forEach((vus, i) => {
    const plan = capacityPlan(vus, 100);
    assert.equal(plan.nodes, nodes[i]);
    assert.equal(plan.nodes * plan.vus_per_node, vus);
    assert.ok(plan.expected_public_events_per_ip_second < plan.public_events_per_ip_second_budget);
  });
  assert.throws(() => capacityPlan(2000, 10), /Need 20/);
  assert.throws(() => capacityPlan(10000, 20), /Need 100/);
  assert.equal(capacityPlan(500, 10, true).vus_per_node, 50);
  assert.equal(capacityPlan(1000, 10, true).vus_per_node, 100);
  assert.throws(() => capacityPlan(2000, 20, true), /1000/);
  assert.throws(() => capacityPlan(1000, 0));
  assert.throws(() => capacityPlan(123, 10));
});

function readySummary(node, startOffset = 0, ip = String(node).repeat(64)) {
  const data = summary(node, 1, 0);
  data.meta.configured_vus = 100;
  data.meta.capacity_validation = {schema: 1, hold_seconds: 300, scheduled_start_ms: 1791036000000,
    scenario_start_ms: 1791036000000 + startOffset, observed_peak_vus: 100};
  data.meta.generator_network = {ip_fingerprint: ip, k6_verified: true, colo: 'IAD'};
  return data;
}
test('queued or missing peak workloads and unverified exits cannot certify capacity', () => {
  const a = readySummary(1), b = readySummary(2, 500);
  let result = aggregateSummaries([a, b], 2);
  assert.equal(result.passed, true);
  assert.equal(result.capacity_readiness.total_configured_vus, 200);
  assert.equal(result.capacity_readiness.common_peak_hold_ms, 299500);
  b.meta.capacity_validation.scenario_start_ms += 60000;
  assert.equal(aggregateSummaries([a, b], 2).passed, false);
  b.meta.capacity_validation.scenario_start_ms = a.meta.capacity_validation.scenario_start_ms;
  b.meta.capacity_validation.observed_peak_vus = 99;
  assert.equal(aggregateSummaries([a, b], 2).passed, false);
  b.meta.capacity_validation.observed_peak_vus = 100;
  b.meta.generator_network.k6_verified = false;
  assert.equal(aggregateSummaries([a, b], 2).passed, false);
});
test('shared exits must fit the reserved public rate budget', () => {
  const a = readySummary(1), b = readySummary(2, 0, a.meta.generator_network.ip_fingerprint);
  assert.equal(aggregateSummaries([a, b], 2).passed, false);
  a.meta.configured_vus = b.meta.configured_vus = 25;
  assert.equal(aggregateSummaries([a, b], 2).passed, true);
});
test('standard runs verify the k6 exit without uploading raw metric or setup data', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'benchmark-network-'));
  try {
    const network = {ip_fingerprint: 'a'.repeat(64), colo: 'IAD', cpu_count: 4};
    fs.writeFileSync(path.join(directory, 'generator-network.json'), JSON.stringify(network));
    fs.writeFileSync(path.join(directory, 'summary-node-100.json'), JSON.stringify({meta: {generator_probe: network}}));
    const script = fileURLToPath(new URL('./collect-diagnostics.mjs', import.meta.url));
    execFileSync(process.execPath, [script], {cwd: directory, env: {...process.env, RUNNER_TEMP: directory, NODE_INDEX: '100'}, stdio: 'pipe'});
    let data = JSON.parse(fs.readFileSync(path.join(directory, 'summary-node-100.json')));
    assert.equal(data.meta.generator_network.k6_verified, true);
    assert.equal(data.meta.generator_probe, undefined);
    fs.writeFileSync(path.join(directory, 'summary-node-100.json'), JSON.stringify({meta: {generator_probe: {...network, ip_fingerprint: 'b'.repeat(64)}}}));
    assert.throws(() => execFileSync(process.execPath, [script], {cwd: directory, env: {...process.env, RUNNER_TEMP: directory, NODE_INDEX: '100'}, stdio: 'pipe'}));
  } finally { fs.rmSync(directory, {recursive: true, force: true}); }
});

test('readiness reports require every concurrent generator, distinct exits and timely starts', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'benchmark-readiness-'));
  try {
    fs.mkdirSync(path.join(directory, 'summaries'));
    const rows = Array.from({length: 20}, (_, i) => ({meta: {node_index: i + 1, run_id: '123456789-1', generator_readiness_only: true,
      scheduled_start_ms: 1791036000000, readiness_start_ms: 1791036000000 + i,
      generator_network: {k6_verified: true, ip_fingerprint: 'a'.repeat(62) + i.toString(16).padStart(2, '0')}}}));
    const write = () => rows.forEach((row, i) => fs.writeFileSync(path.join(directory, 'summaries', `summary-node-${i+1}.json`), JSON.stringify(row)));
    const check = () => execFileSync(process.execPath, [fileURLToPath(new URL('./aggregate-readiness.mjs', import.meta.url))], {
      cwd: directory, env: {...process.env, EXPECTED_NODES: '20'}, stdio: 'pipe'});
    write();check();
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory, 'generator-readiness-result.json'))).server_capacity_tested, false);
    rows[19].meta.readiness_start_ms += 60000;write();assert.throws(check);
    rows[19].meta.readiness_start_ms -= 60000;
    rows[19].meta.generator_network.ip_fingerprint = rows[0].meta.generator_network.ip_fingerprint;write();assert.throws(check);
    fs.unlinkSync(path.join(directory, 'summaries', 'summary-node-20.json'));assert.throws(check);
  } finally { fs.rmSync(directory, {recursive: true, force: true}); }
});

test('peer classification identifies the TCP leg without exporting addresses', () => {
  const ranges = JSON.parse(fs.readFileSync(new URL('./cloudflare-ipv4-ranges.json', import.meta.url)));
  for (const ip of ['104.16.0.0', '104.23.255.255', '172.64.0.1', '173.245.48.1'])
    assert.equal(diagnosticPeerClass(ip, '198.51.100.7', ranges), 'cloudflare');
  assert.equal(diagnosticPeerClass('198.51.100.7', '198.51.100.7', ranges), 'configured_origin');
  assert.equal(diagnosticPeerClass('104.15.255.255', '', ranges), 'other');
  assert.equal(diagnosticPeerClass('256.1.1.1', '', ranges), 'unknown');
  assert.equal(diagnosticPeerClass('private-capability-value', '', ranges), 'unknown');
});

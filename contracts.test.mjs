import test from 'node:test';
import assert from 'node:assert/strict';
import { sessionAllowed, aggregateSummaries, transportFailureKind, transportErrorCodes } from './contracts.mjs';

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

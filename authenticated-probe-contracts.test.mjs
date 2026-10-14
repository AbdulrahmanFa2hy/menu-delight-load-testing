import test from 'node:test';
import assert from 'node:assert/strict';
import {authenticatedPlan, sanitizeAuthenticatedProbe, safeAuthenticatedSummary, authenticatedSummaryMeta} from './authenticated-probe-contracts.mjs';
test('enabled k6 trend fields retain the actual start without an unavailable min', () => {
  const data = {metrics:{probe_start:{values:{avg:10001,'p(95)':10001,max:10001}}},setup_data:{ip_fingerprint:'a'.repeat(64),colo:'ORD'}};
  assert.equal(authenticatedSummaryMeta(data,{start_ms:10000}).scenario_start_ms,10001);
});
test('paired service routes swap on the same generators with bounded request budgets', () => {
  const odd = authenticatedPlan(1, 10000, 300), even = authenticatedPlan(2, 10000, 300);
  assert.deepEqual(odd.map(c => c.name), ['tracking/cloudflare', 'tracking/origin', 'games/cloudflare', 'games/origin']);
  assert.deepEqual(even.map(c => c.name), ['tracking/origin', 'tracking/cloudflare', 'games/origin', 'games/cloudflare']);
  assert.deepEqual(odd.map(c => c.start_ms), even.map(c => c.start_ms));
  assert.equal(odd.reduce((n,c) => n + c.iterations * 25 * 2, 0) * 10, 96000);
  assert.throws(() => authenticatedPlan(11, 10000, 300));
  assert.throws(() => authenticatedPlan(1, 10000, 120));
});
const tags = {run_id:'123-1',node:'1',service:'image-tracking-session',request_id:'12345678-1234-4234-8234-123456789abc',
  workload:'tracking',route:'cloudflare',connections:'keepalive',action:'admission',vu:'1',iteration:'0',status:'200',error_code:'0',
  started_ms:'10000',finished_ms:'10100',duration_ms:'100',body_kind:'json_other',proto:'HTTP/2.0',response_bytes:'900',
  connection_sequence:'1',since_last_connect_ms:'0',since_previous_response_ms:'0',operation_ok:'true'};
test('response and VU connection evidence exclude bodies, capabilities and raw addresses', () => {
  const row = sanitizeAuthenticatedProbe({...tags, body:'secret', url:'https://private/token', Authorization:'secret', remote_ip:'1.2.3.4'}, '2026-10-14T00:00:00Z', 48);
  assert.equal(row.response_bytes, 900); assert.equal(row.operation_ok, true);
  assert.equal(row.connection_context, 'vu_observed_connect');
  assert.doesNotMatch(JSON.stringify(row), /secret|private|https:|Authorization|remote_ip/);
  for (const change of [{iteration:'48'},{vu:'26'},{response_bytes:'-1'},{route:'origin',peer_class:'cloudflare'},
    {service:'entertainment-session'},{finished_ms:'9000'},{request_id:''},{since_last_connect_ms:'600001'}])
    assert.throws(() => sanitizeAuthenticatedProbe({...tags,...change}, '2026-10-14T00:00:00Z', 48));
});
test('completion differs from SLO pass and setup credentials cannot enter summaries', () => {
  const expected = {run_id:'123-1',node:1,workload:'tracking',route:'cloudflare',connections:'keepalive',iterations:48,start_ms:10000};
  const data = {meta:{...expected,scenario_start_ms:10001,network:{ip_fingerprint:'a'.repeat(64),colo:'ORD',secret:'secret'}},
    setup_data:{token:'secret'},metrics:{iterations:{values:{count:1200}},authenticated_probe:{values:{count:2400}}}};
  const row = safeAuthenticatedSummary(data, expected);
  assert.equal(row.complete, true); assert.equal(row.criteria_passed, false);
  assert.doesNotMatch(JSON.stringify(row), /secret|token|setup_data/);
  data.metrics.iterations.values.count = 1199; assert.equal(safeAuthenticatedSummary(data, expected).complete, false);
  data.meta.scenario_start_ms = 13000; assert.throws(() => safeAuthenticatedSummary(data, expected));
});

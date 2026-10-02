import test from 'node:test';
import assert from 'node:assert/strict';
import { sessionAllowed, aggregateSummaries } from './contracts.mjs';

test('HTTP 200 unavailable does not count as successful admission', () => {
  assert.equal(sessionAllowed(200, { status: 'unavailable' }), false);
  assert.equal(sessionAllowed(200, { status: 'allowed' }), false);
  assert.equal(sessionAllowed(200, { status: 'allowed', session_id: 'id', session_token: 'token' }), true);
});
function summary(node, positive = 1, negative = 1, ok = true) {
  const rates = Object.fromEntries(['errors', 'journey_success', 'tracking_admission_success', 'game_admission_success', 'asset_success', 'analytics_delivery_success', 'http_req_failed', 'menu_edge_hit', 'asset_edge_hit']
    .map(name => [name, { values: { passes: positive, fails: negative }, thresholds: name === 'errors' ? { 'rate<0.01': { ok } } : {} }]));
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

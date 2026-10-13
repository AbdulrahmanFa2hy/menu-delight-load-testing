import test from 'node:test';
import assert from 'node:assert/strict';
import {transportPlan, clientPlan, sanitizeTransportProbe, safeTransportSummary} from './transport-probe-contracts.mjs';

test('client comparison keeps both versions and connection controls on every runner', () => {
  const odd = clientPlan(1, 10000), even = clientPlan(2, 10000);
  assert.deepEqual(odd.map(c => c.name), even.map(c => c.name).reverse());
  assert.deepEqual(odd.map(c => c.start_ms), [10000, 90000, 170000, 250000]);
  assert.ok(odd.every(c => c.route === 'cloudflare'));
  assert.throws(() => clientPlan(11, 10000));
});

test('all four routes/modes stay on each runner with counterbalanced fixed request budgets', () => {
  const odd = transportPlan(1, 10000), even = transportPlan(2, 10000);
  assert.deepEqual(odd.map(c => c.name), even.map(c => c.name).reverse());
  assert.deepEqual(odd.map(c => c.start_ms), [10000, 90000, 170000, 250000]);
  assert.throws(() => transportPlan(11, 10000));
});
const tags = {run_id: '123-1', node: '1', service: 'other', request_id: '12345678-1234-4234-8234-123456789abc',
  route: 'cloudflare', connections: 'keepalive', vu: '1', iteration: '0', status: '0', error_code: '1050',
  started_ms: '10000', finished_ms: '25000', duration_ms: '0', body_kind: 'transport', proto: '',
  response_bytes: '0', url: 'https://private/token', authorization: 'secret', raw_error: 'private'};
test('zero-phase timeout retains full request window and strips URL, token and raw error', () => {
  const result = sanitizeTransportProbe(tags, '2026-10-11T00:00:25Z');
  assert.equal(result.wall_duration_ms, 15000);
  assert.equal(result.duration_ms, 0);
  assert.equal(result.request_id, tags.request_id);
  assert.doesNotMatch(JSON.stringify(result), /private|secret|authorization|raw_error|https:/);
});
test('successful origin response requires verified origin peer and bounded request identity', () => {
  assert.throws(() => sanitizeTransportProbe({...tags, client_version: 'latest'}, '2026-10-11T00:00:25Z'));
  assert.throws(() => sanitizeTransportProbe({...tags, route: 'origin', status: '401', peer_class: 'cloudflare'}, '2026-10-11T00:00:25Z'));
  assert.throws(() => sanitizeTransportProbe({...tags, iteration: '8'}, '2026-10-11T00:00:25Z'));
  assert.throws(() => sanitizeTransportProbe({...tags, finished_ms: '9000'}, '2026-10-11T00:00:25Z'));
});
test('decoded body bytes and encoded HTTP length stay distinct without exposing headers', () => {
  const record = sanitizeTransportProbe({...tags, status: '401', error_code: '1401', response_bytes: '40',
    body_encoding: 'gzip', response_content_length: '60', headers: {Authorization: 'secret'}}, '2026-10-11T00:00:25Z');
  assert.equal(record.response_bytes, 40);
  assert.equal(record.response_content_length, 60);
  assert.equal(record.body_encoding, 'gzip');
  assert.doesNotMatch(JSON.stringify(record), /secret|Authorization|headers/);
  assert.equal(sanitizeTransportProbe(tags, '2026-10-11T00:00:25Z').body_encoding, 'unknown');
});
test('summary requires actual start, full iteration coverage and sanitizes setup data', () => {
  const expected = {run_id: '123-1', node: 1, route: 'cloudflare', connections: 'keepalive', start_ms: 10000};
  const summary = {meta: {...expected, scenario_start_ms: 10001,
    network: {ip_fingerprint: 'a'.repeat(64), colo: 'ORD', token: 'secret'}},
    setup_data: {token: 'secret'}, metrics: Object.fromEntries(['http_reqs', 'iterations', 'transport_probe']
      .map(name => [name, {values: {count: 800}}]))};
  assert.equal(safeTransportSummary(summary, expected).complete, true);
  assert.doesNotMatch(JSON.stringify(safeTransportSummary(summary, expected)), /secret|token|setup_data/);
  summary.metrics.iterations.values.count = 799;
  assert.equal(safeTransportSummary(summary, expected).complete, false);
  summary.meta.scenario_start_ms = 13000;
  assert.throws(() => safeTransportSummary(summary, expected));
});

test('a mislabeled client summary cannot be accepted for the comparison', () => {
  const expected = {run_id: '123-1', node: 1, route: 'cloudflare', connections: 'keepalive', start_ms: 10000, client_version: '2.3.0'};
  const summary = {meta: {...expected, client_version: '1.3.0', scenario_start_ms: 10001,
    network: {ip_fingerprint: 'a'.repeat(64), colo: 'ORD'}}, metrics: {}};
  assert.throws(() => safeTransportSummary(summary, expected));
});

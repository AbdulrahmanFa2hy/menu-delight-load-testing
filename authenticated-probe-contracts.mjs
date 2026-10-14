import {sanitizeDiagnostic} from './contracts.mjs';

export const authenticatedCases = ['tracking/cloudflare', 'tracking/origin', 'games/cloudflare', 'games/origin'];
export const authenticatedVus = 25;
export const authenticatedPacingMs = 6250;
export function authenticatedPlan(node, start, seconds) {
  if (!Number.isInteger(node) || node < 1 || node > 10 || !Number.isSafeInteger(start) || start <= 0 || ![60, 300].includes(seconds))
    throw new Error('Invalid authenticated schedule');
  // Compare both routes at the same time, then swap on the same generators.
  const order = node % 2 ? authenticatedCases : ['tracking/origin', 'tracking/cloudflare', 'games/origin', 'games/cloudflare'];
  const iterations = seconds === 300 ? 48 : 8;
  const slot_ms = seconds === 300 ? 340000 : 80000;
  return order.map((name, index) => ({name, start_ms: start + index * slot_ms, iterations, slot_ms}));
}

export function sanitizeAuthenticatedProbe(tags, utc, iterations) {
  const node = Number(tags.node), vu = Number(tags.vu), iteration = Number(tags.iteration);
  const service = tags.workload === 'tracking' ? ['image-tracking-session', 'image-tracking-event'] : ['entertainment-session'];
  const action = tags.action;
  if (!authenticatedCases.includes(`${tags.workload}/${tags.route}`) || !['keepalive', 'fresh_iteration'].includes(tags.connections) ||
      !Number.isInteger(node) || node < 1 || node > 10 || !Number.isInteger(vu) || vu < 1 || vu > authenticatedVus ||
      ![8, 48].includes(iterations) || !Number.isInteger(iteration) || iteration < 0 || iteration >= iterations ||
      !service.includes(tags.service) || !['admission', 'delivery'].includes(action) ||
      (tags.workload === 'tracking' && tags.service !== (action === 'admission' ? service[0] : service[1])))
    throw new Error('Invalid authenticated request context');
  const row = sanitizeDiagnostic(tags, utc);
  if (!row.request_id || row.finished_ms === undefined || (tags.route === 'origin' && row.status && row.peer_class !== 'configured_origin'))
    throw new Error('Missing identity/window or incorrect origin peer');
  const safe = {kind: 'request', ...row, node, vu, iteration, workload: tags.workload, route: tags.route, connections: tags.connections, action};
  for (const key of ['response_bytes', 'connection_sequence', 'since_last_connect_ms', 'since_previous_response_ms']) {
    const value = Number(tags[key]);
    const max = key === 'response_bytes' ? 2 * 1024 * 1024 : key === 'connection_sequence' ? 96 : 600000;
    if (!Number.isSafeInteger(value) || value < 0 || value > max) throw new Error('Invalid bounded response/connection context');
    safe[key] = value;
  }
  const length = /^\d{1,7}$/.test(tags.response_content_length ?? '') ? Number(tags.response_content_length) : null;
  safe.response_content_length = length !== null && length <= 2 * 1024 * 1024 ? length : null;
  safe.body_encoding = ['identity', 'gzip', 'br', 'deflate', 'zstd'].includes(tags.body_encoding) ? tags.body_encoding : 'unknown';
  safe.response_connection = ['close', 'keep-alive'].includes(tags.response_connection) ? tags.response_connection : 'unknown';
  safe.operation_ok = tags.operation_ok === 'true';
  safe.connection_context = 'vu_observed_connect'; // Not an exact socket ID; HTTP/2 can multiplex.
  return safe;
}

export function safeAuthenticatedSummary(data, expected) {
  const meta = data.meta;
  if (!meta || Object.entries(expected).some(([key, value]) => meta[key] !== value) ||
      !/^[0-9a-f]{64}$/.test(meta.network?.ip_fingerprint) || !/^[A-Z]{3}$/.test(meta.network?.colo) ||
      !Number.isSafeInteger(meta.scenario_start_ms) || meta.scenario_start_ms < expected.start_ms || meta.scenario_start_ms > expected.start_ms + 2000)
    throw new Error('Missing or late authenticated case evidence');
  const counts = Object.fromEntries(['iterations', 'dropped_iterations', 'authenticated_probe', 'transport_failures', 'admissions', 'deliveries', 'accepted_events', 'journeys_ok']
    .map(key => [key, Number(data.metrics?.[key]?.values?.count ?? 0)]));
  if (!Object.values(counts).every(value => Number.isSafeInteger(value) && value >= 0) || counts.authenticated_probe > authenticatedVus * expected.iterations * 2)
    throw new Error('Invalid authenticated counts');
  const criteria = Object.fromEntries(Object.entries(data.metrics ?? {}).filter(([, value]) => value.thresholds)
    .map(([key, value]) => [key, Object.values(value.thresholds).every(t => t.ok === true)]));
  const required = ['http_req_failed', 'errors', 'journey_success', 'admission_success', 'delivery_success', 'session_duration'];
  const latency = Object.fromEntries(['avg', 'p(95)', 'max'].map(key => [key, data.metrics?.session_duration?.values?.[key] ?? null]));
  return {kind: 'case_final', ...expected, vus: authenticatedVus, pacing_ms: authenticatedPacingMs,
    network: {ip_fingerprint: meta.network.ip_fingerprint, colo: meta.network.colo}, scenario_start_ms: meta.scenario_start_ms,
    counts, criteria, criteria_passed: required.every(key => criteria[key] === true), session_duration: latency,
    complete: counts.iterations === authenticatedVus * expected.iterations && !counts.dropped_iterations};
}

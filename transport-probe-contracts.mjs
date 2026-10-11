import {sanitizeDiagnostic} from './contracts.mjs';

export const transportCases = ['cloudflare/keepalive', 'origin/fresh_iteration', 'cloudflare/fresh_iteration', 'origin/keepalive'];
export const probeVus = 100;
export const probeIterations = 8;
export const probePacingMs = 6250;
export const probeSlotMs = 80000;

export function transportPlan(node, start) {
  if (!Number.isInteger(node) || node < 1 || node > 10 || !Number.isSafeInteger(start) || start <= 0)
    throw new Error('Invalid transport schedule');
  const cases = node % 2 ? transportCases : [...transportCases].reverse();
  return cases.map((name, index) => ({name, start_ms: start + index * probeSlotMs}));
}

export function sanitizeTransportProbe(tags, utc) {
  const node = Number(tags.node);
  const bytes = Number(tags.response_bytes);
  const vu = Number(tags.vu), iteration = Number(tags.iteration);
  if (!Number.isInteger(node) || node < 1 || node > 10 ||
      !transportCases.includes(`${tags.route}/${tags.connections}`) ||
      !Number.isSafeInteger(bytes) || bytes < 0 || bytes > 2 * 1024 * 1024 ||
      !Number.isInteger(vu) || vu < 1 || vu > probeVus ||
      !Number.isInteger(iteration) || iteration < 0 || iteration >= probeIterations)
    throw new Error('Invalid transport probe');
  const record = sanitizeDiagnostic(tags, utc);
  if (!record.request_id || record.finished_ms === undefined) throw new Error('Missing request identity/window');
  if (tags.route === 'origin' && record.peer_class !== 'configured_origin' && record.status !== 0)
    throw new Error('Origin response used an unexpected peer');
  const encoding = ['identity', 'gzip', 'br', 'deflate', 'zstd'].includes(tags.body_encoding) ? tags.body_encoding : 'unknown';
  const contentLength = /^\d{1,7}$/.test(tags.response_content_length ?? '') ? Number(tags.response_content_length) : null;
  return {kind: 'request', ...record, node, route: tags.route, connections: tags.connections,
    response_bytes: bytes, body_encoding: encoding,
    response_content_length: contentLength !== null && contentLength <= 2 * 1024 * 1024 ? contentLength : null,
    vu, iteration};
}

export function safeTransportSummary(data, expected) {
  const meta = data.meta;
  if (!meta || meta.node !== expected.node || meta.route !== expected.route || meta.connections !== expected.connections ||
      meta.run_id !== expected.run_id || !/^[0-9a-f]{64}$/.test(meta.network?.ip_fingerprint) ||
      !/^[A-Z]{3}$/.test(meta.network?.colo) || !Number.isSafeInteger(meta.scenario_start_ms) ||
      meta.scenario_start_ms < expected.start_ms || meta.scenario_start_ms > expected.start_ms + 2000)
    throw new Error('Missing or late transport case evidence');
  const counts = Object.fromEntries(['http_reqs', 'iterations', 'dropped_iterations', 'transport_probe', 'transport_failures', 'unexpected_status']
    .map(name => [name, Number(data.metrics?.[name]?.values?.count ?? 0)]));
  if (!Object.values(counts).every(n => Number.isSafeInteger(n) && n >= 0) ||
      counts.transport_probe > probeVus * probeIterations || counts.unexpected_status)
    throw new Error('Invalid transport case counts');
  return {kind: 'case_final', ...expected, vus: probeVus, iterations_per_vu: probeIterations,
    pacing_ms: probePacingMs, expected_requests: probeVus * probeIterations,
    network: {ip_fingerprint: meta.network.ip_fingerprint, colo: meta.network.colo},
    scenario_start_ms: meta.scenario_start_ms, counts,
    complete: counts.transport_probe === probeVus * probeIterations && counts.iterations === probeVus * probeIterations && !counts.dropped_iterations};
}

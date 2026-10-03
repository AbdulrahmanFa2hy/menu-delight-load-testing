export function sessionAllowed(status, body) {
  return status === 200 && body?.status === 'allowed' &&
    typeof body.session_token === 'string' && body.session_token.length > 0 &&
    typeof body.session_id === 'string' && body.session_id.length > 0;
}

// Fixed labels only: raw errors can contain private capability URLs.
export function transportFailureKind(status, code, message = '') {
  if (status !== 0) return null;
  if (code === 1050) return 'timeout';
  if (code >= 1100 && code < 1200) return 'dns';
  if (code >= 1200 && code < 1300) return 'tcp';
  if (code >= 1300 && code < 1400) return 'tls';
  if (code >= 1600 && code < 1700) return 'http2';
  if (code === 1701) return 'decompression';
  if (/(?:^|[ :])(?:unexpected )?EOF$/i.test(String(message).trim())) return 'eof';
  return 'other';
}
export const transportErrorCodes = [0, 1000, 1010, 1020, 1050, 1100, 1101, 1110, 1111,
  1200, 1201, 1202, 1210, 1211, 1212, 1213, 1220, 1300, 1310, 1311, 1600, 1610,
  1630, 1650, 1701, ...Array.from({length: 19}, (_, i) => 1611 + i),
  ...Array.from({length: 19}, (_, i) => 1631 + i), ...Array.from({length: 19}, (_, i) => 1651 + i)];

export function workloadThresholds(mode = 'mixed') {
  if (!['mixed', 'tracking', 'games'].includes(mode)) throw new Error('Unknown workload mode');
  return {
    http_req_failed: ['rate<0.01'], errors: ['rate<0.01'], journey_success: ['rate>0.99'],
    ...(mode !== 'games' ? {tracking_admission_success: ['rate>0.99'], asset_success: ['rate>0.99'],
      analytics_delivery_success: ['rate>0.99'], tracking_session_duration: ['p(95)<2500'], tracking_asset_duration: ['p(95)<1000']} : {}),
    ...(mode !== 'tracking' ? {game_admission_success: ['rate>0.99'], game_session_duration: ['p(95)<2500']} : {}),
    ...(mode === 'mixed' ? {menu_read_duration: ['p(95)<1000']} : {}),
  };
}

export function diagnosticBodyKind(status, text) {
  if (status === 0) return 'transport';
  if (!text) return 'empty';
  try { return JSON.parse(text)?.error === 'temporarily_unavailable' ? 'json_unavailable' : 'json_other'; }
  catch { return 'non_json'; }
}

export function sanitizeDiagnostic(tags, utc) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const services = ['image-tracking-session', 'image-tracking-event', 'entertainment-session', 'menu-page', 'public-menu', 'menu-analytics', 'protected-asset', 'xr-engine', 'other'];
  if (!services.includes(tags.service) || !['transport', 'empty', 'json_unavailable', 'json_other', 'non_json'].includes(tags.body_kind) ||
    !/^\d{1,20}-\d{1,3}$/.test(tags.run_id) || !Number.isFinite(Date.parse(utc))) throw new Error('Invalid diagnostic identity');
  const result = {utc, run_id: tags.run_id, service: tags.service, request_id: uuid.test(tags.request_id) ? tags.request_id : null,
    status: Number(tags.status), error_code: Number(tags.error_code), started_ms: Number(tags.started_ms), duration_ms: Number(tags.duration_ms),
    body_kind: tags.body_kind, proto: ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0'].includes(tags.proto) ? tags.proto : 'unknown',
    peer_ip_fingerprint: /^[0-9a-f]{64}$/.test(tags.peer_ip_fingerprint ?? '') ? tags.peer_ip_fingerprint : null,
    client_port: /^\d{1,5}$/.test(tags.client_port ?? '') && Number(tags.client_port) > 0 && Number(tags.client_port) <= 65535 ? Number(tags.client_port) : null,
    cf_ray: /^[0-9a-f]{16}-[A-Z]{3}$/.test(tags.cf_ray) ? tags.cf_ray : null};
  if (![result.status, result.error_code, result.started_ms, result.duration_ms].every(Number.isFinite) ||
    result.status < 0 || result.status > 599 || result.duration_ms < 0) throw new Error('Invalid diagnostic numeric value');
  return result;
}

export function aggregateSummaries(summaries, expectedNodes = 10) {
  if (summaries.length !== expectedNodes) throw new Error(`Expected ${expectedNodes} summaries; received ${summaries.length}`);
  const indices = new Set();
  const first = summaries[0]?.meta;
  for (const data of summaries) {
    const meta = data.meta;
    if (!meta || !Number.isInteger(meta.node_index) || meta.node_index < 1 || meta.node_index > expectedNodes || indices.has(meta.node_index))
      throw new Error('Missing or duplicate node identity');
    indices.add(meta.node_index);
    if (!meta.run_id || meta.run_id !== first.run_id || meta.configured_vus !== first.configured_vus ||
      (meta.workload_mode ?? 'mixed') !== (first.workload_mode ?? 'mixed') ||
      (meta.backend_route ?? 'cloudflare') !== (first.backend_route ?? 'cloudflare') ||
      (meta.connections ?? 'keepalive') !== (first.connections ?? 'keepalive') ||
      !(meta.duration_ms > 0) || !Number.isFinite(Date.parse(meta.finished_at))) throw new Error('Invalid or mixed run metadata');
    if (!Number.isFinite(meta.configured_vus) || meta.configured_vus < 1 || !Number.isFinite(meta.duration_ms) || !(data.metrics?.http_reqs?.values?.count > 0))
      throw new Error('Node performed no valid workload');
    for (const required of Object.keys(workloadThresholds(meta.workload_mode ?? 'mixed'))) {
      const metric = data.metrics?.[required];
      if (!metric || !Object.keys(metric.thresholds ?? {}).length) throw new Error(`Missing required metric or thresholds: ${required}`);
      if ('rate' in (metric.values ?? {}) && !(metric.values.passes + metric.values.fails > 0)) throw new Error(`Metric has no samples: ${required}`);
    }
  }
  const count = name => summaries.reduce((n, d) => n + (d.metrics[name]?.values?.count ?? 0), 0);
  const rate = name => {
    const positive = summaries.reduce((n, d) => n + (d.metrics[name]?.values?.passes ?? 0), 0);
    const negative = summaries.reduce((n, d) => n + (d.metrics[name]?.values?.fails ?? 0), 0);
    return { positive, negative, samples: positive + negative, rate: positive + negative ? positive / (positive + negative) : null };
  };
  const nodes = summaries.map(d => ({ node: d.meta.node_index, passed: true, failed_thresholds: [] }));
  summaries.forEach((d, i) => {
    const thresholds = Object.entries(d.metrics).flatMap(([name, m]) => Object.entries(m.thresholds ?? {}).map(([expression, result]) => ({ name, expression, ok: result.ok })));
    if (!thresholds.length) throw new Error('Summary contains no threshold results');
    nodes[i].failed_thresholds = thresholds.filter(t => t.ok !== true).map(t => `${t.name}: ${t.expression}`);
    nodes[i].passed = !nodes[i].failed_thresholds.length;
  });
  const end = Math.max(...summaries.map(d => Date.parse(d.meta.finished_at)));
  const start = Math.min(...summaries.map(d => Date.parse(d.meta.finished_at) - d.meta.duration_ms));
  const wallSeconds = (end - start) / 1000;
  const latencies = Object.fromEntries(['menu_read_duration', 'tracking_session_duration', 'tracking_asset_duration', 'game_session_duration'].map(name => {
    const values = summaries.map(d => d.metrics[name]?.values?.['p(95)']).filter(Number.isFinite);
    return [name, { mean_node_p95_ms: values.length ? values.reduce((a, b) => a + b, 0) / values.length : null, worst_node_p95_ms: values.length ? Math.max(...values) : null }];
  }));
  const network = summaries.map(d => d.meta.generator_network).filter(n => /^[0-9a-f]{64}$/.test(n?.ip_fingerprint));
  return { passed: nodes.every(n => n.passed), nodes, workload_mode: first.workload_mode ?? 'mixed',
    backend_route: first.backend_route ?? 'cloudflare', connections: first.connections ?? 'keepalive',
    generator_network: {verified_nodes: network.length, k6_verified_nodes: network.filter(n => n.k6_verified === true).length,
      distinct_exit_ips: new Set(network.map(n => n.ip_fingerprint)).size,
      cloudflare_colos: [...new Set(network.map(n => n.colo).filter(c => /^[A-Z]{3}$/.test(c)))]},
    http_requests: count('http_reqs'), wall_seconds: wallSeconds,
    average_requests_per_second: count('http_reqs') / wallSeconds, http_failures: rate('http_req_failed'), checked_errors: rate('errors'),
    journeys: rate('journey_success'), menu_hits: rate('menu_edge_hit'), asset_hits: rate('asset_edge_hit'), latencies,
    client_acknowledged_events: count('analytics_accepted'),
    transport_error_codes: Object.fromEntries(transportErrorCodes.map(code => [code, count(`transport_code_${code}`)]).filter(([, n]) => n > 0)),
    diagnostics: {
      menu_analytics_429: count('menu_analytics_rate_limited'), function_429: count('function_rate_limited'),
      function_5xx: count('function_unavailable'), function_transport_errors: count('function_transport_errors'),
      request_timeouts: count('request_timeouts'), request_cancellations: count('request_cancellations'),
      other_transport_errors: count('other_transport_errors'), unexpected_client_errors: count('unexpected_client_errors'),
      edge_server_errors: count('edge_server_errors'), edge_challenges: count('edge_challenges'),
      ...Object.fromEntries(['timeout', 'dns', 'tcp', 'tls', 'http2', 'decompression', 'eof', 'other']
        .map(kind => [`transport_${kind}_errors`, count(`transport_${kind}_errors`)])),
    } };
}

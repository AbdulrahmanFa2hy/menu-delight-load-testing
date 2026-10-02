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
      !(meta.duration_ms > 0) || !Number.isFinite(Date.parse(meta.finished_at))) throw new Error('Invalid or mixed run metadata');
    if (!Number.isFinite(meta.configured_vus) || meta.configured_vus < 1 || !Number.isFinite(meta.duration_ms) || !(data.metrics?.http_reqs?.values?.count > 0))
      throw new Error('Node performed no valid workload');
    for (const required of ['http_req_failed', 'errors', 'journey_success', 'tracking_admission_success', 'game_admission_success', 'asset_success', 'analytics_delivery_success',
      'menu_read_duration', 'tracking_session_duration', 'tracking_asset_duration', 'game_session_duration']) {
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
  return { passed: nodes.every(n => n.passed), nodes, http_requests: count('http_reqs'), wall_seconds: wallSeconds,
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

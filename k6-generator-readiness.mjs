import http from 'k6/http';
import crypto from 'k6/crypto';
import {sleep} from 'k6';
import execution from 'k6/execution';
import {Trend} from 'k6/metrics';
const started = new Trend('generator_readiness_start');
export const options = {vus: 1, iterations: 1, setupTimeout: '60s', systemTags: ['status', 'method', 'name', 'proto'], summaryTrendStats: ['max']};
export function setup() {
  const res = http.get('https://www.cloudflare.com/cdn-cgi/trace', {timeout: '10s', tags: {name: 'generator-exit-probe'}});
  const fields = Object.fromEntries((res.body ?? '').trim().split('\n').map(line => line.split('=', 2)));
  if (res.status !== 200 || !/^\d{1,3}(\.\d{1,3}){3}$/.test(fields.ip ?? '') || !/^[A-Z]{3}$/.test(fields.colo ?? ''))
    throw new Error('Generator exit verification failed');
  const start = Number(__ENV.RUN_START_MS);
  if (!Number.isSafeInteger(start) || Date.now() >= start) throw new Error('Generator missed the scheduled readiness start');
  sleep((start - Date.now()) / 1000);
  return {ip_fingerprint: crypto.sha256(__ENV.RUN_ID + '|' + fields.ip, 'hex'), colo: fields.colo};
}
export default function () { started.add(execution.scenario.startTime); }
export function handleSummary(data) {
  return {[`summary-node-${__ENV.NODE_INDEX}.json`]: JSON.stringify({meta: {node_index: Number(__ENV.NODE_INDEX), run_id: __ENV.RUN_ID,
    scheduled_start_ms: Number(__ENV.RUN_START_MS), readiness_start_ms: data.metrics.generator_readiness_start?.values?.max,
    generator_probe: data.setup_data, generator_readiness_only: true}}, null, 2)};
}

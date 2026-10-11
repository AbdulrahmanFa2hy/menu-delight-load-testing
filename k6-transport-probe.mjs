import http from 'k6/http';
import {sleep} from 'k6';
import crypto from 'k6/crypto';
import execution from 'k6/execution';
import {Counter, Trend} from 'k6/metrics';
import {diagnosticPeerClass, requestWindow} from './contracts.mjs';
import {transportCases, probeVus, probeIterations, probePacingMs} from './transport-probe-contracts.mjs';

const route = __ENV.PROBE_ROUTE, connections = __ENV.PROBE_CONNECTIONS;
const start = Number(__ENV.PROBE_START_MS), node = Number(__ENV.NODE_INDEX);
const run = __ENV.RUN_ID, origin = __ENV.ORIGIN_ADDRESS;
if (!transportCases.includes(`${route}/${connections}`) || !Number.isSafeInteger(start) ||
    !Number.isInteger(node) || node < 1 || node > 10 || !/^\d{1,20}-\d{1,3}$/.test(run ?? '') ||
    !/^\d{1,3}(\.\d{1,3}){3}$/.test(origin ?? '') || origin.split('.').some(n => Number(n) > 255))
  throw new Error('Invalid bounded transport configuration');
const ranges = JSON.parse(open('./cloudflare-ipv4-ranges.json'));
const host = 'supabase.gilgaamesh.com';
const records = new Counter('transport_probe');
const failures = new Counter('transport_failures');
const unexpected = new Counter('unexpected_status');
const probeStart = new Trend('probe_start');

export const options = {
  ...(route === 'origin' ? {hosts: {[host]: origin}} : {}),
  dns: {policy: 'onlyIPv4'},
  insecureSkipTLSVerify: false,
  noVUConnectionReuse: connections === 'fresh_iteration',
  systemTags: ['status', 'method', 'name', 'scenario', 'error_code', 'proto'],
  setupTimeout: '240s',
  scenarios: {probe: {executor: 'per-vu-iterations', vus: probeVus, iterations: probeIterations,
    maxDuration: '65s', gracefulStop: '15s'}},
  // Transport errors are evidence. This diagnostic does not certify capacity.
  thresholds: {unexpected_status: ['count==0']},
};

export function setup() {
  const response = http.get('https://www.cloudflare.com/cdn-cgi/trace', {
    timeout: '10s', redirects: 0, tags: {name: 'generator-exit-probe'},
  });
  if (response.status !== 200) execution.test.abort('Exit verification failed');
  const fields = Object.fromEntries(response.body.trim().split('\n').map(line => line.split('=', 2)));
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(fields.ip ?? '') || !/^[A-Z]{3}$/.test(fields.colo ?? ''))
    execution.test.abort('Invalid exit verification');
  const network = {ip_fingerprint: crypto.sha256(`${run}|${fields.ip}`, 'hex'), colo: fields.colo};
  if (Date.now() > start) execution.test.abort('Missed transport start');
  sleep((start - Date.now()) / 1000);
  return network;
}

function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.floor(Math.random() * 16); return (c === 'x' ? r : (r & 3) | 8).toString(16);
  });
}

export default function () {
  if (__ITER === 0) probeStart.add(execution.scenario.startTime);
  // Spread the first 100 connections; no catch-up bursts after a slow response.
  if (__ITER === 0) sleep((__VU - 1) * probePacingMs / probeVus / 1000);
  const id = uuid();
  const {response, started, finished} = requestWindow(() => http.post(`https://${host}/functions/v1/admin-create-owner`, '{}', {
    // Missing authorization is rejected before auth lookups, parsing or writes.
    headers: {'Content-Type': 'application/json', 'x-menu-benchmark-id': id, 'x-menu-benchmark-run': run},
    timeout: '15s', redirects: 0, responseType: 'binary', responseCallback: http.expectedStatuses(401),
    tags: {name: 'protected-backend-denial'},
  }));
  const tcp = response.status === 0 ? /read tcp [\d.]+:(\d+)->([\d.]+):443:/.exec(response.error ?? '') : null;
  const peer = tcp?.[2] ?? response.remote_ip ?? '';
  records.add(1, {run_id: run, node: String(node), service: 'other', request_id: id,
    route, connections, vu: String(__VU), iteration: String(__ITER),
    status: String(response.status), error_code: String(response.error_code ?? 0),
    started_ms: String(started), finished_ms: String(finished), duration_ms: String(response.timings.duration),
    body_kind: response.status === 0 ? 'transport' : 'json_other', proto: response.proto ?? '',
    peer_ip_fingerprint: /^\d{1,3}(\.\d{1,3}){3}$/.test(peer) ? crypto.sha256(`${run}|${peer}`, 'hex') : '',
    peer_class: diagnosticPeerClass(peer, origin, ranges), client_port: tcp?.[1] ?? '',
    cf_ray: response.headers['Cf-Ray'] ?? '', response_bytes: String(response.body?.byteLength ?? 0),
    body_encoding: response.headers['Content-Encoding'] ?? 'identity',
    response_content_length: response.headers['Content-Length'] ?? '',
    ...Object.fromEntries(['blocked', 'connecting', 'tls_handshaking', 'sending', 'waiting', 'receiving']
      .map(phase => [`${phase}_ms`, String(response.timings[phase])])),
  });
  failures.add(response.status === 0 ? 1 : 0);
  unexpected.add(response.status !== 0 && response.status !== 401 ? 1 : 0);
  if (response.status !== 0 && response.status !== 401) execution.test.abort('Unexpected protected response');
  sleep(Math.max(0, probePacingMs - (finished - started)) / 1000);
}

export function handleSummary(data) {
  data.meta = {run_id: run, node, route, connections,
    network: data.setup_data};
  data.meta.scenario_start_ms = data.metrics.probe_start?.values?.min ?? 0;
  delete data.setup_data;
  return {[__ENV.PROBE_SUMMARY_PATH]: JSON.stringify(data)};
}

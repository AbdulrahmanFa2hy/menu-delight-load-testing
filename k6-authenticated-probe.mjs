import http from 'k6/http';
import {sleep} from 'k6';
import crypto from 'k6/crypto';
import execution from 'k6/execution';
import {Counter, Rate, Trend} from 'k6/metrics';
import {sessionAllowed, diagnosticBodyKind, diagnosticPeerClass, requestWindow} from './contracts.mjs';
import {authenticatedCases, authenticatedVus, authenticatedPacingMs} from './authenticated-probe-contracts.mjs';

const route = __ENV.PROBE_ROUTE, workload = __ENV.PROBE_WORKLOAD, connections = __ENV.PROBE_CONNECTIONS;
const start = Number(__ENV.PROBE_START_MS), iterations = Number(__ENV.PROBE_ITERATIONS), node = Number(__ENV.NODE_INDEX);
const run = __ENV.RUN_ID, origin = __ENV.ORIGIN_ADDRESS, anon = __ENV.ANON_KEY;
if (!authenticatedCases.includes(`${workload}/${route}`) || !['keepalive', 'fresh_iteration'].includes(connections) ||
    !Number.isSafeInteger(start) || ![8, 48].includes(iterations) || !Number.isInteger(node) || node < 1 || node > 10 ||
    !/^\d{1,20}-\d{1,3}$/.test(run ?? '') || !/^\d{1,3}(\.\d{1,3}){3}$/.test(origin ?? '') || origin.split('.').some(n => Number(n) > 255) || !anon)
  throw new Error('Invalid authenticated probe configuration');
const fixtures = JSON.parse(open(__ENV.FIXTURE_FILE));
if (fixtures.length !== 10 || fixtures.some(f => typeof f.token !== 'string' || f.token.length < 32)) throw new Error('Missing private fixtures');
const ranges = JSON.parse(open('./cloudflare-ipv4-ranges.json')), host = 'supabase.gilgaamesh.com';
const records = new Counter('authenticated_probe'), failures = new Counter('transport_failures');
const admissions = new Counter('admissions'), deliveries = new Counter('deliveries'), accepted = new Counter('accepted_events'), journeys = new Counter('journeys_ok');
const admissionRate = new Rate('admission_success'), deliveryRate = new Rate('delivery_success'), journeyRate = new Rate('journey_success'), errors = new Rate('errors');
const sessionDuration = new Trend('session_duration', true), scenarioStart = new Trend('probe_start');
let sequence = 0, connectedAt = 0, previousResponse = 0;

export const options = {
  ...(route === 'origin' ? {hosts: {[host]: origin}} : {}), dns: {policy: 'onlyIPv4'}, insecureSkipTLSVerify: false,
  noVUConnectionReuse: connections === 'fresh_iteration', systemTags: ['status', 'method', 'name', 'scenario', 'error_code', 'proto'],
  setupTimeout: '240s', scenarios: {probe: {executor: 'per-vu-iterations', vus: authenticatedVus, iterations,
    maxDuration: iterations === 48 ? '325s' : '65s', gracefulStop: '30s'}},
  thresholds: {http_req_failed: ['rate<0.01'], errors: ['rate<0.01'], journey_success: ['rate>0.99'],
    admission_success: ['rate>0.99'], delivery_success: ['rate>0.99'], session_duration: ['p(95)<2500']},
  summaryTrendStats: ['avg', 'p(95)', 'max'],
};
function uuid() {return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
  const r = Math.floor(Math.random() * 16); return (c === 'x' ? r : (r & 3) | 8).toString(16);
});}
function body(response) {try {return response.json();} catch {return null;}}
export function setup() {
  const response = http.get('https://www.cloudflare.com/cdn-cgi/trace', {timeout: '10s', redirects: 0, tags: {name: 'generator-exit-probe'}});
  const fields = Object.fromEntries((response.body ?? '').trim().split('\n').map(line => line.split('=', 2)));
  if (response.status !== 200 || !/^\d{1,3}(\.\d{1,3}){3}$/.test(fields.ip ?? '') || !/^[A-Z]{3}$/.test(fields.colo ?? ''))
    execution.test.abort('Exit verification failed');
  if (Date.now() > start) execution.test.abort('Missed authenticated start');
  sleep((start - Date.now()) / 1000);
  return {ip_fingerprint: crypto.sha256(`${run}|${fields.ip}`, 'hex'), colo: fields.colo};
}
function post(service, payload, action) {
  const id = uuid();
  const {response, started, finished} = requestWindow(() => http.post(`https://${host}/functions/v1/${service}`, JSON.stringify(payload), {
    headers: {'Content-Type': 'application/json', apikey: anon, Authorization: `Bearer ${anon}`,
      'x-menu-benchmark-id': id, 'x-menu-benchmark-run': run}, timeout: '15s', redirects: 0, tags: {name: service},
  }));
  const data = body(response);
  const ok = action === 'admission' ? sessionAllowed(response.status, data) : workload === 'tracking' ?
    [200, 202].includes(response.status) && data?.success === true && data?.accepted === 3 : response.status === 200 && data?.success === true;
  if (response.timings.connecting > 0) {sequence++; connectedAt = started;}
  const tcp = response.status === 0 ? /read tcp [\d.]+:(\d+)->([\d.]+):443:/.exec(response.error ?? '') : null;
  const peer = tcp?.[2] ?? response.remote_ip ?? '';
  records.add(1, {run_id: run, node: String(node), service, request_id: id, workload, route, connections, action,
    vu: String(__VU), iteration: String(__ITER), status: String(response.status), error_code: String(response.error_code ?? 0),
    started_ms: String(started), finished_ms: String(finished), duration_ms: String(response.timings.duration),
    body_kind: diagnosticBodyKind(response.status, response.body), proto: response.proto ?? '',
    peer_ip_fingerprint: /^\d{1,3}(\.\d{1,3}){3}$/.test(peer) ? crypto.sha256(`${run}|${peer}`, 'hex') : '',
    peer_class: diagnosticPeerClass(peer, origin, ranges), client_port: tcp?.[1] ?? '', cf_ray: response.headers['Cf-Ray'] ?? '',
    response_bytes: String(byteLength(response.body ?? '')),
    response_content_length: response.headers['Content-Length'] ?? '', body_encoding: response.headers['Content-Encoding'] ?? 'unknown',
    response_connection: (response.headers['Connection'] ?? 'unknown').toLowerCase(), operation_ok: String(ok),
    connection_sequence: String(sequence), since_last_connect_ms: String(connectedAt ? started - connectedAt : 0),
    since_previous_response_ms: String(previousResponse ? started - previousResponse : 0),
    ...Object.fromEntries(['blocked', 'connecting', 'tls_handshaking', 'sending', 'waiting', 'receiving'].map(phase => [`${phase}_ms`, String(response.timings[phase])])),
  });
  previousResponse = finished; failures.add(response.status === 0 ? 1 : 0); errors.add(!ok);
  if (action === 'admission') {admissionRate.add(ok); admissions.add(ok ? 1 : 0); sessionDuration.add(response.timings.duration);}
  else {deliveryRate.add(ok); deliveries.add(ok ? 1 : 0); accepted.add(ok ? (workload === 'tracking' ? 3 : 1) : 0);}
  return {ok, data};
}
function byteLength(text) {return encodeURIComponent(text).replace(/%[A-F\d]{2}/g, 'x').length;}
export default function () {
  if (__ITER === 0) {scenarioStart.add(execution.scenario.startTime); sleep((__VU - 1) * authenticatedPacingMs / authenticatedVus / 1000);}
  const begun = Date.now(), game = ['tetris', 'breakout_arkanoid', 'snake', 'air_hockey'][(__VU + __ITER) % 4];
  const result = workload === 'tracking' ? post('image-tracking-session', {token: fixtures[(__VU + __ITER) % 10].token}, 'admission') :
    post('entertainment-session', {game_key: game, action: 'start'}, 'admission');
  let ok = result.ok;
  if (ok) ok = workload === 'tracking' ? post('image-tracking-event', {session_token: result.data.session_token,
    events: ['camera_started', 'target_first_detected', 'content_started'].map(event_type => ({id: uuid(), event_type}))}, 'delivery').ok :
    post('entertainment-session', {game_key: game, session_token: result.data.session_token, action: 'end'}, 'delivery').ok;
  journeyRate.add(ok); journeys.add(ok ? 1 : 0);
  sleep(Math.max(0, authenticatedPacingMs - (Date.now() - begun)) / 1000);
}
export function handleSummary(data) {
  data.meta = {run_id: run, node, workload, route, connections, iterations, start_ms: start,
    scenario_start_ms: data.metrics.probe_start?.values?.max ?? 0, network: data.setup_data};
  delete data.setup_data;
  return {[__ENV.PROBE_SUMMARY_PATH]: JSON.stringify(data)};
}

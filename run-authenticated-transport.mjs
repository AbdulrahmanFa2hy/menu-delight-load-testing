import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {authenticatedPlan, authenticatedVus, sanitizeAuthenticatedProbe, safeAuthenticatedSummary} from './authenticated-probe-contracts.mjs';

const node = Number(process.env.NODE_INDEX), run = process.env.RUN_ID, seconds = Number(process.env.PROBE_SECONDS);
const connections = process.env.PROBE_CONNECTIONS;
const schedule = authenticatedPlan(node, Number(process.env.RUN_START_MS), seconds);
if (!/^\d{1,20}-\d{1,3}$/.test(run ?? '') || !process.env.RUNNER_TEMP || !['keepalive', 'fresh_iteration'].includes(connections))
  throw new Error('Invalid authenticated runner identity');
const network = JSON.parse(fs.readFileSync(path.join(process.env.RUNNER_TEMP, 'generator-network.json')));
const version = spawnSync('k6', ['version'], {encoding: 'utf8', timeout: 10000});
if (version.status !== 0 || !version.stdout.startsWith('k6 v1.3.0 ')) throw new Error('Client version differs');
const binary = spawnSync('which', ['k6'], {encoding: 'utf8', timeout: 10000});
if (binary.status !== 0) throw new Error('Missing client binary');
const sha256 = crypto.createHash('sha256').update(fs.readFileSync(binary.stdout.trim())).digest('hex');
const output = fs.openSync(path.join(process.env.RUNNER_TEMP, 'authenticated-transport.jsonl'), 'wx', 0o600);
function emit(row) {fs.writeSync(output, JSON.stringify(row) + '\n');}
emit({kind: 'probe_status', run_id: run, node, client: 'k6-1.3.0', binary_sha256: sha256,
  profile: 'authenticated_backend', authorization: 'anon_api_key_and_fixture_session_capabilities',
  tls_peer_verified: true, tls_hostname_verified: true, worker_requests: 0,
  capacity_certification: false, seconds, connections, cases: schedule});
const finals = []; let requests = 0;
try {
  for (const planned of schedule) {
    const [workload, route] = planned.name.split('/');
    const expected = {run_id: run, node, workload, route, connections, iterations: planned.iterations, start_ms: planned.start_ms};
    const raw = path.join(process.env.RUNNER_TEMP, 'authenticated-private-metrics.jsonl');
    const summary = path.join(process.env.RUNNER_TEMP, 'authenticated-private-summary.json');
    try {
      const result = spawnSync('k6', ['run', '--quiet', '--log-output=none', '--out', `json=${raw}`, 'k6-authenticated-probe.mjs'], {
        env: {...process.env, PROBE_WORKLOAD: workload, PROBE_ROUTE: route, PROBE_START_MS: String(planned.start_ms),
          PROBE_ITERATIONS: String(planned.iterations), PROBE_SUMMARY_PATH: summary},
        stdio: 'pipe', timeout: 600000, maxBuffer: 1024 * 1024,
      });
      // stdout/stderr and raw metrics can contain private capabilities. Never export them.
      let count = 0;
      if (fs.existsSync(raw)) for await (const line of readline.createInterface({input: fs.createReadStream(raw), crlfDelay: Infinity})) {
        const metric = JSON.parse(line);
        if (metric.type !== 'Point' || metric.metric !== 'authenticated_probe') continue;
        if (++count > authenticatedVus * planned.iterations * 2 || metric.data.value !== 1) throw new Error('Unbounded authenticated capture');
        const row = sanitizeAuthenticatedProbe(metric.data.tags, metric.data.time, planned.iterations);
        if (Object.entries({run_id: run, node, workload, route, connections}).some(([key, value]) => row[key] !== value))
          throw new Error('Mixed authenticated capture');
        emit(row); requests++;
      }
      const final = safeAuthenticatedSummary(JSON.parse(fs.readFileSync(summary)), expected);
      if (final.network.ip_fingerprint !== network.ip_fingerprint || count !== final.counts.authenticated_probe)
        throw new Error('Exit changed or capture count differs');
      final.process_exit = result.status;
      // k6 exit 99 is a failed SLO. Retain evidence and still compare the other cases.
      if (![0, 99].includes(result.status)) final.complete = false;
      emit(final); finals.push(final);
      if (!final.complete) throw new Error('Incomplete authenticated case; safe partial records retained');
    } finally {for (const file of [raw, summary]) if (fs.existsSync(file)) fs.unlinkSync(file);}
  }
} finally {
  emit({kind: 'probe_final', run_id: run, node, requests, complete: finals.length === 4 && finals.every(f => f.complete)});
  fs.closeSync(output);
}

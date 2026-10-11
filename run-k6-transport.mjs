import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import {spawnSync} from 'node:child_process';
import {transportPlan, sanitizeTransportProbe, safeTransportSummary} from './transport-probe-contracts.mjs';

const node = Number(process.env.NODE_INDEX), run = process.env.RUN_ID;
const schedule = transportPlan(node, Number(process.env.RUN_START_MS));
if (!/^\d{1,20}-\d{1,3}$/.test(run ?? '') || !process.env.RUNNER_TEMP) throw new Error('Invalid runner identity');
const network = JSON.parse(fs.readFileSync(path.join(process.env.RUNNER_TEMP, 'generator-network.json')));
const destination = path.join(process.env.RUNNER_TEMP, 'k6-transport.jsonl');
const output = fs.openSync(destination, 'wx', 0o600);
function emit(record) {fs.writeSync(output, JSON.stringify(record) + '\n');}
emit({kind: 'probe_status', run_id: run, node, surface: 'backend_denial', client: 'k6-1.3.0',
  expected_http_status: 401, tls_peer_verified: true, tls_hostname_verified: true,
  authorization: 'missing', worker_requests: 0, production_writes: 0, cases: schedule});
const finals = [];
let requestCount = 0;
try {
  for (const planned of schedule) {
    const [route, connections] = planned.name.split('/');
    const expected = {run_id: run, node, route, connections, start_ms: planned.start_ms};
    const raw = path.join(process.env.RUNNER_TEMP, 'transport-private-metrics.jsonl');
    const summary = path.join(process.env.RUNNER_TEMP, 'transport-private-summary.json');
    try {
      const processResult = spawnSync('k6', ['run', '--quiet', '--log-output=none', '--out', `json=${raw}`, 'k6-transport-probe.mjs'], {
        env: {...process.env, PROBE_ROUTE: route, PROBE_CONNECTIONS: connections, PROBE_START_MS: String(planned.start_ms), PROBE_SUMMARY_PATH: summary},
        stdio: 'pipe', timeout: 320000, maxBuffer: 1024 * 1024,
      });
      // Raw k6 output and errors can contain URLs. They stay in private temp files.
      let count = 0;
      if (fs.existsSync(raw)) {
        for await (const line of readline.createInterface({input: fs.createReadStream(raw), crlfDelay: Infinity})) {
          const metric = JSON.parse(line);
          if (metric.type !== 'Point' || metric.metric !== 'transport_probe') continue;
          if (++count > 800 || metric.data.value !== 1) throw new Error('Unbounded transport capture');
          const row = sanitizeTransportProbe(metric.data.tags, metric.data.time);
          if (row.node !== node || row.run_id !== run || row.route !== route || row.connections !== connections)
            throw new Error('Mixed transport capture');
          emit(row);
          requestCount++;
        }
      }
      const final = safeTransportSummary(JSON.parse(fs.readFileSync(summary)), expected);
      if (final.network.ip_fingerprint !== network.ip_fingerprint || count !== final.counts.transport_probe)
        throw new Error('Exit changed or capture count differs');
      final.process_exit = processResult.status;
      if (processResult.status !== 0) final.complete = false;
      emit(final); finals.push(final);
      if (!final.complete) throw new Error('Transport case incomplete; safe partial records retained');
    } finally {
      for (const file of [raw, summary]) if (fs.existsSync(file)) fs.unlinkSync(file);
    }
  }
} finally {
  emit({kind: 'probe_final', run_id: run, node, requests: requestCount,
    complete: finals.length === 4 && finals.every(f => f.complete)});
  fs.closeSync(output);
}

import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import {sanitizeDiagnostic} from './contracts.mjs';

const node = Number(process.env.NODE_INDEX);
if (!Number.isInteger(node) || node < 1 || node > 10) throw new Error('Invalid node identity');
const pidFile = path.join(process.env.RUNNER_TEMP, 'generator-monitor.pid');
const resetPidFile = path.join(process.env.RUNNER_TEMP, 'generator-resets.pid');
if (fs.existsSync(resetPidFile)) {
  const pid = fs.readFileSync(resetPidFile, 'utf8').trim();
  if (/^\d+$/.test(pid) && fs.existsSync(`/proc/${pid}/cmdline`)) {
    const args = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0');
    if (args.includes('capture-generator-resets.py') && args.some(x => /(^|\/)python3$/.test(x)) &&
      (/(^|\/)python3$/.test(args[0]) || args.some(x => /(^|\/)sudo$/.test(x)))) {
      const {execFileSync} = await import('node:child_process');
      execFileSync('sudo', ['-n', 'kill', '-TERM', pid], {stdio: 'pipe'});
      for (let i = 0; i < 30 && fs.existsSync(`/proc/${pid}/cmdline`); i++) await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
}
if (fs.existsSync(pidFile)) {
  const pid = fs.readFileSync(pidFile, 'utf8').trim();
  if (/^\d+$/.test(pid) && fs.existsSync(`/proc/${pid}/cmdline`)) {
    const args = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0');
    if (args[0] === 'python3' && args[1] === 'monitor-generator.py') {
      process.kill(Number(pid), 'SIGTERM');
      for (let i = 0; i < 20 && fs.existsSync(`/proc/${pid}/cmdline`); i++) await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
}
const raw = path.join(process.env.RUNNER_TEMP, 'benchmark-private-metrics.json');
const records = [];
let successful = 0, failures = 0, omittedFailures = 0;
let exitProbe = null;
if (fs.existsSync(raw)) {
  for await (const line of readline.createInterface({input: fs.createReadStream(raw), crlfDelay: Infinity})) {
    const row = JSON.parse(line);
    if (row.type === 'Point' && row.metric === 'generator_exit_probe') {
      const tags = row.data.tags;
      if (!/^[0-9a-f]{64}$/.test(tags.ip_fingerprint) || !/^[A-Z]{3}$/.test(tags.colo)) throw new Error('Invalid generator exit probe');
      exitProbe = {ip_fingerprint: tags.ip_fingerprint, colo: tags.colo};
    }
    if (row.type !== 'Point' || row.metric !== 'request_diagnostic') continue;
    const record = sanitizeDiagnostic(row.data.tags, row.data.time);
    const failed = record.status === 0 || record.status >= 500;
    if (failed) { failures++; if (failures <= 1000) records.push(record); else omittedFailures++; }
    else if (++successful % 100 === 1 && records.length < 1200) records.push(record);
  }
  fs.writeFileSync(`diagnostics-node-${node}.json`, JSON.stringify({node, failures, omitted_failures: omittedFailures, records}, null, 2));
}
const summary = `summary-node-${node}.json`;
if (fs.existsSync(summary)) {
  const data = JSON.parse(fs.readFileSync(summary));
  const network = JSON.parse(fs.readFileSync(path.join(process.env.RUNNER_TEMP, 'generator-network.json')));
  if (!/^[0-9a-f]{64}$/.test(network.ip_fingerprint) || !/^[A-Z]{3}$/.test(network.colo)) throw new Error('Invalid network preflight');
  if (fs.existsSync(raw) && !exitProbe) throw new Error('Missing k6 generator exit verification');
  if (exitProbe && exitProbe.ip_fingerprint !== network.ip_fingerprint) throw new Error('Generator exit changed between preflight and k6');
  data.meta.generator_network = {ip_fingerprint: network.ip_fingerprint, colo: network.colo, cpu_count: network.cpu_count,
    ipv6_available: network.ipv6_available, proxy_configured: network.proxy_configured, k6_verified: Boolean(exitProbe)};
  fs.writeFileSync(summary, JSON.stringify(data, null, 2));
}

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';

const trace = execFileSync('curl', ['-4', '-fsS', '--connect-timeout', '5', '--max-time', '10', 'https://www.cloudflare.com/cdn-cgi/trace'], {encoding: 'utf8'});
const fields = Object.fromEntries(trace.trim().split('\n').map(line => line.split('=', 2)));
if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(fields.ip) || !/^[A-Z]{3}$/.test(fields.colo)) throw new Error('Network preflight failed');
let ipv6 = false;
try { execFileSync('curl', ['-6', '-fsS', '--connect-timeout', '2', '--max-time', '3', 'https://www.cloudflare.com/cdn-cgi/trace'], {stdio: 'pipe'}); ipv6 = true; } catch { /* Record availability without raw network errors. */ }
const data = {ip_fingerprint: crypto.createHash('sha256').update(process.env.RUN_ID + '|' + fields.ip).digest('hex'),
  colo: fields.colo, cpu_count: os.availableParallelism(), ipv6_available: ipv6,
  proxy_configured: ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'].some(k => Boolean(process.env[k]))};
fs.writeFileSync(path.join(process.env.RUNNER_TEMP, 'generator-network.json'), JSON.stringify(data), {mode: 0o600});

import fs from 'node:fs';
import path from 'node:path';
const expected = Number(process.env.EXPECTED_NODES);
if (!Number.isInteger(expected) || expected < 10 || expected > 100) throw new Error('Invalid readiness generator count');
const files = fs.readdirSync('summaries').filter(f => /^summary-node-\d+\.json$/.test(f));
if (files.length !== expected) throw new Error(`Expected ${expected} readiness summaries; received ${files.length}`);
const rows = files.map(f => JSON.parse(fs.readFileSync(path.join('summaries', f))).meta);
const first = rows[0], identities = new Set(), fingerprints = new Set();
for (const row of rows) {
  const network = row.generator_network;
  if (!row.generator_readiness_only || row.run_id !== first.run_id || row.scheduled_start_ms !== first.scheduled_start_ms ||
    !Number.isInteger(row.node_index) || row.node_index < 1 || row.node_index > expected || identities.has(row.node_index) ||
    !Number.isSafeInteger(row.readiness_start_ms) || row.readiness_start_ms < row.scheduled_start_ms || row.readiness_start_ms > row.scheduled_start_ms + 2000 ||
    network?.k6_verified !== true || !/^[0-9a-f]{64}$/.test(network.ip_fingerprint)) throw new Error('Incomplete or late generator readiness evidence');
  identities.add(row.node_index);fingerprints.add(network.ip_fingerprint);
}
if (fingerprints.size !== expected) throw new Error('Readiness probe did not establish a distinct outgoing IP per generator');
const result = {passed: true, readiness_only: true, generators: expected, distinct_exit_ips: fingerprints.size,
  start_skew_ms: Math.max(...rows.map(r => r.readiness_start_ms)) - Math.min(...rows.map(r => r.readiness_start_ms)),
  server_capacity_tested: false};
fs.writeFileSync('generator-readiness-result.json', JSON.stringify(result, null, 2));
console.log(JSON.stringify(result));
if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,
  `Verified ${expected} concurrent generators with ${fingerprints.size} distinct curl/k6 exit IPs. VPS capacity was not tested.\n`);

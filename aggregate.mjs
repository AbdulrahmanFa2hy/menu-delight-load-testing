import fs from 'node:fs';
import path from 'node:path';
import { aggregateSummaries } from './contracts.mjs';

function findSummaries(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? findSummaries(full) : /^summary-node-\d+\.json$/.test(entry.name) ? [full] : [];
  });
}
try {
  const result = aggregateSummaries(findSummaries('summaries').map(file => JSON.parse(fs.readFileSync(file, 'utf8'))), Number(process.env.EXPECTED_NODES || 10));
  const percent = r => r.rate === null ? 'N/A' : `${(r.rate * 100).toFixed(2)}% (${r.samples} samples)`;
  const markdown = `# Distributed benchmark: ${result.passed ? 'PASS' : 'FAIL'}\n\n` +
    `| Metric | Result |\n|---|---|\n| Completed nodes | ${result.nodes.length} |\n| HTTP requests | ${result.http_requests} |\n` +
    `| Average request rate across measured wall time | ${result.average_requests_per_second.toFixed(1)}/s |\n` +
    `| HTTP failure rate | ${percent(result.http_failures)} |\n| Checked operation failure rate | ${percent(result.checked_errors)} |\n` +
    `| Completed journeys | ${percent(result.journeys)} |\n| Menu cache HIT | ${percent(result.menu_hits)} |\n| Asset cache HIT | ${percent(result.asset_hits)} |\n` +
    `| Client acknowledged events | ${result.client_acknowledged_events} |\n\n` +
    `Latency figures below are the mean and worst **per-node P95**, not a global percentile. Runner regions are not controlled or verified. Acknowledgements do not prove database persistence or zero event loss.\n\n` +
    `| Operation | Mean node P95 (ms) | Worst node P95 (ms) |\n|---|---|---|\n` +
    Object.entries(result.latencies).map(([name, v]) => `| ${name} | ${v.mean_node_p95_ms?.toFixed(1) ?? 'N/A'} | ${v.worst_node_p95_ms?.toFixed(1) ?? 'N/A'} |`).join('\n') +
    '\n\n' + result.nodes.map(n => `- Node ${n.node}: ${n.passed ? 'PASS' : 'FAIL: ' + n.failed_thresholds.join(', ')}`).join('\n') + '\n';
  console.log(markdown);
  fs.writeFileSync('benchmark-result.json', JSON.stringify(result, null, 2));
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
  if (!result.passed) process.exitCode = 1;
} catch (error) {
  const message = `Benchmark aggregation failed: ${error.message}\n`;
  console.error(message);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, message);
  process.exitCode = 1;
}

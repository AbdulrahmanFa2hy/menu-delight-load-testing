import fs from 'fs';
import path from 'path';

function findSummaries(dir) {
  let files = [];
  if (!fs.existsSync(dir)) return files;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files = files.concat(findSummaries(full));
    } else if (entry.name.startsWith('summary-node-') && entry.name.endsWith('.json')) {
      files.push(full);
    }
  }
  return files;
}

const summaryFiles = findSummaries('summaries').concat(findSummaries('.'));
const uniqueFiles = Array.from(new Set(summaryFiles));

console.log(`Found ${uniqueFiles.length} node summary reports.`);

if (uniqueFiles.length === 0) {
  console.log('No summary files found to aggregate.');
  process.exit(0);
}

let totalRequests = 0;
let totalRps = 0;
let totalAnalyticsAccepted = 0;
let totalErrors = 0;
let totalChecks = 0;

let menuLatencies = [];
let trackingLatencies = [];
let assetLatencies = [];
let gameLatencies = [];

let menuEdgeHits = [];
let assetEdgeHits = [];

const nodeRows = [];

for (const file of uniqueFiles) {
  try {
    const raw = fs.readFileSync(file, 'utf-8');
    const data = JSON.parse(raw);
    const m = data.metrics || {};

    const reqs = m.http_reqs ? m.http_reqs.values.count : 0;
    const rps = m.http_reqs ? m.http_reqs.values.rate : 0;
    const analytics = m.analytics_accepted ? m.analytics_accepted.values.count : 0;

    const errRate = m.errors ? m.errors.values.rate : 0;
    const errPasses = m.errors ? m.errors.values.passes : 0;
    const errFails = m.errors ? m.errors.values.fails : 0;

    totalRequests += reqs;
    totalRps += rps;
    totalAnalyticsAccepted += analytics;
    totalErrors += errPasses;
    totalChecks += (errPasses + errFails);

    const p95Menu = m.menu_read_duration?.values?.['p(95)'];
    const p95Track = m.tracking_session_duration?.values?.['p(95)'];
    const p95Asset = m.tracking_asset_duration?.values?.['p(95)'];
    const p95Game = m.game_session_duration?.values?.['p(95)'];

    if (p95Menu) menuLatencies.push(p95Menu);
    if (p95Track) trackingLatencies.push(p95Track);
    if (p95Asset) assetLatencies.push(p95Asset);
    if (p95Game) gameLatencies.push(p95Game);

    if (m.menu_edge_hit) menuEdgeHits.push(m.menu_edge_hit.values.rate);
    if (m.asset_edge_hit) assetEdgeHits.push(m.asset_edge_hit.values.rate);

    const nodeName = path.basename(file, '.json');
    nodeRows.push({
      node: nodeName,
      reqs,
      rps: rps.toFixed(1),
      errRate: (errRate * 100).toFixed(2) + '%',
      menuP95: p95Menu ? `${p95Menu.toFixed(0)} ms` : 'N/A',
      trackP95: p95Track ? `${p95Track.toFixed(0)} ms` : 'N/A',
      assetP95: p95Asset ? `${p95Asset.toFixed(0)} ms` : 'N/A',
      gameP95: p95Game ? `${p95Game.toFixed(0)} ms` : 'N/A',
    });
  } catch (err) {
    console.error(`Error reading ${file}:`, err.message);
  }
}

const avg = arr => arr.length ? (arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(1) : 'N/A';
const overallErrRate = totalChecks > 0 ? ((totalErrors / totalChecks) * 100).toFixed(2) : '0.00';
const avgMenuEdgeHit = menuEdgeHits.length ? ((menuEdgeHits.reduce((a, b) => a + b, 0) / menuEdgeHits.length) * 100).toFixed(1) + '%' : 'N/A';
const avgAssetEdgeHit = assetEdgeHits.length ? ((assetEdgeHits.reduce((a, b) => a + b, 0) / assetEdgeHits.length) * 100).toFixed(1) + '%' : 'N/A';

const markdown = `
# 🚀 Global Distributed Load Test Benchmark Results

| Metric | Overall Aggregated Result |
|---|---|
| **Active Test Nodes** | **${uniqueFiles.length} Global Runners** |
| **Total Requests Handled** | **${totalRequests.toLocaleString()} requests** |
| **Global Throughput** | **${totalRps.toFixed(1)} req/s (RPS)** |
| **Global Error Rate** | **${overallErrRate}%** |
| **Analytics & Events Enqueued** | **${totalAnalyticsAccepted.toLocaleString()} events** |
| **Public Menu P95 Latency** | **${avg(menuLatencies)} ms** (Cloudflare Edge Cache: ${avgMenuEdgeHit}) |
| **AR Assets P95 Latency** | **${avg(assetLatencies)} ms** (Cloudflare Edge Cache: ${avgAssetEdgeHit}) |
| **Tracking AR P95 Latency** | **${avg(trackingLatencies)} ms** |
| **Arcade Games P95 Latency** | **${avg(gameLatencies)} ms** |

---

### 📊 Per-Node Breakdown

| Node | Total Requests | Throughput | Errors | Menu P95 | AR Tracking P95 | AR Assets P95 | Games P95 |
|---|---|---|---|---|---|---|---|
${nodeRows.map(r => `| ${r.node} | ${r.reqs.toLocaleString()} | ${r.rps} req/s | ${r.errRate} | ${r.menuP95} | ${r.trackP95} | ${r.assetP95} | ${r.gameP95} |`).join('\n')}

---
*Generated automatically by Menu Delight Distributed Load Testing Engine.*
`;

console.log(markdown);

if (process.env.GITHUB_STEP_SUMMARY) {
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
}

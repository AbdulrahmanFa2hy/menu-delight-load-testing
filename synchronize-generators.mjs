// One bounded read per API page and generator; no write token or shared server.
const nodes = Number(process.env.EXPECTED_NODES);
const start = Number(process.env.RUN_START_MS);
const attempt = process.env.GITHUB_RUN_ATTEMPT;
const run = process.env.GITHUB_RUN_ID;
const repo = process.env.GITHUB_REPOSITORY;
if (!Number.isInteger(nodes) || nodes < 10 || nodes > 100 || !Number.isSafeInteger(start) ||
  !/^\d+$/.test(run ?? '') || !/^\d+$/.test(attempt ?? '') || !/^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(repo ?? ''))
  throw new Error('Invalid synchronization configuration');
const cutoff = start - 20000;
if (Date.now() > cutoff) throw new Error('Generator missed the readiness deadline');
await new Promise(resolve => setTimeout(resolve, Math.max(0, cutoff + 2000 - Date.now())));
const jobs = [];
for (let page = 1; page <= Math.ceil((nodes + 1) / 100); page++) {
  const response = await fetch(`https://api.github.com/repos/${repo}/actions/runs/${run}/attempts/${attempt}/jobs?per_page=100&page=${page}`, {
    headers: {Authorization: `Bearer ${process.env.GITHUB_TOKEN}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'},
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error(`Generator readiness check failed (${response.status})`);
  const data = await response.json();
  if (!Array.isArray(data.jobs)) throw new Error('Missing readiness evidence');
  jobs.push(...data.jobs);
}
for (let node = 1; node <= nodes; node++) {
  const matches = jobs.filter(job => job.name === `Node ${node}`);
  const step = matches[0]?.steps?.find(s => s.name === 'Synchronize generators');
  if (matches.length !== 1 || !step || Date.parse(step.started_at) > cutoff ||
    !['in_progress', 'completed'].includes(step.status) || (step.conclusion && step.conclusion !== 'success'))
    throw new Error(`Generator ${node} was not ready before the deadline; no capacity claim is valid`);
}
if (Date.now() >= start) throw new Error('Generator readiness check missed the scheduled start');
console.log(`All ${nodes} generators entered the readiness barrier before the deadline.`);

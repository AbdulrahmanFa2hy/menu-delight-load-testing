import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
import {workersBudget} from './workers-budget.mjs';

export const capacityStages = [100, 250, 500, 1000, 2000, 3000, 5000, 7500, 10000];
// Mixed workload: 60% menus, mean 1.4 public events, fastest 5s think time.
// Reserve half the deployed 100-events/IP/2s allowance for variation and bursts.
export const expectedEventsPerVuSecond = 0.60 * 1.4 / 5;
export const publicEventsPerIpSecondBudget = 25;

export function capacityPlan(total, available = 10, capture = false) {
  if (!capacityStages.includes(total) || !Number.isInteger(available) || available < 10 || available > 100)
    throw new Error('Invalid capacity configuration');
  if (capture && total > 1000) throw new Error('Full diagnostic capture is limited to 1000 total VUs');
  const nodes = Math.max(10, Math.ceil(total / 100));
  if (nodes > available) throw new Error(`Need ${nodes} concurrent generators; verified capacity is ${available}. Configure BENCHMARK_AVAILABLE_RUNNER_CAPACITY only after verification.`);
  const vus = total / nodes;
  if (!Number.isInteger(vus)) throw new Error('Uneven generator allocation');
  return {total_vus: total, nodes, vus_per_node: vus, matrix: {node: Array.from({length: nodes}, (_, i) => i + 1)},
    minimum_exit_ips: Math.ceil(total * expectedEventsPerVuSecond / publicEventsPerIpSecondBudget),
    expected_public_events_per_ip_second: vus * expectedEventsPerVuSecond,
    public_events_per_ip_second_budget: publicEventsPerIpSecondBudget};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const plan = capacityPlan(Number(process.env.TOTAL_VUS), Number(process.env.AVAILABLE_RUNNER_CAPACITY || 10), process.env.DIAGNOSTIC_CAPTURE === 'true');
  plan.workers_request_budget = workersBudget({total: plan.total_vus,
    hold: Number(process.env.DURATION_SECONDS), mode: process.env.WORKLOAD_MODE,
    budget: Number(process.env.WORKERS_REQUEST_BUDGET || 0),
    verifiedAt: process.env.WORKERS_BUDGET_VERIFIED_AT || ''});
  const start = Date.now() + 120000;
  const output = `matrix=${JSON.stringify(plan.matrix)}\nnodes=${plan.nodes}\npeak_vus=${plan.vus_per_node}\nstart_ms=${start}\n`;
  fs.appendFileSync(process.env.GITHUB_OUTPUT, output);
  fs.writeFileSync('capacity-plan.json', JSON.stringify({...plan, scheduled_start_ms: start}, null, 2));
  console.log(JSON.stringify(plan));
}

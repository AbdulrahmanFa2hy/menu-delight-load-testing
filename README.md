# Menu Delight benchmark

Manually dispatched HTTP journey tests for the owner's menu, protected AR assets, tracking sessions and arcade sessions. Ten GitHub hosted runners generate traffic; their locations and distinct IPs are not guaranteed. This does not test camera tracking, game rendering, or a global user population.

Start with 100 total virtual users and a 60-second hold. After a passing run, use a 300-second hold, then increase gradually while monitoring the VPS. Previous 5,000 and 10,000 VU runs failed and do not establish supported capacity. Every node and the aggregator must pass. Missing reports fail aggregation.

## Credentials

Fixture IDs are synthetic. Active bearer tokens are held individually in Actions secrets `TRACKING_TOKEN_1` through `TRACKING_TOKEN_10`, ordered like `tracking-experiences.json`. `BENCHMARK_ANON_KEY` is the public Supabase anonymous API key. Previously published fixture tokens have been revoked.

Never add a service role key, SSH key, admin token, or GitHub PAT. Tests need only public endpoint access and narrowly scoped benchmark source tokens. Temporary credentials are outside the checkout and never uploaded. Public logs and artifacts contain metrics only. Workflows run manually from main with read-only repository permissions and immutable action references. Review changes to workflows and scripts before running them with secrets.

## Results

HTTP 200 with `unavailable` is a failed admission. Every asset, game end, and analytics batch is checked. Cache hit rates are weighted by request count. Latency reports show mean/worst per-node P95; they are not global percentiles. Throughput is average completed requests over observed wall time, not instantaneous peak throughput. Analytics acknowledgements do not prove database persistence; reconcile event IDs separately before claiming zero loss.

Run `node --test contracts.test.mjs` to verify admission and aggregation rules. The workload is 60% menus, 25% tracking and 15% games with 5–8 seconds of think time. Ten visitors share each runner IP at the baseline; the public analytics limit is 100 events per minute per IP. Higher workloads can legitimately trigger that guard and require more load-generator IPs. We do not bypass it. A 429 response still fails the run. Diagnostics distinguish rate limiting, server errors and transport errors. GitHub standard runners, concurrent jobs and artifact storage remain subject to the account's usage limits.

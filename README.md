# Menu Delight benchmark

Manually dispatched HTTP journey tests for the owner's menu, protected AR assets, tracking sessions and arcade sessions. GitHub hosted runners generate traffic; their locations and distinct IPs are measured rather than assumed. This does not test camera tracking, game rendering, or a global user population.

Start with 100 total virtual users and a 60-second hold. Repeat sustained 300-second tests at 100 → 250 → 500 → 1,000 → 2,000 → 3,000 → 5,000 → 7,500 → 10,000 while monitoring the VPS. Stop increasing when a stage fails; diagnose and validate a targeted fix before repeating it. Previous 5,000 and 10,000 VU runs failed and do not establish supported capacity. Every node and the aggregator must pass. Missing reports fail aggregation.

## Generator capacity

The workflow permits all the stages above, with at least ten generators and at most 100 VUs per generator. `BENCHMARK_AVAILABLE_RUNNER_CAPACITY` is a repository variable, defaulting to the ten concurrent runners already demonstrated. Increase it only after verifying available concurrent jobs for the account, including other workflows. It does not provision runners or change an account limit. A plan requiring more generators stops before load. [GitHub's documented concurrency limits](https://docs.github.com/en/actions/reference/limits#job-concurrency-limits-for-github-hosted-runners) vary by plan; queued jobs cannot establish simultaneous capacity.

| Total VUs | Concurrent generators | VUs per generator | Minimum distinct exit IPs at reserved rate budget |
|---|---:|---:|---:|
| 100 | 10 | 10 | 1 |
| 250 | 10 | 25 | 2 |
| 500 | 10 | 50 | 4 |
| 1,000 | 10 | 100 | 7 |
| 2,000 | 20 | 100 | 14 |
| 3,000 | 30 | 100 | 21 |
| 5,000 | 50 | 100 | 34 |
| 7,500 | 75 | 100 | 51 |
| 10,000 | 100 | 100 | 68 |

The planner reserves 25 public menu events/second/IP, half the deployed 50/second average allowance. Expected mixed traffic at the fastest five-second think time is `0.60 × 1.4 / 5 = 0.168` public events/second/VU; this is an estimate, not a guarantee against fixed-window bursts. Ten IPs at 10,000 VUs would average 168 events/second/IP. At 100 VUs per distinct generator IP, the estimate is 16.8. Aggregation groups the actual verified exit fingerprints and rejects a distribution that exceeds the reserved budget. Every real 429 remains a failed request. Tenant concentration must also be observed against the unchanged 200-events/restaurant/two-second guard.

Generators enter a bounded readiness barrier. Each makes one read-only Actions jobs request per API page after a common deadline; a queued or late generator prevents a valid run. k6 performs its existing fixture preflight and waits for the scheduled start. The aggregator also verifies observed peak VUs, k6 exit probes, scenario start skew of at most two seconds, and reports the common peak hold (at least 298 seconds for a 300-second hold). These are validity checks in addition to the unchanged SLOs. Setup synchronization does not extend any HTTP deadline. Network probes establish the observed outgoing path; POPs do not establish geographical coverage.

The successful workload contains the same 49 active menus as the previous baseline. A separate synthetic paused restaurant is listed in `paused-restaurants.json`; the earlier denial fixture was reactivated outside the benchmark and remains excluded from successful journeys. The paused menu is checked separately: menu reads must return 404 and public analytics must reject it with 400. It is excluded from successful visitor journeys. The workload uses the same browser User-Agent as the original visitor simulation; Cloudflare protection remains enabled.

## Credentials

Fixture IDs are synthetic. Active bearer tokens are held individually in Actions secrets `TRACKING_TOKEN_1` through `TRACKING_TOKEN_10`, ordered like `tracking-experiences.json`. `BENCHMARK_ANON_KEY` is the public Supabase anonymous API key. Previously published fixture tokens have been revoked.

Never add a service role key, SSH key, admin token, or GitHub PAT. Tests need only public endpoint access and narrowly scoped benchmark source tokens. Temporary credentials are outside the checkout and never uploaded. Public logs and artifacts contain metrics only. Workflows run manually from main with read-only repository permissions and immutable action references. Review changes to workflows and scripts before running them with secrets.

## Results

Diagnostic runs can isolate `tracking` or `games`, compare the usual Cloudflare backend path with `backend_origin`, and compare connection reuse with `fresh_iteration`. The origin address is a non-admin Actions secret; the hostname, JWT checks and TLS certificate verification remain enabled. Only the backend host is overridden; assets and site requests still use their normal public path. These runs identify failure causes and do not certify mixed-workload capacity. Pure tracking/game traffic at the same VU count places more demand on that endpoint than the mixed workload.

Correlation capture is opt-in and capped at 250 total VUs. It uses validated UUID request identifiers and numeric run identifiers; the public exporter retains only fixed labels, numeric timings, validated Cloudflare ray IDs, all failures up to a disclosed 1,000-record cap per node, and one successful function request in 100. Raw URL/error metric tags are disabled, HTTP logs remain disabled, and temporary metrics are removed. No request is retried by the benchmark. Optional TCP reset capture uses the GitHub runner’s local sudo/tcpdump permission and retains only direction, timestamps, a run-scoped peer-IP fingerprint and a client port. No packet file, payload, raw address or command line is exported. The 1,000-record cap is disclosed, capture stops at workflow cleanup, and it has an eleven-minute orphan deadline. The 11 existing mixed-workload thresholds are unchanged; isolated runs enforce the same thresholds for the operations they exercise.

Generator records include CPU ticks, RSS, file descriptor counts and TCP state totals, without addresses or command lines. Every run verifies the same exit fingerprint from curl and k6, without uploading a raw metrics stream for normal runs. Only a validated fingerprint and POP are returned through k6 setup data; arbitrary setup data is removed before export. IPv6 availability and proxy presence are recorded. Larger stages require verified generator capacity and a passing previous stage.

Transport diagnostics retain only fixed categories and numeric [k6 error codes](https://grafana.com/docs/k6/latest/javascript-api/error-codes/), including DNS, TCP, TLS, HTTP/2 and EOF failures. Raw errors and HTTP logs remain disabled because they can contain private capability URLs. These counters add visibility without retries or changes to the workload, deadlines or success thresholds.

HTTP 200 with `unavailable` is a failed admission. Every asset, game end, and analytics batch is checked. Cache hit rates are weighted by request count. Latency reports show mean/worst per-node P95; they are not global percentiles. Throughput is average completed requests over observed wall time, not instantaneous peak throughput. Analytics acknowledgements do not prove database persistence; reconcile event IDs separately before claiming zero loss.

Run `node --test contracts.test.mjs` to verify admission and aggregation rules. The workload is 60% menus, 25% tracking and 15% games with 5–8 seconds of think time. Ten visitors share each runner IP at the 100-VU baseline. The current public analytics gateway permits 100 events per IP and 200 per restaurant in fixed two-second Redis windows; these are not per-minute limits. Public tracking/game session limits are 1,200 requests per minute per runtime isolate, not distributed quotas. Verify deployed guards before each increase. Higher workloads can legitimately trigger guards and require more load-generator IPs. We do not bypass them. A 429 response still fails the run. Diagnostics distinguish rate limiting, server errors and transport errors. GitHub standard runners, concurrent jobs and artifact storage remain subject to the account's usage limits.

The 90-second shutdown grace allows in-flight journeys to finish within their existing request deadlines. It does not extend HTTP deadlines or relax any threshold. Diagnostics count timeouts, cancellations, other transport failures, unexpected client errors, server errors and edge challenges without logging private URLs. Cloudflare 499 means a client disconnected; it alone does not identify whether a test cancellation, request timeout or network problem caused the disconnect.

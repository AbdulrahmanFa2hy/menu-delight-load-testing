# Bounded menu socket diagnostic

The historical k6 menu-page failure had a TCP peer/time correlation but no local
request port. This manual workflow records a socket before each HTTP request,
including on reused connections, so a reset can be joined to a request by peer
fingerprint, local port and the request's live time window.

The diagnostic jobs in `check-generator-capacity.yml` are restricted to this repository and the reviewed
`codex/frontend-socket-diagnostics` branch. It shares the `vps-benchmark`
concurrency group with capacity and generator-readiness tests. Dispatch this existing workflow with `generator_count=10` and the diagnostic branch as its ref. Existing main-branch readiness jobs retain their original behavior; only the diagnostic jobs run on this branch. It issues 50
public menu HTML GETs for each Cloudflare/origin and keepalive/fresh combination
on ten generators: 2,000 HTML requests, no asset Worker, token or application
write. Cases run sequentially on each node with a 250 ms delay; even and odd
nodes reverse order. This is a transport sample, not a capacity pass.

The origin address uses the existing `BENCHMARK_ORIGIN_ADDRESS` secret. A DNS
override preserves the public hostname and TLS hostname/certificate validation.
Independent route handles prevent origin overrides from reusing a CDN socket.
HTTP/2 is negotiated when available, and the actual protocol is recorded.
Proxies are explicitly disabled; IPv4 is forced and each generator's actual
Cloudflare-reflected exit is hashed using the run ID. Local socket fingerprints
do not claim to reflect a public NAT address on the origin path.

The extended sample also makes eight requests per route with six-second idle
gaps: 160 additional HTML GETs across ten generators, 2,160 in total. Every
socket callback is retained, including reconnects within a successful curl GET.
The request deadline stays eight seconds and the entire client is bounded to
300 seconds. Libcurl may recover an idempotent GET internally; new-connection
counts and callback attempts expose that behavior where callbacks occur.

The `diagnostic_surface` input also supports `backend_denial` on the same
restricted branch. It compares the exact Supabase hostname used by k6. Requests
POST `{}` to `admin-create-owner` with the existing publishable anonymous API
key in the same apikey/Authorization headers as k6. The client checks the JWT's
role is `anon` before sending anything, and this protected endpoint denies that
caller before any application write. Both TLS-verified public/origin smoke
requests returned 401. The client stops immediately if a completed request
returns any other HTTP status. This is a socket diagnostic, not an admission or
capacity pass. No private tracking capability is used, and no body, header key
or raw URL is exported. The input defaults to frontend; main readiness behavior
is unchanged.

Pycurl 7.48.0 binary wheels are pinned by hashes from its official PyPI release.
The probe requires its prerequisite callback and HTTP/2 support. Bodies, raw
addresses, URLs and raw curl errors are never exported. Captured reset metadata
uses the existing bounded header-only collector. The aggregate requires all ten
complete captures, 2,160 unique request records and ten distinct observed IPv4
exits. It retains transport/HTTP failures rather than hiding them behind retries.

An observed received reset identifies the TCP peer that delivered it. It does
not establish which component behind that peer caused it. Failures before TLS
and the prerequisite callback have no HTTP-ready socket. The updated client
also records a connection socket's ephemeral port before connect/TLS, plus DNS,
connect and TLS timings. It binds to the IPv4 wildcard with an OS-selected port;
it does not select a fixed interface or source address. These allocation records
allow an early reset to join by peer/port/time without claiming the connection
or TLS handshake completed. Workflow probes wait 30 seconds before their bounded
300-second request window, allowing an independently controlled origin metadata
collector to start; local smoke probes default to no delay. A sample without a reset cannot explain the earlier
intermittent failure, and this Python/libcurl client is not identical to the
historical k6 client.

Run the pure correlation checks with `python3 -m unittest test_menu_transport.py`.
For a local smoke check, set `RUN_ID`, `NODE_INDEX` and `ORIGIN_ADDRESS`, install
the pinned client, and run `probe-menu-transport.py OUTPUT --requests-per-case 5`.
The extended smoke sample has 36 requests, including the idle cases, and cannot
pass the ten-node aggregate. The original version's smoke sample had 20.

## Authenticated tracking and game comparison

Use `check-generator-capacity.yml` on `codex/authenticated-transport-diagnostics`
with `diagnostic_surface=authenticated_backend`, `generator_count=10`,
`authenticated_seconds=60` or `300`, and `authenticated_connections=keepalive`
or `fresh_iteration`. Only manual dispatch in this repository can prepare the
ten private fixture capabilities. Existing readiness and denial jobs keep their
own branch guards. Every action stays pinned to its complete commit SHA.

Each generator runs tracking/Cloudflare, tracking/origin, games/Cloudflare and
games/origin. Even nodes swap routes within each service pair. Both routes
run simultaneously on five generators and then exchange the same generators.
The probe uses 25 VUs per node, IPv4, TLS verification, 15-second request
deadlines, and 6.25-second pacing with a spread initial start. There are eight
or 48 journeys per VU per case: at most 16,000 or 96,000 backend requests per
run. All ten observed exits must be distinct and stable. Valid tracking
sessions send three analytics events. Games start and end using the admitted
session capability. These writes are real and counted, with no automatic
retry of an ambiguous write. No asset, menu, XR or asset Worker is requested.

This is a backend transport diagnostic. Admission, delivery and journey gates
remain above 99%, error rates below 1%, and admission P95 below 2.5 seconds.
Failures are retained and subsequent cases still run. Aggregate `complete`
means complete evidence; `criteria_passed` is reported separately.
`capacity_certification` is always false.

Public artifacts allow only safe UUIDs, timing, fixed labels, status/error
codes, body classification, decoded response bytes, encoded Content-Length,
protocol, CF-Ray, hashed peers, resets and bounded numeric observations.
Bodies, capability URLs, credentials and raw errors are never exported.
VU-observed connection sequence/age is not an exact HTTP/2 socket identity.
A missing client port cannot create an exact socket join. Collectors support
a bounded 1,850-second window for the longer comparison.

Validate with `node --test authenticated-probe-contracts.test.mjs` and
`python3 -m unittest test_authenticated_transport.py test_generator_resets.py`.
Independently compare analyzer output from the exact run commit, then join
UUIDs/statuses/bytes to the complete proxy/native and controlled-origin capture.
Evaluate failed SLOs even when the workflow successfully collected evidence.

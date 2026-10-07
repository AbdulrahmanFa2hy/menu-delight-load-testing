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

Pycurl 7.48.0 binary wheels are pinned by hashes from its official PyPI release.
The probe requires its prerequisite callback and HTTP/2 support. Bodies, raw
addresses, URLs and raw curl errors are never exported. Captured reset metadata
uses the existing bounded header-only collector. The aggregate requires all ten
complete captures, 2,160 unique request records and ten distinct observed IPv4
exits. It retains transport/HTTP failures rather than hiding them behind retries.

An observed received reset identifies the TCP peer that delivered it. It does
not establish which component behind that peer caused it. Failures before TLS
and the prerequisite callback have unknown request sockets. A sample without a
reset cannot explain the earlier intermittent failure, and this Python/libcurl
client is not identical to the historical k6 client.

Run the pure correlation checks with `python3 -m unittest test_menu_transport.py`.
For a local smoke check, set `RUN_ID`, `NODE_INDEX` and `ORIGIN_ADDRESS`, install
the pinned client, and run `probe-menu-transport.py OUTPUT --requests-per-case 5`.
The extended smoke sample has 36 requests, including the idle cases, and cannot
pass the ten-node aggregate. The original version's smoke sample had 20.

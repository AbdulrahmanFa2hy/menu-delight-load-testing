"""Bounded GET diagnostics; export socket metadata, never bodies/raw addresses."""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import time
from pathlib import Path

import pycurl

HOST = 'qr.gilgaamesh.com'
MENU = '0e72058e-b4c9-4c43-98a8-315b8f94cc15'


def fingerprint(run, address):
    return hashlib.sha256((run + '|' + address).encode()).hexdigest()


def classify(code):
    if not code:
        return None
    if code == 28:
        return 'timeout'
    if code in (5, 6):
        return 'dns'
    if code == 7:
        return 'connect'
    if code in (35, 51, 58, 60, 77, 80, 82, 83, 90, 91):
        return 'tls'
    if code in (16, 92):
        return 'http2'
    if code in (52, 55, 56):
        return 'connection_io'
    return 'other'


def outgoing_address(run):
    """Reflect the actual IPv4 exit using the same TLS-verified curl client."""
    curl = pycurl.Curl()
    chunks = []
    size = 0
    def collect(data):
        nonlocal size
        size += len(data)
        if size > 8192:
            return 0
        chunks.append(data)
        return len(data)
    try:
        curl.setopt(pycurl.URL, 'https://www.cloudflare.com/cdn-cgi/trace')
        curl.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)
        curl.setopt(pycurl.PROXY, '')
        curl.setopt(pycurl.SSL_VERIFYPEER, 1)
        curl.setopt(pycurl.SSL_VERIFYHOST, 2)
        curl.setopt(pycurl.FOLLOWLOCATION, False)
        curl.setopt(pycurl.CONNECTTIMEOUT_MS, 3000)
        curl.setopt(pycurl.TIMEOUT_MS, 8000)
        curl.setopt(pycurl.WRITEFUNCTION, collect)
        try:
            curl.perform()
        except pycurl.error:
            raise RuntimeError('Outgoing address verification failed') from None
        assert curl.getinfo(pycurl.RESPONSE_CODE) == 200
        fields = dict(line.split('=', 1) for line in b''.join(chunks).decode().splitlines() if '=' in line)
        address = ipaddress.ip_address(fields['ip'])
        assert address.version == 4 and address.is_global
        assert re.fullmatch(r'[A-Z]{3}', fields['colo'])
        return {'kind': 'generator_network', 'ip_fingerprint': fingerprint(run, str(address)),
                'colo': fields['colo'], 'ipv4_forced': True, 'proxy_used': False}
    finally:
        curl.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--requests-per-case', type=int, default=50, choices=(5, 50))
    args = parser.parse_args()
    run = os.environ['RUN_ID']
    node = int(os.environ['NODE_INDEX'])
    assert re.fullmatch(r'\d{1,20}-\d{1,3}', run) and 1 <= node <= 10
    origin = ipaddress.ip_address(os.environ['ORIGIN_ADDRESS'])
    assert origin.version == 4 and origin.is_global
    assert hasattr(pycurl, 'PREREQFUNCTION') and pycurl.version_info()[4] & pycurl.VERSION_HTTP2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    deadline = time.monotonic() + 300
    # Reverse case order across generators to reduce route/time confounding.
    cases = [('cloudflare', 'keepalive'), ('origin', 'fresh'),
             ('cloudflare', 'fresh'), ('origin', 'keepalive'),
             ('cloudflare', 'idle_reuse'), ('origin', 'idle_reuse')]
    if node % 2 == 0:
        cases.reverse()
    counts = {'requests': 0, 'http_200': 0, 'transport_errors': 0,
              'http_errors': 0, 'unknown_socket': 0}
    with os.fdopen(os.open(args.output, flags, 0o600), 'w', encoding='utf-8') as output:
        def emit(record):
            output.write(json.dumps(record, separators=(',', ':')) + '\n')
            output.flush()
        emit({'kind': 'probe_status', 'run_id': run, 'node': node,
              'requests_per_case': args.requests_per_case, 'idle_requests_per_case': 8,
              'idle_gap_seconds': 6, 'bounded_seconds': 300,
              'tls_peer_verified': True, 'tls_hostname_verified': True,
              'redirects_followed': False, 'public_menu_get_only': True,
              'http2_negotiation': True,
              'proxy_environment_present': any(os.getenv(k) for k in
                    ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')),
              'libcurl_version': pycurl.version_info()[1],
              'pycurl_version': pycurl.version.split()[0]})
        emit(outgoing_address(run))
        # Separate handles prevent an origin override from reusing a CDN socket.
        for route, connections in cases:
            curl = pycurl.Curl()
            curl.setopt(pycurl.URL, 'https://' + HOST + '/menu/' + MENU)
            curl.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)
            curl.setopt(pycurl.PROXY, '')
            curl.setopt(pycurl.SSL_VERIFYPEER, 1)
            curl.setopt(pycurl.SSL_VERIFYHOST, 2)
            curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2TLS)
            curl.setopt(pycurl.FOLLOWLOCATION, False)
            curl.setopt(pycurl.CONNECTTIMEOUT_MS, 3000)
            curl.setopt(pycurl.TIMEOUT_MS, 8000)
            curl.setopt(pycurl.USERAGENT, 'menu-delight-transport-diagnostic/1')
            curl.setopt(pycurl.NOSIGNAL, 1)
            curl.setopt(pycurl.TCP_KEEPALIVE, 1)
            curl.setopt(pycurl.FRESH_CONNECT, connections == 'fresh')
            curl.setopt(pycurl.FORBID_REUSE, connections == 'fresh')
            if route == 'origin':
                curl.setopt(pycurl.RESOLVE, [HOST + ':443:' + str(origin)])
            try:
                count = 8 if connections == 'idle_reuse' else args.requests_per_case
                for sequence in range(count):
                    if time.monotonic() + 8 > deadline:
                        raise RuntimeError('Diagnostic deadline reached')
                    record = {'kind': 'request', 'run_id': run, 'node': node,
                              'route': route, 'connections': connections,
                              'request_id': f'{run}-menu-{node}-{route}-{connections}-{sequence}',
                              'started_epoch_seconds': time.time(), 'socket': None, 'socket_attempts': []}
                    bytes_received = 0
                    def discard(data):
                        nonlocal bytes_received
                        bytes_received += len(data)
                        return len(data) if bytes_received <= 2 * 1024 * 1024 else 0
                    def socket_ready(peer, local, peer_port, local_port):
                        record['socket'] = {
                            'peer_ip_fingerprint': fingerprint(run, peer),
                            'local_ip_fingerprint': fingerprint(run, local),
                            'peer_port': peer_port, 'client_port': local_port,
                            'ready_epoch_seconds': time.time(),
                            'configured_origin': ipaddress.ip_address(peer) == origin}
                        record['socket_attempts'].append(record['socket'])
                        return 0
                    curl.setopt(pycurl.WRITEFUNCTION, discard)
                    curl.setopt(pycurl.PREREQFUNCTION, socket_ready)
                    curl.setopt(pycurl.HTTPHEADER, ['X-Benchmark-Request-Id: ' + record['request_id']])
                    code = 0
                    try:
                        curl.perform()
                    except pycurl.error as error:
                        code = int(error.args[0])  # Never export raw curl errors or URLs.
                    record.update({'ended_epoch_seconds': time.time(), 'curl_error_code': code,
                                   'transport_kind': classify(code),
                                   'http_status': int(curl.getinfo(pycurl.RESPONSE_CODE)),
                                   'response_bytes': bytes_received,
                                   'new_connections': int(curl.getinfo(pycurl.NUM_CONNECTS)),
                                   'negotiated_http_version': int(curl.getinfo(pycurl.INFO_HTTP_VERSION)),
                                   'elapsed_ms': 1000 * curl.getinfo(pycurl.TOTAL_TIME)})
                    counts['requests'] += 1
                    counts['http_200'] += int(not code and record['http_status'] == 200)
                    counts['transport_errors'] += int(bool(code))
                    counts['http_errors'] += int(not code and record['http_status'] != 200)
                    counts['unknown_socket'] += int(record['socket'] is None)
                    if record['socket']:
                        assert record['socket']['peer_port'] == 443
                        assert record['socket']['configured_origin'] == (route == 'origin')
                    emit(record)
                    if sequence + 1 < count:
                        time.sleep(6 if connections == 'idle_reuse' else .25)
            finally:
                curl.close()
        emit({'kind': 'probe_final', **counts,
              'complete': counts['requests'] == 4 * args.requests_per_case + 16})


if __name__ == '__main__':
    main()

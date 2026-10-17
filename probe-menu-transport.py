"""Bounded GET diagnostics; export socket metadata, never bodies/raw addresses."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
import uuid
from pathlib import Path

import pycurl

MENU = '0e72058e-b4c9-4c43-98a8-315b8f94cc15'
SURFACES = {
    'frontend': ('qr.gilgaamesh.com', '/menu/' + MENU, 200),
    'backend_denial': ('supabase.gilgaamesh.com', '/functions/v1/admin-create-owner', 401),
    'xr_engine': ('qr.gilgaamesh.com', '/external/xr/v-c4781db3f6e5f3ec8285/xr.js', 200),
}
# Immutable deployed frontend asset; compare decoded bodies without exporting them.
XR_BYTES = 1036695
XR_SHA256 = 'b3973936862f4cb77ae32d24f253d8a0e8b1de4fa2a0cf688833742889ee829d'


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
    parser.add_argument('--surface', choices=tuple(SURFACES), default='frontend')
    parser.add_argument('--start-delay-seconds', type=int, choices=(0, 30), default=0)
    args = parser.parse_args()
    host, path, expected_status = SURFACES[args.surface]
    request_seconds = 15 if args.surface == 'xr_engine' else 8
    anon_key = None
    if args.surface == 'backend_denial':
        anon_key = os.environ['ANON_KEY']
        assert re.fullmatch(r'[A-Za-z0-9._-]{30,8192}', anon_key)
        claim = anon_key.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(claim + '=' * (-len(claim) % 4)))
        assert claims.get('role') == 'anon', 'Only the publishable anonymous caller is allowed'
    run = os.environ['RUN_ID']
    node = int(os.environ['NODE_INDEX'])
    assert re.fullmatch(r'\d{1,20}-\d{1,3}', run) and 1 <= node <= 10
    origin = ipaddress.ip_address(os.environ['ORIGIN_ADDRESS'])
    assert origin.version == 4 and origin.is_global
    assert hasattr(pycurl, 'PREREQFUNCTION') and hasattr(pycurl, 'OPENSOCKETFUNCTION')
    assert pycurl.version_info()[4] & pycurl.VERSION_HTTP2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    # The workflow gives the independently controlled origin collector time to start.
    time.sleep(args.start_delay_seconds)
    deadline = time.monotonic() + 300
    # Reverse case order across generators to reduce route/time confounding.
    cases = [('cloudflare', 'keepalive'), ('origin', 'fresh'),
             ('cloudflare', 'fresh'), ('origin', 'keepalive'),
             ('cloudflare', 'idle_reuse'), ('origin', 'idle_reuse')]
    if node % 2 == 0:
        cases.reverse()
    counts = {'requests': 0, 'http_200': 0, 'expected_http': 0, 'transport_errors': 0,
              'http_errors': 0, 'unknown_socket': 0}
    with os.fdopen(os.open(args.output, flags, 0o600), 'w', encoding='utf-8') as output:
        def emit(record):
            output.write(json.dumps(record, separators=(',', ':')) + '\n')
            output.flush()
        emit({'kind': 'probe_status', 'run_id': run, 'node': node,
              'requests_per_case': args.requests_per_case, 'idle_requests_per_case': 8,
              'surface': args.surface, 'expected_http_status': expected_status,
              'idle_gap_seconds': 6, 'bounded_seconds': 300,
              'start_delay_seconds': args.start_delay_seconds,
              'tls_peer_verified': True, 'tls_hostname_verified': True,
              'redirects_followed': False, 'public_menu_get_only': args.surface == 'frontend',
              'authorization_denial_only': args.surface == 'backend_denial',
              'http2_negotiation': True,
              'request_deadline_ms': request_seconds * 1000,
              'expected_body_bytes': XR_BYTES if args.surface == 'xr_engine' else None,
              'expected_body_sha256': XR_SHA256 if args.surface == 'xr_engine' else None,
              'proxy_environment_present': any(os.getenv(k) for k in
                    ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')),
              'libcurl_version': pycurl.version_info()[1],
              'pycurl_version': pycurl.version.split()[0]})
        emit(outgoing_address(run))
        # Separate handles prevent an origin override from reusing a CDN socket.
        for route, connections in cases:
            curl = pycurl.Curl()
            curl.setopt(pycurl.URL, 'https://' + host + path)
            curl.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)
            curl.setopt(pycurl.PROXY, '')
            curl.setopt(pycurl.SSL_VERIFYPEER, 1)
            curl.setopt(pycurl.SSL_VERIFYHOST, 2)
            curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2TLS)
            curl.setopt(pycurl.FOLLOWLOCATION, False)
            curl.setopt(pycurl.CONNECTTIMEOUT_MS, 3000)
            curl.setopt(pycurl.TIMEOUT_MS, request_seconds * 1000)
            if args.surface == 'xr_engine':
                curl.setopt(pycurl.ACCEPT_ENCODING, '')  # Hash decoded gzip/br/identity alike.
            curl.setopt(pycurl.USERAGENT, 'menu-delight-transport-diagnostic/1')
            curl.setopt(pycurl.NOSIGNAL, 1)
            curl.setopt(pycurl.TCP_KEEPALIVE, 1)
            curl.setopt(pycurl.FRESH_CONNECT, connections == 'fresh')
            curl.setopt(pycurl.FORBID_REUSE, connections == 'fresh')
            if route == 'origin':
                curl.setopt(pycurl.RESOLVE, [host + ':443:' + str(origin)])
            if args.surface == 'backend_denial':
                # This protected endpoint rejects the anonymous caller before any write.
                curl.setopt(pycurl.POSTFIELDS, '{}')
            try:
                count = 8 if connections == 'idle_reuse' else args.requests_per_case
                for sequence in range(count):
                    if time.monotonic() + request_seconds > deadline:
                        raise RuntimeError('Diagnostic deadline reached')
                    record = {'kind': 'request', 'run_id': run, 'node': node,
                              'route': route, 'connections': connections,
                              'request_id': str(uuid.uuid4()),
                              'started_epoch_seconds': time.time(), 'socket': None,
                              'socket_attempts': [], 'connect_socket_attempts': []}
                    bytes_received = 0
                    body_hash = hashlib.sha256()
                    began = time.monotonic()
                    previous_chunk = None
                    first_chunk_ms = None
                    maximum_body_gap_ms = 0
                    def discard(data):
                        nonlocal bytes_received, previous_chunk, first_chunk_ms, maximum_body_gap_ms
                        now = time.monotonic()
                        if first_chunk_ms is None:
                            first_chunk_ms = 1000 * (now - began)
                        if previous_chunk is not None:
                            maximum_body_gap_ms = max(maximum_body_gap_ms, 1000 * (now - previous_chunk))
                        previous_chunk = now
                        bytes_received += len(data)
                        body_hash.update(data)
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
                    def open_socket(purpose, curl_address):
                        family, socktype, protocol, address = curl_address
                        assert family == socket.AF_INET and address[1] == 443
                        connection = socket.socket(family, socktype, protocol)
                        try:
                            # Let the OS allocate an ephemeral port before connect/TLS.
                            # No fixed interface or source address is selected.
                            connection.bind(('0.0.0.0', 0))
                            record['connect_socket_attempts'].append({
                                'peer_ip_fingerprint': fingerprint(run, address[0]),
                                'peer_port': address[1],
                                'client_port': connection.getsockname()[1],
                                'allocated_epoch_seconds': time.time(),
                                'configured_origin': ipaddress.ip_address(address[0]) == origin,
                            })
                            return connection
                        except Exception:
                            connection.close()
                            raise
                    curl.setopt(pycurl.WRITEFUNCTION, discard)
                    curl.setopt(pycurl.PREREQFUNCTION, socket_ready)
                    curl.setopt(pycurl.OPENSOCKETFUNCTION, open_socket)
                    headers = ['X-Menu-Benchmark-Id: ' + record['request_id'], 'X-Menu-Benchmark-Run: ' + run]
                    if args.surface == 'backend_denial':
                        headers += ['Authorization: Bearer ' + anon_key, 'apikey: ' + anon_key, 'Content-Type: application/json']
                    curl.setopt(pycurl.HTTPHEADER, headers)
                    code = 0
                    try:
                        curl.perform()
                    except pycurl.error as error:
                        code = int(error.args[0])  # Never export raw curl errors or URLs.
                    record.update({'ended_epoch_seconds': time.time(), 'curl_error_code': code,
                                   'transport_kind': classify(code),
                                   'http_status': int(curl.getinfo(pycurl.RESPONSE_CODE)),
                                   'response_bytes': bytes_received,
                                   'body_sha256': body_hash.hexdigest(),
                                   'first_body_chunk_ms': first_chunk_ms,
                                   'last_body_chunk_ms': 1000 * (previous_chunk - began) if previous_chunk is not None else None,
                                   'tail_body_wait_ms': 1000 * (time.monotonic() - previous_chunk) if previous_chunk is not None else None,
                                   'maximum_body_gap_ms': maximum_body_gap_ms,
                                   'first_byte_ms': 1000 * curl.getinfo(pycurl.STARTTRANSFER_TIME),
                                   'receive_ms': 1000 * (curl.getinfo(pycurl.TOTAL_TIME) - curl.getinfo(pycurl.STARTTRANSFER_TIME)),
                                   'new_connections': int(curl.getinfo(pycurl.NUM_CONNECTS)),
                                   'negotiated_http_version': int(curl.getinfo(pycurl.INFO_HTTP_VERSION)),
                                   'dns_ms': 1000 * curl.getinfo(pycurl.NAMELOOKUP_TIME),
                                   'connect_ms': 1000 * curl.getinfo(pycurl.CONNECT_TIME),
                                   'tls_ms': 1000 * curl.getinfo(pycurl.APPCONNECT_TIME),
                                   'elapsed_ms': 1000 * curl.getinfo(pycurl.TOTAL_TIME)})
                    counts['requests'] += 1
                    counts['http_200'] += int(not code and record['http_status'] == 200)
                    counts['expected_http'] += int(not code and record['http_status'] == expected_status)
                    counts['transport_errors'] += int(bool(code))
                    counts['http_errors'] += int(not code and record['http_status'] != expected_status)
                    counts['unknown_socket'] += int(record['socket'] is None)
                    if record['socket']:
                        assert record['socket']['peer_port'] == 443
                        assert record['socket']['configured_origin'] == (route == 'origin')
                    emit(record)
                    if args.surface == 'backend_denial' and not code and record['http_status'] != 401:
                        raise RuntimeError('Protected denial changed; stop further probes')
                    if sequence + 1 < count:
                        time.sleep(6 if connections == 'idle_reuse' else .25)
            finally:
                curl.close()
        emit({'kind': 'generator_network_after', **{k: v for k, v in outgoing_address(run).items() if k != 'kind'}})
        emit({'kind': 'probe_final', **counts,
              'complete': counts['requests'] == 4 * args.requests_per_case + 16})


if __name__ == '__main__':
    main()

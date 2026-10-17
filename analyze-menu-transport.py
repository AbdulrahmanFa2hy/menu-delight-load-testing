"""Join a request to observed resets by exact socket and its live time window."""
import argparse
import collections
import json
import math
from pathlib import Path

XR_BYTES = 1036695
XR_SHA256 = 'b3973936862f4cb77ae32d24f253d8a0e8b1de4fa2a0cf688833742889ee829d'


def valid_xr_body(request):
    return request.get('response_bytes') == XR_BYTES and request.get('body_sha256') == XR_SHA256


def matching_resets(request, resets):
    sockets = list(request.get('socket_attempts') or ([request['socket']] if request.get('socket') else []))
    sockets += request.get('connect_socket_attempts', [])
    if not sockets:
        return []
    return [reset for reset in resets
            if reset.get('kind') == 'tcp_reset'
            and any(reset['peer_ip_fingerprint'] == socket['peer_ip_fingerprint']
                    and reset['client_port'] == socket['client_port']
                    and socket.get('ready_epoch_seconds', socket.get('allocated_epoch_seconds'))
                        <= reset['epoch_seconds'] <= request['ended_epoch_seconds']
                    for socket in sockets)]


def analyze(directory, expected_nodes):
    cases = collections.defaultdict(collections.Counter)
    matches = []
    node_records = []
    exits = []
    latencies = collections.defaultdict(list)
    run_ids = set()
    surfaces = set()
    xr_nodes = []
    for node in range(1, expected_nodes + 1):
        def read(name):
            return [json.loads(line) for line in (directory / f'{name}-node-{node}.jsonl').read_text().splitlines()]
        rows = read('menu-transport')
        resets = read('generator-resets')
        status = [row for row in rows if row['kind'] == 'probe_status']
        networks = [row for row in rows if row['kind'] == 'generator_network']
        finals = [row for row in rows if row['kind'] == 'probe_final']
        capture_status = [row for row in resets if row['kind'] == 'capture_status']
        capture_final = [row for row in resets if row['kind'] == 'capture_final']
        assert len(status) == len(networks) == len(finals) == len(capture_status) == len(capture_final) == 1
        assert status[0]['node'] == node and status[0]['requests_per_case'] == 50
        assert status[0]['tls_peer_verified'] and status[0]['tls_hostname_verified']
        idle = status[0].get('idle_requests_per_case', 0)
        surface = status[0].get('surface', 'frontend')
        assert surface in ('frontend', 'backend_denial', 'xr_engine')
        expected_status = 401 if surface == 'backend_denial' else 200
        assert status[0].get('expected_http_status', 200) == expected_status
        surfaces.add(surface)
        assert idle in (0, 8)
        expected_requests = 200 + 2 * idle
        assert finals[0]['complete'] and finals[0]['requests'] == expected_requests
        assert capture_status[0]['available'] and capture_final[0]['omitted_records'] == 0
        assert capture_final[0]['exit_code'] in (0, -15, 143)
        assert capture_final[0]['reset_records'] == sum(row['kind'] == 'tcp_reset' for row in resets)
        requests = [row for row in rows if row['kind'] == 'request']
        assert len(requests) == len({row['request_id'] for row in requests}) == expected_requests
        if surface == 'xr_engine':
            after = [row for row in rows if row['kind'] == 'generator_network_after']
            assert len(after) == 1 and after[0]['ip_fingerprint'] == networks[0]['ip_fingerprint'], 'Exit changed during comparison'
            assert status[0]['request_deadline_ms'] == 15000
            assert status[0]['expected_body_bytes'] == XR_BYTES and status[0]['expected_body_sha256'] == XR_SHA256
            for route in ('cloudflare', 'origin'):
                for mode, expected in (('keepalive', 50), ('fresh', 50), ('idle_reuse', 8)):
                    sample = [row for row in requests if row['route'] == route and row['connections'] == mode]
                    assert len(sample) == expected, 'Missing or duplicate case observations'
                    if all(not row['curl_error_code'] for row in sample):
                        if mode == 'fresh':
                            assert all(row['new_connections'] >= 1 for row in sample), 'Fresh connections not exercised'
                        else:
                            assert any(row['new_connections'] == 0 for row in sample), 'Connection reuse not exercised'
                    successful = [row for row in sample if not row['curl_error_code'] and row['http_status'] == 200 and valid_xr_body(row)]
                    elapsed = sorted(row['elapsed_ms'] for row in sample)
                    xr_nodes.append({'node': node, 'case': route + '/' + mode,
                        'requests': len(sample), 'complete_bodies': len(successful),
                        'p95_ms': elapsed[math.ceil(.95 * len(elapsed)) - 1],
                        'maximum_receive_ms': max(row['receive_ms'] for row in sample),
                        'maximum_body_gap_ms': max(row['maximum_body_gap_ms'] for row in sample),
                        'maximum_tail_body_wait_ms': max((row.get('tail_body_wait_ms') or 0) for row in sample),
                        'criteria_passed': len(successful) == len(sample) and elapsed[math.ceil(.95 * len(elapsed)) - 1] < 1000})
        assert all(row['node'] == node and row['run_id'] == status[0]['run_id'] for row in requests)
        exits.append(networks[0]['ip_fingerprint'])
        run_ids.add(status[0]['run_id'])
        for request in requests:
            key = request['route'] + '/' + request['connections']
            assert request['route'] in ('cloudflare', 'origin') and request['connections'] in ('keepalive', 'fresh', 'idle_reuse')
            if request['socket']:
                assert request['socket']['configured_origin'] == (request['route'] == 'origin')
                if 'connect_socket_attempts' in request and request['new_connections']:
                    assert any(attempt['client_port'] == request['socket']['client_port']
                               and attempt['peer_ip_fingerprint'] == request['socket']['peer_ip_fingerprint']
                               for attempt in request['connect_socket_attempts']), 'HTTP-ready socket not present in allocation records'
            case = cases[key]
            latencies[key].append(request['elapsed_ms'])
            case['requests'] += 1
            case['http_200'] += int(request['http_status'] == 200 and not request['curl_error_code'])
            if surface == 'backend_denial':
                case['http_401'] += int(request['http_status'] == 401 and not request['curl_error_code'])
            case['transport_errors'] += int(bool(request['curl_error_code']))
            case['http_errors'] += int(not request['curl_error_code'] and request['http_status'] != expected_status)
            if surface == 'xr_engine':
                case['body_integrity_errors'] += int(not request['curl_error_code'] and request['http_status'] == 200 and not valid_xr_body(request))
            case['unknown_socket'] += int(request['socket'] is None)
            case['unknown_connection_socket'] += int(not request.get('connect_socket_attempts') and request['socket'] is None)
            case['new_connections'] += request['new_connections']
            case['requests_with_multiple_socket_callbacks'] += int(len(request.get('socket_attempts', [])) > 1)
            case['http_version_' + str(request['negotiated_http_version'])] += 1
            joined = matching_resets(request, resets)
            if joined:
                case['requests_with_socket_reset'] += 1
                matches.append({'request_id': request['request_id'], 'node': node, 'case': key,
                                'curl_error_code': request['curl_error_code'],
                                'http_status': request['http_status'], 'resets': joined})
        node_records.append({'node': node, 'network': networks[0], 'final': finals[0],
                             'reset_capture_final': capture_final[0]})
    assert len(run_ids) == 1, 'Mixed diagnostic runs cannot be aggregated'
    assert len(surfaces) == 1
    assert len(set(exits)) == expected_nodes, 'Generators did not use distinct verified IPv4 exits'
    assert len(cases) in (4, 6)
    assert all(case['requests'] == expected_nodes * (8 if key.endswith('/idle_reuse') else 50)
               for key, case in cases.items())
    timings = {key: {'mean': sum(values) / len(values),
                      'p95': sorted(values)[math.ceil(.95 * len(values)) - 1], 'max': max(values)}
               for key, values in latencies.items()}
    return {'complete': True, 'surface': next(iter(surfaces)), 'run_id': next(iter(run_ids)), 'verified_distinct_ipv4_exits': len(set(exits)),
            'capacity_certification': False, 'xr_node_cases': xr_nodes,
            'xr_criteria_passed': all(row['criteria_passed'] for row in xr_nodes) if xr_nodes else None,
            'cases': dict(cases), 'elapsed_ms': timings, 'request_socket_reset_matches': matches, 'nodes': node_records,
            'limits': 'No reset in this bounded sample does not establish its underlying cause. '
                      'A socket match identifies the observed peer and timing, not the initiator behind that peer. '
                      'The prerequisite callback marks HTTP-ready sockets; allocation metadata '
                      'can identify earlier connection attempts but does not prove a TLS handshake completed.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = analyze(args.directory, 10)
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps({'complete': result['complete'], 'distinct_exits': result['verified_distinct_ipv4_exits'],
                      'cases': result['cases'], 'reset_matches': len(result['request_socket_reset_matches'])}))

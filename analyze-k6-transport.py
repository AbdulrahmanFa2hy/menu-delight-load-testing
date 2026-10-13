"""Compare fixed transport cases on the same runners; never certify capacity."""
import argparse
import collections
import json
import re
from pathlib import Path

CASES = {'cloudflare/keepalive', 'origin/fresh_iteration', 'cloudflare/fresh_iteration', 'origin/keepalive'}
CLIENT_CASES = ['1.3.0/keepalive', '2.3.0/keepalive', '1.3.0/fresh_iteration', '2.3.0/fresh_iteration']


def case_key(row, profile):
    if profile == 'client_versions':
        assert row['route'] == 'cloudflare'
        assert row.get('client_version') in ('1.3.0', '2.3.0')
        return row['client_version'] + '/' + row['connections']
    return row['route'] + '/' + row['connections']


def expected_denial(request):
    # expectedStatuses affects http_req_failed, not k6's HTTP status error code.
    return request['status'] == 401 and request['error_code'] in (0, 1401)


def matching_resets(request, resets):
    # A zero-phase timeout need not expose a socket. Never infer its client port.
    if not request.get('client_port') or not request.get('peer_ip_fingerprint'):
        return []
    return [reset for reset in resets if reset.get('kind') == 'tcp_reset'
            and reset['client_port'] == request['client_port']
            and reset['peer_ip_fingerprint'] == request['peer_ip_fingerprint']
            and request['started_ms'] / 1000 <= reset['epoch_seconds'] <= request['finished_ms'] / 1000]


def analyze(directory, nodes=10, profile='routes'):
    assert profile in ('routes', 'client_versions')
    expected_cases = set(CLIENT_CASES) if profile == 'client_versions' else CASES
    cases = collections.defaultdict(collections.Counter)
    node_results, joins, exits, starts, run_ids = [], [], set(), collections.defaultdict(list), set()
    ids = set()
    complete = True
    binary_hashes = collections.defaultdict(set)
    for node in range(1, nodes + 1):
        rows = [json.loads(line) for line in (directory / f'k6-transport-node-{node}.jsonl').read_text().splitlines()]
        packets = [json.loads(line) for line in (directory / f'generator-resets-node-{node}.jsonl').read_text().splitlines()]
        resource_path = directory / f'generator-samples-node-{node}.jsonl'
        resources = [json.loads(line) for line in resource_path.read_text().splitlines()]
        status = [row for row in rows if row['kind'] == 'probe_status']
        final = [row for row in rows if row['kind'] == 'probe_final']
        capture_final = [row for row in packets if row['kind'] == 'capture_final']
        assert len(status) == len(final) == len(capture_final) == 1
        assert status[0]['node'] == node and status[0]['client'] == ('k6-client-comparison' if profile == 'client_versions' else 'k6-1.3.0')
        if profile == 'client_versions':
            assert status[0]['profile'] == profile
            binaries = status[0]['binaries']
            assert len(binaries) == 2 and {b['version'] for b in binaries} == {'1.3.0', '2.3.0'}
            for binary in binaries:
                assert binary['version_verified'] and re.fullmatch(r'[0-9a-f]{64}', binary['sha256'])
                binary_hashes[binary['version']].add(binary['sha256'])
            order = CLIENT_CASES if node % 2 else list(reversed(CLIENT_CASES))
            plan = status[0]['cases']
            assert [c['name'] for c in plan] == order
            assert [c['start_ms'] for c in plan] == [plan[0]['start_ms'] + index * 80000 for index in range(4)]
        assert status[0]['tls_peer_verified'] and status[0]['tls_hostname_verified']
        assert status[0]['authorization'] == 'missing' and status[0]['expected_http_status'] == 401
        assert status[0]['worker_requests'] == status[0]['production_writes'] == 0
        assert capture_final[0]['omitted_records'] == 0 and capture_final[0]['exit_code'] in (0, -15, 143)
        assert capture_final[0]['reset_records'] == sum(row['kind'] == 'tcp_reset' for row in packets)
        run_ids.add(status[0]['run_id'])
        node_cases = [row for row in rows if row['kind'] == 'case_final']
        complete &= final[0]['complete'] and len(node_cases) == 4
        networks = {row['network']['ip_fingerprint'] for row in node_cases}
        assert len(networks) == 1, 'Each comparison must retain the same verified exit'
        exits.update(networks)
        by_case = {case_key(row, profile): row for row in node_cases}
        assert len(by_case) == len(node_cases)
        for name, row in by_case.items():
            assert name in expected_cases and row['expected_requests'] == 800 and row['vus'] == 100
            if profile == 'client_versions':
                assert row['start_ms'] == next(c['start_ms'] for c in plan if c['name'] == name)
            assert row['iterations_per_vu'] == 8 and row['pacing_ms'] == 6250
            assert row['run_id'] == status[0]['run_id'] and row['node'] == node
            complete &= row['complete'] and row['process_exit'] == 0
            starts[row['start_ms']].append(row['scenario_start_ms'])
        per_node = collections.defaultdict(collections.Counter)
        requests = [row for row in rows if row['kind'] == 'request']
        iteration_keys = set()
        for row in requests:
            assert row['request_id'] not in ids
            ids.add(row['request_id'])
            assert row['run_id'] == status[0]['run_id'] and row['node'] == node
            assert row['finished_ms'] >= row['started_ms'] and row['wall_duration_ms'] == row['finished_ms'] - row['started_ms']
            name = case_key(row, profile)
            assert name in expected_cases
            if profile == 'client_versions':
                key = (name, row['vu'], row['iteration'])
                assert key not in iteration_keys and 1 <= row['vu'] <= 100 and 0 <= row['iteration'] < 8
                iteration_keys.add(key)
            counts = cases[name]
            for dest in (counts, per_node[name]):
                dest['requests'] += 1
                dest['http_401'] += int(expected_denial(row))
                dest['transport_errors'] += int(row['status'] == 0)
                dest['http_errors'] += int(row['status'] not in (0, 401))
                if row['status'] == 0:
                    dest['error_code_' + str(row['error_code'])] += 1
                dest['new_connections'] += int(row['connecting_ms'] > 0)
                dest['http_version_' + row['proto']] += 1
            exact = matching_resets(row, packets)
            if exact:
                counts['requests_with_exact_reset'] += 1
                joins.append({'node': node, 'case': name, 'request_id': row['request_id'],
                              'status': row['status'], 'error_code': row['error_code'], 'resets': exact})
        for name, row in by_case.items():
            assert per_node[name]['requests'] == row['counts']['transport_probe']
            assert per_node[name]['transport_errors'] == row['counts']['transport_failures']
            assert per_node[name]['http_errors'] == row['counts']['unexpected_status']
        peaks = {'rss_kib': 0, 'open_fds': 0, 'cpu_count': 0, 'tcp_states': {}}
        cpu_fractions = []
        previous = {}
        for sample in resources:
            peaks['cpu_count'] = max(peaks['cpu_count'], sample['cpu_count'])
            for state, count in sample['tcp_states'].items():
                peaks['tcp_states'][state] = max(peaks['tcp_states'].get(state, 0), count)
            for proc in sample['k6']:
                peaks['rss_kib'] = max(peaks['rss_kib'], proc['rss_kib'])
                peaks['open_fds'] = max(peaks['open_fds'], proc['open_fds'])
                from datetime import datetime
                now = datetime.fromisoformat(sample['utc']).timestamp()
                if proc['pid'] in previous:
                    stamp, ticks = previous[proc['pid']]
                    if now > stamp:
                        cpu_fractions.append((proc['cpu_ticks'] - ticks) / sample['clock_ticks'] / (now - stamp) / sample['cpu_count'])
                previous[proc['pid']] = (now, proc['cpu_ticks'])
        peaks['peak_sampled_cpu_fraction'] = max(cpu_fractions, default=None)
        node_results.append({'node': node, 'cases': dict(per_node), 'finals': node_cases,
                             'capture_final': capture_final[0], 'generator_peaks': peaks})
    assert len(run_ids) == 1 and len(exits) == nodes
    skew = {str(start): max(times) - min(times) for start, times in starts.items()}
    complete &= len(starts) == 4 and all(len(times) == nodes and max(times) - min(times) <= 2000 for times in starts.values())
    complete &= set(cases) == expected_cases and all(c['requests'] == nodes * 800 for c in cases.values())
    if profile == 'client_versions':
        assert all(len(hashes) == 1 for hashes in binary_hashes.values())
        assert len({next(iter(hashes)) for hashes in binary_hashes.values()}) == 2
    return {'complete': bool(complete), 'run_id': next(iter(run_ids)), 'client': 'k6-client-comparison' if profile == 'client_versions' else 'k6-1.3.0',
            'profile': profile, 'client_binary_sha256': {v: next(iter(hashes)) for v, hashes in binary_hashes.items()},
            'verified_distinct_ipv4_exits': len(exits), 'cases': dict(cases), 'slot_start_skew_ms': skew,
            'requests': len(ids), 'request_socket_reset_matches': joins, 'nodes': node_results,
            'worker_requests': 0, 'production_writes': 0,
            'limits': 'This paced, protected-endpoint transport diagnostic does not certify application capacity. '
                      'All four cases use each runner; case order is reversed on even nodes. '
                      'A reset tuple identifies the observed peer and direction, not its upstream initiator. '
                      'Timeouts without a client port have no exact socket join. No retry is added.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--profile', choices=('routes', 'client_versions'), default='routes')
    args = parser.parse_args()
    result = analyze(args.directory, profile=args.profile)
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps({key: result[key] for key in ('complete', 'requests', 'cases', 'slot_start_skew_ms')}))
    if not result['complete']:
        raise SystemExit(1)

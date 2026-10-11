"""Compare fixed transport cases on the same runners; never certify capacity."""
import argparse
import collections
import json
from pathlib import Path

CASES = {'cloudflare/keepalive', 'origin/fresh_iteration', 'cloudflare/fresh_iteration', 'origin/keepalive'}


def matching_resets(request, resets):
    # A zero-phase timeout need not expose a socket. Never infer its client port.
    if not request.get('client_port') or not request.get('peer_ip_fingerprint'):
        return []
    return [reset for reset in resets if reset.get('kind') == 'tcp_reset'
            and reset['client_port'] == request['client_port']
            and reset['peer_ip_fingerprint'] == request['peer_ip_fingerprint']
            and request['started_ms'] / 1000 <= reset['epoch_seconds'] <= request['finished_ms'] / 1000]


def analyze(directory, nodes=10):
    cases = collections.defaultdict(collections.Counter)
    node_results, joins, exits, starts, run_ids = [], [], set(), collections.defaultdict(list), set()
    ids = set()
    complete = True
    for node in range(1, nodes + 1):
        rows = [json.loads(line) for line in (directory / f'k6-transport-node-{node}.jsonl').read_text().splitlines()]
        packets = [json.loads(line) for line in (directory / f'generator-resets-node-{node}.jsonl').read_text().splitlines()]
        resource_path = directory / f'generator-samples-node-{node}.jsonl'
        resources = [json.loads(line) for line in resource_path.read_text().splitlines()]
        status = [row for row in rows if row['kind'] == 'probe_status']
        final = [row for row in rows if row['kind'] == 'probe_final']
        capture_final = [row for row in packets if row['kind'] == 'capture_final']
        assert len(status) == len(final) == len(capture_final) == 1
        assert status[0]['node'] == node and status[0]['client'] == 'k6-1.3.0'
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
        by_case = {row['route'] + '/' + row['connections']: row for row in node_cases}
        assert len(by_case) == len(node_cases)
        for name, row in by_case.items():
            assert name in CASES and row['expected_requests'] == 800 and row['vus'] == 100
            assert row['iterations_per_vu'] == 8 and row['pacing_ms'] == 6250
            assert row['run_id'] == status[0]['run_id'] and row['node'] == node
            complete &= row['complete'] and row['process_exit'] == 0
            starts[row['start_ms']].append(row['scenario_start_ms'])
        per_node = collections.defaultdict(collections.Counter)
        requests = [row for row in rows if row['kind'] == 'request']
        for row in requests:
            assert row['request_id'] not in ids
            ids.add(row['request_id'])
            assert row['run_id'] == status[0]['run_id'] and row['node'] == node
            assert row['finished_ms'] >= row['started_ms'] and row['wall_duration_ms'] == row['finished_ms'] - row['started_ms']
            name = row['route'] + '/' + row['connections']
            assert name in CASES
            counts = cases[name]
            for dest in (counts, per_node[name]):
                dest['requests'] += 1
                dest['http_401'] += int(row['status'] == 401 and not row['error_code'])
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
    complete &= set(cases) == CASES and all(c['requests'] == nodes * 800 for c in cases.values())
    return {'complete': bool(complete), 'run_id': next(iter(run_ids)), 'client': 'k6-1.3.0',
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
    args = parser.parse_args()
    result = analyze(args.directory)
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps({key: result[key] for key in ('complete', 'requests', 'cases', 'slot_start_skew_ms')}))
    if not result['complete']:
        raise SystemExit(1)

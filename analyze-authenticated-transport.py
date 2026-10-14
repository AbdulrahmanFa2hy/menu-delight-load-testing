"""Verify complete paired captures without treating a diagnostic as capacity certification."""
import argparse, collections, json, math, re
from pathlib import Path

CASES = ['tracking/cloudflare', 'tracking/origin', 'games/cloudflare', 'games/origin']

def percentile(values, fraction):
    values = sorted(values)
    if not values: return None
    index = (len(values) - 1) * fraction
    low = math.floor(index)
    return values[low] + (values[min(low + 1, len(values) - 1)] - values[low]) * (index - low)

def analyze(directory, nodes=10):
    totals = collections.defaultdict(collections.Counter)
    failures, node_results, run_ids, exits, hashes = [], [], set(), set(), set()
    starts, unique_ids = collections.defaultdict(list), set()
    complete, all_criteria = True, True
    for node in range(1, nodes + 1):
        rows = [json.loads(line) for line in (directory / f'authenticated-transport-node-{node}.jsonl').read_text().splitlines()]
        packets = [json.loads(line) for line in (directory / f'generator-resets-node-{node}.jsonl').read_text().splitlines()]
        samples = [json.loads(line) for line in (directory / f'generator-samples-node-{node}.jsonl').read_text().splitlines()]
        status = [r for r in rows if r['kind'] == 'probe_status']
        end = [r for r in rows if r['kind'] == 'probe_final']
        finals = [r for r in rows if r['kind'] == 'case_final']
        capture_end = [r for r in packets if r['kind'] == 'capture_final']
        assert len(status) == len(end) == len(capture_end) == 1 and len(finals) == 4
        status = status[0]
        assert status['node'] == node and status['profile'] == 'authenticated_backend' and status['client'] == 'k6-1.3.0'
        assert status['authorization'] == 'anon_api_key_and_fixture_session_capabilities'
        assert status['tls_peer_verified'] and status['tls_hostname_verified'] and not status['capacity_certification']
        assert status['worker_requests'] == 0 and status['seconds'] in (60, 300) and status['connections'] in ('keepalive', 'fresh_iteration')
        assert re.fullmatch(r'[0-9a-f]{64}', status['binary_sha256'])
        run_ids.add(status['run_id']); hashes.add(status['binary_sha256'])
        iterations, slot = (48, 340000) if status['seconds'] == 300 else (8, 80000)
        order = CASES if node % 2 else ['tracking/origin', 'tracking/cloudflare', 'games/origin', 'games/cloudflare']
        plan = status['cases']
        assert [c['name'] for c in plan] == order
        assert [c['start_ms'] for c in plan] == [plan[0]['start_ms'] + i * slot for i in range(4)]
        assert all(c['iterations'] == iterations and c['slot_ms'] == slot for c in plan)
        assert capture_end[0]['omitted_records'] == 0 and capture_end[0]['exit_code'] in (0, -15, 143)
        assert capture_end[0]['reset_records'] == sum(p['kind'] == 'tcp_reset' for p in packets)
        complete &= end[0]['complete']
        requests = [r for r in rows if r['kind'] == 'request']
        assert end[0]['node'] == node and end[0]['run_id'] == status['run_id'] and end[0]['requests'] == len(requests)
        seen = set(); by_case = collections.defaultdict(list)
        for row in requests:
            assert row['node'] == node and row['run_id'] == status['run_id'] and row['connections'] == status['connections']
            assert re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', row['request_id'])
            assert row['request_id'] not in unique_ids; unique_ids.add(row['request_id'])
            name = row['workload'] + '/' + row['route']
            assert name in CASES and row['action'] in ('admission', 'delivery')
            assert 1 <= row['vu'] <= 25 and 0 <= row['iteration'] < iterations
            assert row['finished_ms'] >= row['started_ms'] and row['wall_duration_ms'] == row['finished_ms'] - row['started_ms']
            assert row['connection_context'] == 'vu_observed_connect'
            assert row['route'] != 'origin' or row['status'] == 0 or row['peer_class'] == 'configured_origin'
            assert not row['operation_ok'] or row['status'] in (200, 202)
            key = (name, row['vu'], row['iteration'], row['action'])
            assert key not in seen; seen.add(key); by_case[name].append(row)
            if row['status'] == 0 or row['status'] >= 500:
                exact = [p for p in packets if p['kind'] == 'tcp_reset' and row.get('client_port') and
                         p['client_port'] == row['client_port'] and p['peer_ip_fingerprint'] == row['peer_ip_fingerprint'] and
                         row['started_ms'] / 1000 <= p['epoch_seconds'] <= row['finished_ms'] / 1000]
                peer_time = [p for p in packets if p['kind'] == 'tcp_reset' and p['peer_ip_fingerprint'] == row['peer_ip_fingerprint'] and
                             row['started_ms'] / 1000 <= p['epoch_seconds'] <= row['finished_ms'] / 1000]
                failures.append({**row, 'exact_socket_resets': exact, 'peer_time_resets': peer_time})
        assert len({f['workload'] + '/' + f['route'] for f in finals}) == 4
        networks = {f['network']['ip_fingerprint'] for f in finals}; assert len(networks) == 1
        assert all(re.fullmatch(r'[0-9a-f]{64}', n) for n in networks); exits.update(networks)
        node_cases = {}
        for final in finals:
            name = final['workload'] + '/' + final['route']
            planned = next(c for c in plan if c['name'] == name)
            assert final['start_ms'] == planned['start_ms'] and final['iterations'] == iterations and final['vus'] == 25 and final['pacing_ms'] == 6250
            assert final['node'] == node and final['run_id'] == status['run_id'] and final['connections'] == status['connections']
            assert final['start_ms'] <= final['scenario_start_ms'] <= final['start_ms'] + 2000
            starts[final['start_ms']].append(final['scenario_start_ms'])
            group = by_case[name]; admission = [r for r in group if r['action'] == 'admission']; delivery = [r for r in group if r['action'] == 'delivery']
            assert len(admission) == 25 * iterations
            paired = {(r['vu'], r['iteration']):r for r in admission}
            assert len(paired) == len(admission)
            for row in delivery:
                source = paired[(row['vu'], row['iteration'])]
                assert source['operation_ok'] and source['finished_ms'] <= row['started_ms']
            assert len(delivery) == sum(r['operation_ok'] for r in admission)
            counts = collections.Counter(requests=len(group), admissions=sum(r['operation_ok'] for r in admission),
                deliveries=sum(r['operation_ok'] for r in delivery), transport_errors=sum(r['status'] == 0 for r in group),
                http_5xx=sum(r['status'] >= 500 for r in group), http_429=sum(r['status'] == 429 for r in group),
                new_connections=sum(r['connecting_ms'] > 0 for r in group), journeys_ok=sum(r['operation_ok'] for r in delivery))
            counts['accepted_events'] = counts['deliveries'] * (3 if final['workload'] == 'tracking' else 1)
            for field, expected in [('authenticated_probe',counts['requests']),('transport_failures',counts['transport_errors']),
                                    ('admissions',counts['admissions']),('deliveries',counts['deliveries']),('accepted_events',counts['accepted_events']),('journeys_ok',counts['journeys_ok'])]:
                assert final['counts'][field] == expected
            assert final['counts']['iterations'] == len(admission) and final['counts']['dropped_iterations'] == 0
            latency = percentile([r['duration_ms'] for r in admission], .95)
            derived = {'http_req_failed':sum(r['status'] not in (200, 202) for r in group)/(len(group)+1) < .01,
                'errors':sum(not r['operation_ok'] for r in group)/len(group) < .01,
                'journey_success':counts['journeys_ok']/len(admission) > .99,
                'admission_success':counts['admissions']/len(admission) > .99,
                'delivery_success':bool(delivery) and counts['deliveries']/len(delivery) > .99,
                'session_duration':latency < 2500}
            assert final['criteria'] == derived and final['criteria_passed'] == all(derived.values())
            assert math.isclose(final['session_duration']['p(95)'], latency, abs_tol=.01)
            complete &= final['complete'] and final['process_exit'] in (0, 99)
            all_criteria &= final['criteria_passed']
            assert (final['process_exit'] == 0) == final['criteria_passed']
            for row in group:
                counts[f'status_{row["status"]}'] += 1
                if row['status'] == 0: counts[f'error_code_{row["error_code"]}'] += 1
                counts[f'protocol_{row["proto"]}'] += 1
            totals[name].update(counts)
            node_cases[name] = {'counts':dict(counts),'criteria':derived,'session_p95_ms':latency}
        peaks = {'rss_kib':0,'open_fds':0,'cpu_count':0,'tcp_states':{}}
        for sample in samples:
            peaks['cpu_count'] = max(peaks['cpu_count'], sample['cpu_count'])
            for state,count in sample['tcp_states'].items(): peaks['tcp_states'][state] = max(peaks['tcp_states'].get(state,0),count)
            for process in sample['k6']:
                for key in ('rss_kib','open_fds'): peaks[key] = max(peaks[key],process[key])
        node_results.append({'node':node,'cases':node_cases,'finals':finals,'capture_final':capture_end[0],'generator_peaks':peaks})
    assert len(run_ids) == len(hashes) == 1 and len(exits) == nodes
    assert len(starts) == 4 and all(len(times) == nodes and max(times) - min(times) <= 2000 for times in starts.values())
    return {'complete':bool(complete),'criteria_passed':bool(all_criteria),'capacity_certification':False,
        'run_id':next(iter(run_ids)),'client_binary_sha256':next(iter(hashes)),'requests':len(unique_ids),
        'verified_distinct_ipv4_exits':len(exits),'worker_requests':0,'cases':{k:dict(v) for k,v in totals.items()},
        'slot_start_skew_ms':{str(k):max(v)-min(v) for k,v in starts.items()},'failures':failures,'nodes':node_results,
        'limits':'Backend-only diagnostics omit assets and XR/menu requests and cannot certify full application capacity. '
                 'Connection sequence/age describes VU-observed connects, not an exact HTTP/2 socket. '
                 'Received resets identify an observed peer and direction, not an upstream initiator. No failed write is retried.'}

if __name__ == '__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('directory',type=Path); parser.add_argument('output',type=Path)
    args=parser.parse_args(); result=analyze(args.directory); args.output.write_text(json.dumps(result,indent=2))
    print(json.dumps({k:result[k] for k in ('complete','criteria_passed','requests','cases','slot_start_skew_ms')}))
    if not result['complete']: raise SystemExit(1)

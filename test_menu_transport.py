import importlib.util
import pathlib
import unittest
import json
import tempfile

spec = importlib.util.spec_from_file_location('transport', pathlib.Path(__file__).with_name('analyze-menu-transport.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


class SocketCorrelationTests(unittest.TestCase):
    def xr_fixture(self, directory):
        rows = [{'kind': 'probe_status', 'node': 1, 'run_id': '123-1', 'surface': 'xr_engine',
            'requests_per_case': 50, 'idle_requests_per_case': 8, 'tls_peer_verified': True,
            'tls_hostname_verified': True, 'expected_http_status': 200, 'request_deadline_ms': 15000,
            'expected_body_bytes': transport.XR_BYTES, 'expected_body_sha256': transport.XR_SHA256},
            {'kind': 'generator_network', 'ip_fingerprint': 'exit'},
            {'kind': 'generator_network_after', 'ip_fingerprint': 'exit'},
            {'kind': 'probe_final', 'complete': True, 'requests': 216}]
        for route in ('cloudflare', 'origin'):
            for mode, count in (('fresh', 50), ('keepalive', 50), ('idle_reuse', 8)):
                for sequence in range(count):
                    rows.append({'kind': 'request', 'node': 1, 'run_id': '123-1',
                        'request_id': f'{route}-{mode}-{sequence}', 'route': route, 'connections': mode,
                        'curl_error_code': 0, 'http_status': 200, 'response_bytes': transport.XR_BYTES,
                        'body_sha256': transport.XR_SHA256, 'new_connections': int(mode == 'fresh' or sequence == 0),
                        'elapsed_ms': 100, 'receive_ms': 50, 'maximum_body_gap_ms': 5,
                        'socket': None, 'negotiated_http_version': 3})
        (directory / 'menu-transport-node-1.jsonl').write_text('\n'.join(map(json.dumps, rows)))
        resets = [{'kind': 'capture_status', 'available': True},
            {'kind': 'capture_final', 'omitted_records': 0, 'exit_code': 0, 'reset_records': 0}]
        (directory / 'generator-resets-node-1.jsonl').write_text('\n'.join(map(json.dumps, resets)))
        return rows

    def test_complete_xr_fixture_and_integrity_failure_remains_visible(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = pathlib.Path(folder)
            rows = self.xr_fixture(directory)
            result = transport.analyze(directory, 1)
            self.assertTrue(result['xr_criteria_passed'])
            self.assertFalse(result['capacity_certification'])
            rows[-1]['body_sha256'] = '0' * 64
            (directory / 'menu-transport-node-1.jsonl').write_text('\n'.join(map(json.dumps, rows)))
            result = transport.analyze(directory, 1)
            self.assertFalse(result['xr_criteria_passed'])
            self.assertEqual(result['cases']['origin/idle_reuse']['body_integrity_errors'], 1)

    def test_changed_exit_and_false_fresh_mode_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = pathlib.Path(folder)
            rows = self.xr_fixture(directory)
            rows[2]['ip_fingerprint'] = 'changed'
            (directory / 'menu-transport-node-1.jsonl').write_text('\n'.join(map(json.dumps, rows)))
            with self.assertRaisesRegex(AssertionError, 'Exit changed'):
                transport.analyze(directory, 1)
            rows[2]['ip_fingerprint'] = 'exit'
            rows[4]['new_connections'] = 0
            (directory / 'menu-transport-node-1.jsonl').write_text('\n'.join(map(json.dumps, rows)))
            with self.assertRaisesRegex(AssertionError, 'Fresh connections'):
                transport.analyze(directory, 1)

    def test_xr_body_requires_complete_length_and_exact_digest(self):
        valid = {'response_bytes': transport.XR_BYTES, 'body_sha256': transport.XR_SHA256}
        self.assertTrue(transport.valid_xr_body(valid))
        self.assertFalse(transport.valid_xr_body({**valid, 'response_bytes': transport.XR_BYTES - 1}))
        self.assertFalse(transport.valid_xr_body({**valid, 'body_sha256': '0' * 64}))
        self.assertFalse(transport.valid_xr_body({}))

    def test_reused_socket_reset_belongs_only_to_its_live_request(self):
        socket = {'peer_ip_fingerprint': 'peer-a', 'client_port': 12345, 'ready_epoch_seconds': 10}
        first = {'socket': socket, 'ended_epoch_seconds': 11}
        second = {'socket': {**socket, 'ready_epoch_seconds': 12}, 'ended_epoch_seconds': 13}
        reset = {'kind': 'tcp_reset', 'peer_ip_fingerprint': 'peer-a', 'client_port': 12345, 'epoch_seconds': 12.5}
        self.assertEqual(transport.matching_resets(first, [reset]), [])
        self.assertEqual(transport.matching_resets(second, [reset]), [reset])

    def test_other_socket_and_before_ready_do_not_match(self):
        request = {'socket': {'peer_ip_fingerprint': 'a', 'client_port': 12345, 'ready_epoch_seconds': 10},
                   'ended_epoch_seconds': 11}
        base = {'kind': 'tcp_reset', 'peer_ip_fingerprint': 'a', 'client_port': 12345, 'epoch_seconds': 10.5}
        wrong = [{**base, 'peer_ip_fingerprint': 'b'}, {**base, 'client_port': 23456}, {**base, 'epoch_seconds': 9.99}]
        self.assertEqual(transport.matching_resets(request, wrong), [])

    def test_early_handshake_failure_has_no_socket_join(self):
        self.assertEqual(transport.matching_resets({'socket': None}, [{'kind': 'tcp_reset'}]), [])

    def test_reconnect_retains_reset_on_the_first_socket(self):
        old = {'peer_ip_fingerprint': 'a', 'client_port': 12345, 'ready_epoch_seconds': 10}
        new = {**old, 'client_port': 23456, 'ready_epoch_seconds': 10.7}
        request = {'socket': new, 'socket_attempts': [old, new], 'ended_epoch_seconds': 11}
        reset = {'kind': 'tcp_reset', 'peer_ip_fingerprint': 'a', 'client_port': 12345, 'epoch_seconds': 10.5}
        self.assertEqual(transport.matching_resets(request, [reset]), [reset])

    def test_pre_tls_reset_matches_allocated_socket_without_http_ready_callback(self):
        allocation = {'peer_ip_fingerprint': 'a', 'client_port': 12345, 'allocated_epoch_seconds': 10}
        request = {'socket': None, 'connect_socket_attempts': [allocation], 'ended_epoch_seconds': 11}
        reset = {'kind': 'tcp_reset', 'peer_ip_fingerprint': 'a', 'client_port': 12345, 'epoch_seconds': 10.5}
        self.assertEqual(transport.matching_resets(request, [reset]), [reset])
        self.assertEqual(transport.matching_resets(request, [{**reset, 'client_port': 23456}]), [])
        self.assertEqual(transport.matching_resets(request, [{**reset, 'epoch_seconds': 9.99}]), [])
        self.assertEqual(transport.matching_resets(request, [{**reset, 'epoch_seconds': 11.01}]), [])

    def test_earlier_allocated_connection_can_win_after_another_socket_is_opened(self):
        first = {'peer_ip_fingerprint': 'a', 'client_port': 12345, 'allocated_epoch_seconds': 10}
        later = {'peer_ip_fingerprint': 'b', 'client_port': 23456, 'allocated_epoch_seconds': 10.1}
        request = {'socket': {'peer_ip_fingerprint': 'a', 'client_port': 12345, 'ready_epoch_seconds': 10.3},
                   'connect_socket_attempts': [first, later], 'ended_epoch_seconds': 11}
        reset = {'kind': 'tcp_reset', 'peer_ip_fingerprint': 'a', 'client_port': 12345, 'epoch_seconds': 10.2}
        self.assertEqual(transport.matching_resets(request, [reset]), [reset])


if __name__ == '__main__':
    unittest.main()

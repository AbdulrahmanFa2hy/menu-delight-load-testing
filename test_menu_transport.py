import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('transport', pathlib.Path(__file__).with_name('analyze-menu-transport.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


class SocketCorrelationTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()

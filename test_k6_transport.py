import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('transport', pathlib.Path(__file__).with_name('analyze-k6-transport.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


class WindowCorrelationTests(unittest.TestCase):
    def test_zero_phase_window_includes_late_reset_and_excludes_other_socket(self):
        request = {'client_port': 12345, 'peer_ip_fingerprint': 'a', 'started_ms': 10000, 'finished_ms': 25000}
        reset = {'kind': 'tcp_reset', 'client_port': 12345, 'peer_ip_fingerprint': 'a', 'epoch_seconds': 24.9}
        self.assertEqual(transport.matching_resets(request, [reset]), [reset])
        for wrong in ({**reset, 'client_port': 23456}, {**reset, 'peer_ip_fingerprint': 'b'},
                      {**reset, 'epoch_seconds': 25.1}, {**reset, 'epoch_seconds': 9.9}):
            self.assertEqual(transport.matching_resets(request, [wrong]), [])

    def test_missing_socket_is_not_inferred(self):
        request = {'client_port': None, 'peer_ip_fingerprint': 'a', 'started_ms': 10000, 'finished_ms': 25000}
        reset = {'kind': 'tcp_reset', 'client_port': 12345, 'peer_ip_fingerprint': 'a', 'epoch_seconds': 24.9}
        self.assertEqual(transport.matching_resets(request, [reset]), [])

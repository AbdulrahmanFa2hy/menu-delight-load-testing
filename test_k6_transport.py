import importlib.util
import pathlib
import unittest
import json
import tempfile
import uuid

spec = importlib.util.spec_from_file_location('transport', pathlib.Path(__file__).with_name('analyze-k6-transport.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


class WindowCorrelationTests(unittest.TestCase):
    def test_expected_401_k6_status_code_is_not_a_transport_failure(self):
        self.assertTrue(transport.expected_denial({'status': 401, 'error_code': 1401}))
        self.assertTrue(transport.expected_denial({'status': 401, 'error_code': 0}))
        self.assertFalse(transport.expected_denial({'status': 401, 'error_code': 1050}))
        self.assertFalse(transport.expected_denial({'status': 0, 'error_code': 1401}))

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


class ClientComparisonTests(unittest.TestCase):
    def fixture(self, directory):
        plan = [{'name':name, 'start_ms':10000+index*80000} for index,name in enumerate(transport.CLIENT_CASES)]
        rows = [{'kind':'probe_status','node':1,'run_id':'123-1','client':'k6-client-comparison','profile':'client_versions',
                 'binaries':[{'version':version,'sha256':char*64,'version_verified':True} for version,char in [('1.3.0','a'),('2.3.0','b')]],
                 'tls_peer_verified':True,'tls_hostname_verified':True,'authorization':'missing','expected_http_status':401,
                 'worker_requests':0,'production_writes':0,'cases':plan}]
        for case in plan:
            version, connections = case['name'].split('/')
            for vu in range(1,101):
                for iteration in range(8):
                    rows.append({'kind':'request','node':1,'run_id':'123-1','route':'cloudflare','connections':connections,'client_version':version,
                                 'vu':vu,'iteration':iteration,'request_id':str(uuid.uuid5(uuid.NAMESPACE_URL,f'{case["name"]}/{vu}/{iteration}')),
                                 'started_ms':case['start_ms']+iteration*6250,'finished_ms':case['start_ms']+iteration*6250+20,
                                 'wall_duration_ms':20,'status':401,'error_code':1401,'connecting_ms':0 if iteration else 5,'proto':'HTTP/1.1'})
            rows.append({'kind':'case_final','node':1,'run_id':'123-1','route':'cloudflare','connections':connections,'client_version':version,
                         'expected_requests':800,'vus':100,'iterations_per_vu':8,'pacing_ms':6250,'complete':True,'process_exit':0,
                         'start_ms':case['start_ms'],'scenario_start_ms':case['start_ms']+1,
                         'network':{'ip_fingerprint':'c'*64},'counts':{'transport_probe':800,'transport_failures':0,'unexpected_status':0}})
        rows.append({'kind':'probe_final','complete':True})
        (directory/'generator-resets-node-1.jsonl').write_text(json.dumps({'kind':'capture_final','omitted_records':0,'exit_code':-15,'reset_records':0})+'\n')
        (directory/'generator-samples-node-1.jsonl').write_text('')
        return rows

    def evaluate(self, mutate=None):
        with tempfile.TemporaryDirectory() as folder:
            directory=pathlib.Path(folder)
            rows=self.fixture(directory)
            if mutate: mutate(rows)
            (directory/'k6-transport-node-1.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows))
            return transport.analyze(directory,nodes=1,profile='client_versions')

    def test_complete_paired_capture_has_four_separate_client_cases(self):
        result=self.evaluate()
        self.assertTrue(result['complete'])
        self.assertEqual(result['requests'],3200)
        self.assertEqual(set(result['cases']),set(transport.CLIENT_CASES))
        self.assertEqual(result['worker_requests'],0)

    def test_missing_iteration_cannot_be_a_complete_comparison(self):
        with self.assertRaises(AssertionError): self.evaluate(lambda rows: rows.pop(1))

    def test_duplicate_vu_iteration_with_different_request_id_is_rejected(self):
        with self.assertRaises(AssertionError): self.evaluate(lambda rows: rows[2].update(iteration=0))

    def test_mislabeled_client_cannot_silently_move_between_cases(self):
        with self.assertRaises(AssertionError): self.evaluate(lambda rows: rows[1].update(client_version='2.3.0'))

    def test_same_binary_cannot_be_labeled_as_two_versions(self):
        with self.assertRaises(AssertionError): self.evaluate(lambda rows: rows[0]['binaries'][1].update(sha256='a'*64))

    def test_unbalanced_order_is_rejected(self):
        with self.assertRaises(AssertionError): self.evaluate(lambda rows: rows[0]['cases'].reverse())

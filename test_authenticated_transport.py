import importlib.util, json, tempfile, unittest, uuid
from pathlib import Path

spec=importlib.util.spec_from_file_location('authenticated',Path(__file__).with_name('analyze-authenticated-transport.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class AuthenticatedCoverageTests(unittest.TestCase):
    def fixture(self):
        plan=[{'name':name,'start_ms':10000+i*80000,'iterations':8,'slot_ms':80000} for i,name in enumerate(module.CASES)]
        rows=[{'kind':'probe_status','run_id':'123-1','node':1,'profile':'authenticated_backend','client':'k6-1.3.0',
            'binary_sha256':'a'*64,'authorization':'anon_api_key_and_fixture_session_capabilities',
            'tls_peer_verified':True,'tls_hostname_verified':True,'capacity_certification':False,'worker_requests':0,
            'seconds':60,'connections':'keepalive','cases':plan}]
        criteria={key:True for key in ('http_req_failed','errors','journey_success','admission_success','delivery_success','session_duration')}
        for planned in plan:
            workload,route=planned['name'].split('/')
            for vu in range(1,26):
                for iteration in range(8):
                    for action in ('admission','delivery'):
                        started=planned['start_ms']+iteration*6250+(100 if action=='delivery' else 0)
                        rows.append({'kind':'request','run_id':'123-1','node':1,'workload':workload,'route':route,
                            'connections':'keepalive','vu':vu,'iteration':iteration,'action':action,'request_id':str(uuid.uuid4()),
                            'started_ms':started,'finished_ms':started+100,'wall_duration_ms':100,'duration_ms':100,
                            'connection_context':'vu_observed_connect','peer_class':'configured_origin' if route=='origin' else 'cloudflare',
                            'operation_ok':True,'status':200,'error_code':0,'connecting_ms':0,'proto':'HTTP/2.0'})
            rows.append({'kind':'case_final','run_id':'123-1','node':1,'workload':workload,'route':route,'connections':'keepalive',
                'start_ms':planned['start_ms'],'scenario_start_ms':planned['start_ms']+1,'iterations':8,'vus':25,'pacing_ms':6250,
                'network':{'ip_fingerprint':'b'*64},'complete':True,'process_exit':0,'criteria_passed':True,'criteria':dict(criteria),
                'session_duration':{'p(95)':100},'counts':{'iterations':200,'dropped_iterations':0,'authenticated_probe':400,
                    'admissions':200,'deliveries':200,'journeys_ok':200,'accepted_events':600 if workload=='tracking' else 200,'transport_failures':0}})
        rows.append({'kind':'probe_final','run_id':'123-1','node':1,'requests':1600,'complete':True})
        return rows

    def evaluate(self,mutate=None):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);rows=self.fixture()
            if mutate:mutate(rows)
            (root/'authenticated-transport-node-1.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
            (root/'generator-resets-node-1.jsonl').write_text(json.dumps({'kind':'capture_final','reset_records':0,'omitted_records':0,'exit_code':-15})+'\n')
            (root/'generator-samples-node-1.jsonl').write_text('')
            return module.analyze(root,nodes=1)

    def test_complete_paired_success_never_certifies_capacity(self):
        result=self.evaluate();self.assertTrue(result['complete']);self.assertTrue(result['criteria_passed'])
        self.assertFalse(result['capacity_certification']);self.assertEqual(result['requests'],1600)
        self.assertEqual(result['cases']['tracking/origin']['accepted_events'],600)

    def test_missing_iteration_is_rejected(self):
        with self.assertRaises(AssertionError):self.evaluate(lambda rows:rows.pop(1))

    def test_duplicate_iteration_with_unique_id_is_rejected(self):
        with self.assertRaises(AssertionError):self.evaluate(lambda rows:rows[3].update(iteration=0))

    def test_origin_peer_cannot_be_cloudflare(self):
        def mutate(rows):next(r for r in rows if r['kind']=='request' and r['route']=='origin')['peer_class']='cloudflare'
        with self.assertRaises(AssertionError):self.evaluate(mutate)

    def test_capability_followup_without_admission_is_rejected(self):
        with self.assertRaises(AssertionError):self.evaluate(lambda rows:rows[1].update(operation_ok=False))

    def test_swapped_schedule_is_rejected(self):
        with self.assertRaises(AssertionError):self.evaluate(lambda rows:rows[0]['cases'].reverse())

    def test_fake_slo_pass_is_rejected(self):
        def summary(rows):next(r for r in rows if r['kind']=='case_final')['session_duration']['p(95)']=0
        with self.assertRaises(AssertionError):self.evaluate(summary)

if __name__=='__main__':unittest.main()

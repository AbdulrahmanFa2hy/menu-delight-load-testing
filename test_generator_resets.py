import importlib.util, json, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('capture_generator_resets',Path(__file__).with_name('capture-generator-resets.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
parse_reset=module.parse_reset

class ResetMetadataTests(unittest.TestCase):
    def test_direction_tuple_and_redaction(self):
        for text,direction,port in [
            ('1791030000.123 eth0 In IP 172.67.1.2.443 > 10.1.0.4.41234: tcp 0 secret-url?token=never-export','received',41234),
            ('1791030000.123 eth0 Out IP 10.1.0.4.42345 > 172.67.1.2.443: tcp 0','sent',42345),
            ('1791030000.123 eth0 In IP6 2606:4700::1.443 > fd00::2.43456: tcp 0','received',43456),
        ]:
            row=parse_reset(text,{'10.1.0.4','fd00::2'},'37100000000-1')
            self.assertEqual(row['direction'],direction);self.assertEqual(row['client_port'],port)
            self.assertEqual(len(row['peer_ip_fingerprint']),64)
            self.assertNotIn('never-export',json.dumps(row));self.assertNotIn('172.67.1.2',json.dumps(row))
    def test_malformed_and_unrelated_packets_are_ignored(self):
        for line in ['secret-url?token=never-export','1791030000.123 IP 999.1.2.3.443 > 10.1.0.4.50000: tcp 0',
            '1791030000.123 IP 172.67.1.2.443 > 10.9.0.4.50000: tcp 0','1791030000.123 IP 172.67.1.2.443 > 10.1.0.4.99999: tcp 0']:
            self.assertIsNone(parse_reset(line,{'10.1.0.4'},'37100000000-1'))

if __name__=='__main__':unittest.main()

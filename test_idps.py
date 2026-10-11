#!/usr/bin/env python3
"""
Automated Test Suite for SkyFireWall IDPS (Trained on NSL-KDD)
"""

import os
import sys
import unittest
import scapy.all as scapy

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from idps.model import IDPSModel, ATTACK_MAP
from idps.feature_extractor import LiveFeatureExtractor, PacketFlowTracker, resolve_service, map_tcp_flag
from idps.prevention import FirewallPreventionManager
from idps.engine import IDPSEngine
from idps.alert_logger import IDPSAlertLogger

class TestIDPSModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        model_path = os.path.join(BASE_DIR, "models", "idps_nsl_kdd.joblib")
        cls.model = IDPSModel(model_bundle_path=model_path)

    def test_model_loaded(self):
        self.assertTrue(self.model.is_trained, "Model should be loaded and marked trained")
        self.assertIsNotNone(self.model.binary_pipeline)
        self.assertIsNotNone(self.model.category_pipeline)

    def test_normal_traffic_prediction(self):
        # Sample normal HTTP connection features
        sample_normal = {
            'duration': 0.0,
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'SF',
            'src_bytes': 215.0,
            'dst_bytes': 3450.0,
            'land': 0,
            'wrong_fragment': 0.0,
            'urgent': 0.0,
            'hot': 0.0,
            'num_failed_logins': 0.0,
            'logged_in': 1.0,
            'count': 5.0,
            'srv_count': 5.0,
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 30.0,
            'dst_host_srv_count': 255.0,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.03,
            'dst_host_srv_diff_host_rate': 0.04,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
        res = self.model.predict(sample_normal)
        self.assertFalse(res['is_attack'], "Normal traffic should not be flagged as attack")
        self.assertEqual(res['category'], 'Normal')
        self.assertEqual(res['threat_level'], 'LOW')

    def test_dos_attack_prediction(self):
        # Sample Neptune (SYN flood DoS) connection features
        sample_neptune = {
            'duration': 0.0,
            'protocol_type': 'tcp',
            'service': 'private',
            'flag': 'S0',
            'src_bytes': 0.0,
            'dst_bytes': 0.0,
            'land': 0,
            'wrong_fragment': 0.0,
            'urgent': 0.0,
            'hot': 0.0,
            'num_failed_logins': 0.0,
            'logged_in': 0.0,
            'count': 123.0,
            'srv_count': 6.0,
            'serror_rate': 1.0,
            'srv_serror_rate': 1.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.05,
            'diff_srv_rate': 0.07,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 255.0,
            'dst_host_srv_count': 26.0,
            'dst_host_same_srv_rate': 0.10,
            'dst_host_diff_srv_rate': 0.05,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 1.0,
            'dst_host_srv_serror_rate': 1.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
        res = self.model.predict(sample_neptune)
        self.assertTrue(res['is_attack'], "Neptune DoS traffic must be detected as an attack")
        self.assertEqual(res['category'], 'DoS')
        self.assertEqual(res['threat_level'], 'CRITICAL')


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = LiveFeatureExtractor()

    def test_service_and_flag_resolution(self):
        self.assertEqual(resolve_service(80, 'tcp'), 'http')
        self.assertEqual(resolve_service(443, 'tcp'), 'http_443')
        self.assertEqual(resolve_service(22, 'tcp'), 'ssh')
        self.assertEqual(resolve_service(53, 'udp'), 'domain_u')

        self.assertEqual(map_tcp_flag(0x02, is_syn=True, is_ack=False, is_fin=False, is_rst=False), 'S0')
        self.assertEqual(map_tcp_flag(0x12, is_syn=True, is_ack=True, is_fin=False, is_rst=False), 'S1')
        self.assertEqual(map_tcp_flag(0x04, is_syn=False, is_ack=False, is_fin=False, is_rst=True), 'REJ')
        self.assertEqual(map_tcp_flag(0x11, is_syn=False, is_ack=True, is_fin=True, is_rst=False), 'SF')

    def test_scapy_packet_extraction(self):
        pkt = scapy.IP(src="192.168.1.100", dst="10.0.0.5") / scapy.TCP(sport=54321, dport=80, flags="S")
        features, meta = self.extractor.extract_from_scapy(pkt)

        self.assertEqual(meta['src_ip'], '192.168.1.100')
        self.assertEqual(meta['dst_ip'], '10.0.0.5')
        self.assertEqual(meta['protocol'], 'TCP')
        self.assertEqual(meta['service'], 'http')
        self.assertEqual(meta['flag'], 'S0')

        self.assertIn('duration', features)
        self.assertIn('dst_host_count', features)
        self.assertIn('serror_rate', features)
        self.assertEqual(features['protocol_type'], 'tcp')


class TestFirewallPrevention(unittest.TestCase):
    def setUp(self):
        self.pm = FirewallPreventionManager(protected_ips={'10.0.0.1', '192.168.1.1'})

    def test_protected_ip_whitelist(self):
        self.assertTrue(self.pm.is_protected('127.0.0.1'))
        self.assertTrue(self.pm.is_protected('localhost'))
        self.assertTrue(self.pm.is_protected('10.0.0.1'))
        # Should refuse to block protected IP
        self.assertFalse(self.pm.block_ip('127.0.0.1'))
        self.assertFalse(self.pm.block_ip('10.0.0.1'))

    def test_block_and_track(self):
        attacker_ip = "198.51.100.77"
        self.assertFalse(self.pm.is_blocked(attacker_ip))
        # Simulated block
        with self.pm.lock:
            self.pm.dynamically_blocked_ips.add(attacker_ip)
        self.assertTrue(self.pm.is_blocked(attacker_ip))
        # Unblock cleanup
        self.pm.unblock_all()
        self.assertFalse(self.pm.is_blocked(attacker_ip))


class TestEndToEndIDPSEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        model_path = os.path.join(BASE_DIR, "models", "idps_nsl_kdd.joblib")
        cls.engine = IDPSEngine(
            model_path=model_path,
            confidence_threshold=0.60,
            enable_prevention=False # Test mode without touching OS firewall rules
        )

    def test_inspect_normal_packet(self):
        pkt = scapy.IP(src="192.168.1.50", dst="10.0.0.1") / scapy.TCP(sport=50000, dport=80, flags="A") / scapy.Raw(load=b"GET / HTTP/1.1\r\n\r\n")
        res = self.engine.inspect_and_enforce(pkt)
        self.assertEqual(res['ips_action'], 'ALLOW')

    def test_inspect_syn_flood_dos(self):
        # Simulate burst of SYN packets from same host with no replies (S0 flag)
        for i in range(10):
            pkt = scapy.IP(src="203.0.113.99", dst="10.0.0.1") / scapy.TCP(sport=40000 + i, dport=135, flags="S")
            res = self.engine.inspect_and_enforce(pkt)

        # After several SYN error connections, it must trigger detection
        self.assertTrue(res['is_attack'])
        self.assertEqual(res['threat_level'], 'CRITICAL')
        self.assertIn(res['category'], ['DoS', 'Probe'])

if __name__ == "__main__":
    unittest.main()

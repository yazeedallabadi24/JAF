"""Unit tests for Phase 3: Outbound Tool & URL Egress Firewall."""

import base64
import unittest
from core.phase3_egress_firewall import EgressFirewall


class TestPhase3EgressFirewall(unittest.TestCase):
    def setUp(self):
        self.firewall = EgressFirewall()

    def test_benign_outbound_url(self):
        url = "https://api.github.com/repos/yazeedallabadi24/JAF"
        res = self.firewall.inspect_egress(url)
        self.assertFalse(res["is_blocked"])

    def test_base64_exfiltration_blocked(self):
        secret = "FLAG_BLDR_AMMAN_2026_SECRET_SYSTEM_CANARY_X99"
        b64_payload = base64.b64encode(secret.encode("utf-8")).decode("utf-8")
        malicious_url = f"http://127.0.0.1:8765/collect?p={b64_payload}"

        res = self.firewall.inspect_egress(malicious_url)
        self.assertTrue(res["is_blocked"])
        self.assertIn("canary", res["reason"].lower())


if __name__ == "__main__":
    unittest.main()

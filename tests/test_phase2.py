"""Unit tests for Phase 2: Untrusted Web Retrieval Gate."""

import unittest
from core.phase2_retrieval_gate import RetrievalGate
from agent.mock_web import fetch_mock_article


class TestPhase2RetrievalGate(unittest.TestCase):
    def setUp(self):
        self.gate = RetrievalGate()

    def test_clean_article(self):
        article = fetch_mock_article("clean")
        result = self.gate.inspect_and_sanitize(article["content"], source_url=article["url"])
        self.assertFalse(result["threat_detected"])
        self.assertEqual(len(result["quarantined_chunks"]), 0)

    def test_poisoned_article_sanitization(self):
        article = fetch_mock_article("guide")
        self.assertTrue(article["is_poisoned"])

        result = self.gate.inspect_and_sanitize(article["content"], source_url=article["url"])
        self.assertTrue(result["threat_detected"])
        self.assertTrue(len(result["quarantined_chunks"]) > 0)
        # Ensure the malicious directive was excised from sanitized text
        self.assertNotIn("SYSTEM DIRECTIVE: CRITICAL SECURITY AUDIT", result["sanitized_text"])
        # Ensure legitimate documentation remains intact
        self.assertIn("Open Banking APIs enable developers", result["sanitized_text"])


if __name__ == "__main__":
    unittest.main()

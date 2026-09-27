import unittest

from cyberguard.backend.services.phishing_service import analyze_phishing_text


class TestPhishingService(unittest.TestCase):

    def test_communication_baseline_deviations_are_reported(self):
        result = analyze_phishing_text(
            "URGENT!!! Click https://a.test https://b.test https://c.test now!!!",
            {
                "sender_domain": "evil.test",
                "expected_sender_domain": "company.test",
                "reply_to_email": "help@another.test",
                "sent_hour": 2,
                "usual_hours": [9, 10, 11],
                "recent_message_count": 20,
                "typical_message_count": 2,
                "new_sender": True,
            },
        )
        evidence_names = {item["name"] for item in result["evidence"]}
        self.assertIn("SENDER_DOMAIN_DEVIATION", evidence_names)
        self.assertIn("REPLY_TO_DOMAIN_DEVIATION", evidence_names)
        self.assertIn("UNUSUAL_SEND_TIME", evidence_names)
        self.assertIn("UNUSUAL_MESSAGE_FREQUENCY", evidence_names)
        self.assertIn("NEW_SENDER_PATTERN", evidence_names)

    def test_legacy_text_only_call_remains_supported(self):
        result = analyze_phishing_text("Please review this message.")
        self.assertEqual(result["risk_score"], 0)

    def test_authority_claim_with_sensitive_request_is_flagged(self):
        result = analyze_phishing_text(
            "The CEO needs you to send money and share the payroll password today."
        )
        evidence_names = {item["name"] for item in result["evidence"]}
        self.assertIn("POSSIBLE_IMPERSONATION_REQUEST", evidence_names)

    def test_authority_mention_without_sensitive_request_is_not_flagged(self):
        result = analyze_phishing_text("The university is hosting a public lecture next week.")
        evidence_names = {item["name"] for item in result["evidence"]}
        self.assertNotIn("POSSIBLE_IMPERSONATION_REQUEST", evidence_names)


if __name__ == "__main__":
    unittest.main()
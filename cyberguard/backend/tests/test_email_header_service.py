import unittest
from cyberguard.backend.services.email_header_service import parse_email_headers

class TestEmailHeaderService(unittest.TestCase):
    def test_spf_fail_detection(self):
        raw_headers = '''Received-SPF: Fail (example.com: domain of user@example.com does not designate 1.2.3.4 as permitted sender)\nAuthentication-Results: mx.google.com; spf=fail; dkim=pass; dmarc=pass'''
        contributions, _ = parse_email_headers(raw_headers)
        self.assertIn('SPF_AUTHENTICATION_FAIL', contributions)
        self.assertEqual(contributions['SPF_AUTHENTICATION_FAIL'], 40)

    def test_dkim_and_dmarc_fail(self):
        raw_headers = '''Authentication-Results: mx.google.com; dkim=fail; dmarc=fail'''
        contributions, _ = parse_email_headers(raw_headers)
        self.assertIn('DKIM_SIGNATURE_FAIL', contributions)
        self.assertIn('DMARC_POLICY_FAIL', contributions)
        self.assertEqual(contributions['DKIM_SIGNATURE_FAIL'], 35)
        self.assertEqual(contributions['DMARC_POLICY_FAIL'], 45)

    def test_spoofed_return_path(self):
        raw_headers = '''From: Security Team <security@paypal.com>\nReturn-Path: <attacker@evil-domain.com>'''
        contributions, headers_info = parse_email_headers(raw_headers)
        self.assertIn('SPOOFED_RETURN_PATH_DOMAIN', contributions)
        self.assertEqual(contributions['SPOOFED_RETURN_PATH_DOMAIN'], 45)

    def test_all_pass_no_contributions(self):
        raw_headers = '''From: Support <support@example.com>\nReturn-Path: <support@example.com>\nReceived-SPF: Pass (example.com: domain of user@example.com designates 1.2.3.4 as permitted sender)\nAuthentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass'''
        contributions, _ = parse_email_headers(raw_headers)
        self.assertEqual(contributions, {})

if __name__ == '__main__':
    unittest.main()

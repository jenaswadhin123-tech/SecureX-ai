import unittest
from unittest.mock import patch, MagicMock
from cyberguard.backend.services.url_service import _inspect_website, _query_google_safe_browsing, analyze_url

class TestURLService(unittest.TestCase):

    def test_plain_text_is_rejected_as_a_url(self):
        with self.assertRaisesRegex(ValueError, "complete URL"):
            analyze_url("WEBSITE_PASSWORD_FORM WEBSITE_CREDENTIAL_LANGUAGE")

    def test_url_without_scheme_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "http:// or https://"):
            analyze_url("example.com/login")

    @patch("cyberguard.backend.config.SAFE_BROWSING_API_KEY", "")
    def test_gsb_no_api_key(self):
        score = _query_google_safe_browsing("http://malware.testing.google.test")
        self.assertEqual(score, 0)

    @patch("cyberguard.backend.config.SAFE_BROWSING_API_KEY", "FAKE_KEY")
    @patch("requests.post")
    def test_gsb_malware_match(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "matches": [{"threatType": "MALWARE"}]
        }
        mock_post.return_value = mock_resp

        score = _query_google_safe_browsing("http://malware.testing.google.test")
        self.assertEqual(score, 80)

    @patch("cyberguard.backend.config.SAFE_BROWSING_API_KEY", "FAKE_KEY")
    @patch("requests.post")
    def test_gsb_social_engineering_match(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "matches": [{"threatType": "SOCIAL_ENGINEERING"}]
        }
        mock_post.return_value = mock_resp

        score = _query_google_safe_browsing("http://phishing.testing.google.test")
        self.assertEqual(score, 90)

    @patch("cyberguard.backend.config.SAFE_BROWSING_API_KEY", "FAKE_KEY")
    @patch("requests.post")
    def test_analyze_url_with_gsb(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "matches": [{"threatType": "SOCIAL_ENGINEERING"}]
        }
        mock_post.return_value = mock_resp

        result = analyze_url("http://example.com")
        self.assertIn("GOOGLE_SAFE_BROWSING", [e["name"] for e in result["evidence"]])
        self.assertGreaterEqual(result["risk_score"], 70)

    @patch("cyberguard.backend.services.url_service._is_public_hostname", return_value=True)
    @patch("requests.get")
    def test_website_inspection_detects_deceptive_login_page(self, mock_get, _mock_public_host):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8", "Location": ""}
        mock_resp.encoding = "utf-8"
        mock_resp.iter_content.return_value = [
            b"<title>PayPal account verification</title>"
            b"<form><input type='password'></form>"
            b"Your account is suspended. Verify your password immediately."
        ]
        mock_get.return_value = mock_resp

        evidence = _inspect_website("https://secure-login.example.com")
        self.assertIn("WEBSITE_PASSWORD_FORM", evidence)
        self.assertIn("WEBSITE_CREDENTIAL_LANGUAGE", evidence)
        self.assertIn("WEBSITE_URGENCY_LANGUAGE", evidence)
        self.assertIn("WEBSITE_BRAND_DOMAIN_MISMATCH", evidence)

    @patch("cyberguard.backend.services.url_service._is_public_hostname", return_value=False)
    @patch("requests.get")
    def test_website_inspection_skips_private_hosts(self, mock_get, _mock_public_host):
        self.assertEqual(_inspect_website("http://127.0.0.1/admin"), {})
        mock_get.assert_not_called()

if __name__ == "__main__":
    unittest.main()

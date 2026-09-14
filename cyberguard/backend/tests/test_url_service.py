import unittest
from unittest.mock import patch, MagicMock
from cyberguard.backend.services.url_service import _query_google_safe_browsing, analyze_url

class TestURLService(unittest.TestCase):

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

if __name__ == "__main__":
    unittest.main()

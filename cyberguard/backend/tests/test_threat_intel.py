import unittest
from unittest.mock import patch, MagicMock
from cyberguard.backend.services.virustotal_service import _query_virustotal_url
from cyberguard.backend.services.abuseipdb_service import _query_abuseipdb_ip
from cyberguard.backend.services.url_service import analyze_url
from cyberguard.backend.services.account_service import analyze_account_log

class TestThreatIntel(unittest.TestCase):

    @patch("cyberguard.backend.config.VIRUSTOTAL_API_KEY", "")
    def test_virustotal_no_api_key(self):
        score = _query_virustotal_url("http://example.com")
        self.assertEqual(score, 0)

    @patch("cyberguard.backend.config.VIRUSTOTAL_API_KEY", "FAKE_VT_KEY")
    @patch("requests.get")
    def test_virustotal_malicious_detection(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 4,
                        "suspicious": 1
                    }
                }
            }
        }
        mock_get.return_value = mock_resp

        score = _query_virustotal_url("http://malware.test")
        self.assertEqual(score, 95)

    @patch("cyberguard.backend.config.ABUSEIPDB_API_KEY", "")
    def test_abuseipdb_no_api_key(self):
        score = _query_abuseipdb_ip("192.168.1.1")
        self.assertEqual(score, 0)

    @patch("cyberguard.backend.config.ABUSEIPDB_API_KEY", "FAKE_ABUSE_KEY")
    @patch("requests.get")
    def test_abuseipdb_high_abuse_score(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 88
            }
        }
        mock_get.return_value = mock_resp

        score = _query_abuseipdb_ip("1.2.3.4")
        self.assertEqual(score, 88)

    @patch("cyberguard.backend.config.VIRUSTOTAL_API_KEY", "FAKE_VT_KEY")
    @patch("requests.get")
    def test_analyze_url_with_virustotal(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 0
                    }
                }
            }
        }
        mock_get.return_value = mock_resp

        result = analyze_url("http://suspicious.example")
        self.assertIn("VIRUSTOTAL_SCAN", [e["name"] for e in result["evidence"]])
        self.assertGreaterEqual(result["risk_score"], 60)

if __name__ == "__main__":
    unittest.main()

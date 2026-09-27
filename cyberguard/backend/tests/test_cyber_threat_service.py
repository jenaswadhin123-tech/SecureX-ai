import unittest

from cyberguard.backend.services.cyber_threat_service import analyze_cyber_events


class TestCyberThreatService(unittest.TestCase):
    def test_detects_malware_indicator(self):
        result = analyze_cyber_events([
            {"user": "analyst", "event_type": "endpoint_alert", "threat_indicator": "Trojan.Test"}
        ])

        evidence_names = {item["name"] for item in result["evidence"]}
        self.assertIn("MALWARE_INDICATOR", evidence_names)
        self.assertEqual(result["risk_score"], 55)

    def test_detects_api_abuse_outbound_exfiltration_and_suspicious_port(self):
        events = [
            {
                "event_type": "api_request",
                "user": "service-account",
                "status_code": 429,
                "request_count": 20,
            },
            {
                "event_type": "network",
                "user": "service-account",
                "direction": "egress",
                "destination_port": 4444,
                "bytes_out": 110 * 1024 * 1024,
            },
        ]

        result = analyze_cyber_events(events)

        evidence_names = {item["name"] for item in result["evidence"]}
        self.assertTrue({"API_ABUSE", "POSSIBLE_DATA_EXFILTRATION", "SUSPICIOUS_OUTBOUND_PORT"}.issubset(evidence_names))

    def test_detects_insider_activity_abnormal_activity_and_unusual_logs(self):
        events = [
            {"user": "employee-1", "action": "bulk_download"}
            for _ in range(5)
        ]
        events.extend([
            {"user": "employee-1", "action": "privilege_escalation"},
            {"user": "employee-1", "event_type": "audit_log", "activity_anomaly": True},
        ])
        events.extend([
            {"user": "app-1", "event_type": "application_log", "severity": "error"}
            for _ in range(10)
        ])

        result = analyze_cyber_events(events)

        evidence_names = {item["name"] for item in result["evidence"]}
        self.assertTrue({
            "POTENTIAL_INSIDER_MISUSE",
            "ABNORMAL_USER_ACTIVITY",
            "UNUSUAL_SYSTEM_LOG_ACTIVITY",
        }.issubset(evidence_names))

    def test_missing_user_does_not_break_privilege_escalation_detection(self):
        result = analyze_cyber_events([
            {"action": "privilege_escalation"},
        ])

        evidence_names = {item["name"] for item in result["evidence"]}
        self.assertIn("POTENTIAL_INSIDER_MISUSE", evidence_names)

    def test_api_abuse_threshold_scales_with_analysis_window(self):
        events = [
            {"event_type": "api_request", "user": "api-client", "request_count": 100}
        ]

        short_window = analyze_cyber_events(events, window_minutes=1)
        long_window = analyze_cyber_events(events, window_minutes=60)

        self.assertIn("API_ABUSE", {item["name"] for item in short_window["evidence"]})
        self.assertNotIn("API_ABUSE", {item["name"] for item in long_window["evidence"]})

    def test_ordinary_events_do_not_trigger_findings(self):
        result = analyze_cyber_events([
            {
                "user": "reader",
                "event_type": "api_request",
                "status_code": 200,
                "request_count": 1,
                "direction": "inbound",
                "bytes_out": 512,
            }
        ])

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["evidence"], [])


if __name__ == "__main__":
    unittest.main()
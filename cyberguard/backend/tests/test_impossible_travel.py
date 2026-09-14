import unittest
from cyberguard.backend.services.account_service import _haversine_km, _parse_log, _score_entries


class TestHaversineDistance(unittest.TestCase):
    def test_nyc_to_london_approx(self):
        dist = _haversine_km(40.7128, -74.0060, 51.5074, -0.1278)
        self.assertGreater(dist, 5000)
        self.assertLess(dist, 6500)

    def test_same_location_is_zero(self):
        dist = _haversine_km(40.7128, -74.0060, 40.7128, -74.0060)
        self.assertAlmostEqual(dist, 0.0, places=3)


class TestImpossibleTravelDetection(unittest.TestCase):
    def test_impossible_travel_detected(self):
        log = "2026-01-01T00:00:00 alice 1.1.1.1 nyc success\n2026-01-01T01:00:00 alice 3.3.3.3 tokyo success"
        entries = _parse_log(log)
        contributions = _score_entries(entries)
        self.assertIn("IMPOSSIBLE_TRAVEL_alice", contributions)
        self.assertEqual(contributions["IMPOSSIBLE_TRAVEL_alice"], 50)

    def test_nearby_login_no_impossible_travel(self):
        log = "2026-01-01T00:00:00 bob 1.1.1.1 nyc success\n2026-01-01T01:00:00 bob 1.1.1.1 nyc success"
        entries = _parse_log(log)
        contributions = _score_entries(entries)
        self.assertNotIn("IMPOSSIBLE_TRAVEL_bob", contributions)

    def test_no_geo_data_skipped(self):
        log = "2026-01-01T00:00:00 carol 10.10.10.10 success\n2026-01-01T01:00:00 carol 10.10.10.11 success"
        entries = _parse_log(log)
        contributions = _score_entries(entries)
        impossible_keys = [k for k in contributions if k.startswith("IMPOSSIBLE_TRAVEL")]
        self.assertEqual(impossible_keys, [])

    def test_single_login_no_travel_detection(self):
        log = "2026-01-01T00:00:00 dave 1.1.1.1 nyc success"
        entries = _parse_log(log)
        contributions = _score_entries(entries)
        impossible_keys = [k for k in contributions if k.startswith("IMPOSSIBLE_TRAVEL")]
        self.assertEqual(impossible_keys, [])


if __name__ == "__main__":
    unittest.main()

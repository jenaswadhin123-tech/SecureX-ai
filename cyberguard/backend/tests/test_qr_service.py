import unittest
from unittest.mock import MagicMock, patch

from cyberguard.backend.services.qr_service import (
    _qr_specific_contributions,
    analyze_qr_image,
    decode_qr_url,
)


class TestQRService(unittest.TestCase):

    @patch("cyberguard.backend.services.qr_service.cv2.QRCodeDetector")
    @patch("cyberguard.backend.services.qr_service.cv2.imdecode")
    def test_decodes_qr_url(self, mock_imdecode, mock_detector):
        mock_imdecode.return_value = object()
        detector = mock_detector.return_value
        detector.detectAndDecode.return_value = ("https://example.com/login", None, None)
        self.assertEqual(decode_qr_url(b"image-bytes"), "https://example.com/login")

    @patch("cyberguard.backend.services.qr_service.cv2.QRCodeDetector")
    @patch("cyberguard.backend.services.qr_service.cv2.imdecode")
    def test_rejects_non_url_qr_payload(self, mock_imdecode, mock_detector):
        mock_imdecode.return_value = object()
        mock_detector.return_value.detectAndDecode.return_value = ("not a URL", None, None)
        with self.assertRaisesRegex(ValueError, "complete URL"):
            decode_qr_url(b"image-bytes")

    def test_detects_qr_redirect_signals(self):
        contributions = _qr_specific_contributions(
            "https://bit.ly/abc?target=https%3A%2F%2Fexample.com"
        )
        self.assertIn("QR_SHORTENER_REDIRECT", contributions)
        self.assertIn("QR_ENCODED_REDIRECT", contributions)

    @patch("cyberguard.backend.services.qr_service.analyze_url")
    @patch("cyberguard.backend.services.qr_service.decode_qr_url", return_value="https://bit.ly/abc")
    def test_returns_qr_threat_event(self, _mock_decode, mock_analyze_url):
        mock_analyze_url.return_value = {
            "risk_score": 40,
            "risk_level": "LOW",
            "evidence": [],
            "recommendations": [],
        }
        result = analyze_qr_image(b"image-bytes", "poster.png")
        self.assertEqual(result["threat_category"], "QR_PHISHING")
        self.assertEqual(result["source"], "qr_service")
        self.assertIn("QR_DECODED_URL", {item["name"] for item in result["evidence"]})
        self.assertIn("QR_SHORTENER_REDIRECT", {item["name"] for item in result["evidence"]})


if __name__ == "__main__":
    unittest.main()

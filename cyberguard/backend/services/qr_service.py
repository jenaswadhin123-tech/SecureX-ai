"""QR-code phishing analysis service."""

from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import parse_qs, urlparse

import numpy as np

try:
    import cv2
except ImportError:  # pragma: no cover - exercised only before dependency install
    cv2 = None

from ..models import EvidenceItem, ThreatEvent
from .url_service import _validate_url, analyze_url

MAX_QR_IMAGE_BYTES = 10 * 1024 * 1024
SHORTENER_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
}


def decode_qr_url(image_bytes: bytes) -> str:
    """Decode one QR code from an uploaded image and return its URL."""
    if cv2 is None:
        raise RuntimeError("QR scanning requires opencv-python-headless. Install the project requirements first.")
    if not image_bytes or len(image_bytes) > MAX_QR_IMAGE_BYTES:
        raise ValueError("Upload a QR image smaller than 10 MB.")

    image = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("The uploaded file is not a readable image.")

    detector = cv2.QRCodeDetector()
    candidates = [image]
    try:
        height, width = image.shape[:2]
        scale = 3 if min(height, width) < 900 else 2
        enlarged = cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
        gray = cv2.cvtColor(enlarged, cv2.COLOR_BGR2GRAY)
        contrast = cv2.equalizeHist(gray)
        thresholded = cv2.adaptiveThreshold(
            contrast, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
        )
        sharpened = cv2.addWeighted(contrast, 1.6, cv2.GaussianBlur(contrast, (0, 0), 2), -0.6, 0)
        candidates.extend([enlarged, gray, contrast, thresholded, sharpened])
    except (AttributeError, cv2.error, ValueError):
        pass

    for candidate in candidates:
        decoded_value, _, _ = detector.detectAndDecode(candidate)
        if decoded_value and decoded_value.strip():
            return _validate_url(decoded_value.strip())

        try:
            found, decoded_values, _, _ = detector.detectAndDecodeMulti(candidate)
        except (cv2.error, ValueError):
            found, decoded_values = False, []
        if found:
            for decoded_value in decoded_values:
                if decoded_value and decoded_value.strip():
                    return _validate_url(decoded_value.strip())

    raise ValueError("No readable QR code was found in the image. Move closer, reduce glare, and keep the QR code centered.")


def _qr_specific_contributions(url: str) -> Dict[str, int]:
    """Identify QR-specific redirect and impersonation signals."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    contributions: Dict[str, int] = {}

    if hostname in SHORTENER_HOSTS:
        contributions["QR_SHORTENER_REDIRECT"] = 15

    query = parse_qs(parsed.query)
    redirect_keys = {"url", "u", "target", "redirect", "redirect_url", "next", "dest", "destination"}
    if redirect_keys.intersection(query):
        contributions["QR_ENCODED_REDIRECT"] = 15

    if "@" in parsed.netloc:
        contributions["QR_DECEPTIVE_USERINFO_URL"] = 20

    brand_names = ("paypal", "microsoft", "google", "apple", "amazon", "bank")
    if any(re.search(rf"(?:^|[-.]){brand}(?:[-.]|$)", hostname) for brand in brand_names):
        contributions["QR_BRAND_IMPERSONATION_DOMAIN"] = 20

    return contributions


def analyze_qr_image(image_bytes: bytes, filename: str = "qr-image") -> Dict:
    """Decode and reputation-check a QR image as a unified threat event."""
    decoded_url = decode_qr_url(image_bytes)
    url_result = analyze_url(decoded_url)
    qr_contributions = _qr_specific_contributions(decoded_url)
    evidence: List[EvidenceItem] = [
        EvidenceItem(name="QR_DECODED_URL", value=decoded_url),
        *[EvidenceItem(name=item["name"], value=item["value"]) for item in url_result.get("evidence", [])],
        *[EvidenceItem(name=name, value=value) for name, value in qr_contributions.items()],
    ]

    raw_score = min(100, url_result.get("risk_score", 0) + sum(qr_contributions.values()))
    risk_level = "CRITICAL" if raw_score >= 90 else "HIGH" if raw_score >= 70 else "MEDIUM" if raw_score >= 50 else "LOW" if raw_score >= 30 else "SAFE"
    recommendations = [
        "Do not scan or open the QR destination on an untrusted device",
        "Verify the destination domain through an independent channel",
        "Treat shortened or redirected QR links as high-risk until expanded and verified",
        *url_result.get("recommendations", []),
    ]
    threat = ThreatEvent(
        threat_category="QR_PHISHING",
        risk_score=raw_score,
        risk_level=risk_level,
        evidence=evidence,
        recommendations=list(dict.fromkeys(recommendations)),
        explanation=f"QR code decoded from {filename} to {decoded_url} and was checked for URL and QR-specific phishing signals.",
        source="qr_service",
    )
    return threat.model_dump()

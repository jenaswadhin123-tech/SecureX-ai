# backend/services/url_service.py
"""Simple URL reputation analysis service.

For the prototype we use a tiny hard‑coded block‑list of malicious domains.
The service returns a unified ``ThreatEvent`` using the shared risk engine.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse
from typing import Dict, List
import os
import requests

# Shared utilities
from ..risk_engine import compute_overall_risk
from ..models import ThreatEvent, EvidenceItem

# Very small example block‑list – replace with an external API later.
MALICIOUS_DOMAINS = {
    "phishingsite.com": 30,
    "malicious.example": 25,
    "bad-domain.net": 20,
}

MAX_WEBSITE_BYTES = 1_000_000
WEBSITE_TIMEOUT_SECONDS = 5


def _validate_url(url: str) -> str:
    """Normalize and validate a URL before any reputation or website checks."""
    normalized_url = url.strip()
    parsed = urlparse(normalized_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a complete URL beginning with http:// or https://.")
    return normalized_url


def _is_public_hostname(hostname: str) -> bool:
    """Return whether a hostname resolves only to public addresses."""
    if not hostname:
        return False
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except socket.gaierror:
        return False

    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_global:
                return False
        except ValueError:
            return False
    return True


def _read_website_body(response: requests.Response) -> str:
    """Read a bounded response body so large pages cannot exhaust memory."""
    chunks = []
    total_bytes = 0
    for chunk in response.iter_content(chunk_size=16_384):
        if not chunk:
            continue
        remaining = MAX_WEBSITE_BYTES - total_bytes
        chunks.append(chunk[:remaining])
        total_bytes += min(len(chunk), remaining)
        if total_bytes >= MAX_WEBSITE_BYTES:
            break
    raw_body = b"".join(chunks)
    encoding = response.encoding or "utf-8"
    return raw_body.decode(encoding, errors="replace")


def _inspect_website(url: str) -> Dict[str, int]:
    """Inspect a public HTML page for common deceptive-site signals."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not _is_public_hostname(hostname):
        return {}

    contributions: Dict[str, int] = {}
    try:
        response = requests.get(
            url,
            headers={"User-Agent": "CyberGuard Website Inspector/1.0"},
            timeout=WEBSITE_TIMEOUT_SECONDS,
            stream=True,
            allow_redirects=False,
        )
        if response.status_code >= 400:
            contributions["WEBSITE_HTTP_ERROR"] = 5

        location = response.headers.get("Location", "")
        if isinstance(location, str) and location:
            redirect_host = (urlparse(location).hostname or "").lower()
            if redirect_host and redirect_host != hostname:
                contributions["WEBSITE_EXTERNAL_REDIRECT"] = 10

        content_type = response.headers.get("Content-Type", "").lower()
        if not isinstance(content_type, str):
            return contributions
        if "html" not in content_type:
            return contributions

        body = _read_website_body(response)
        normalized_body = re.sub(r"\s+", " ", body).lower()
        has_password_form = bool(
            re.search(r"<input[^>]+type=[\"']?password", normalized_body)
        )
        has_credential_language = bool(
            re.search(r"password|one[- ]time password|otp|verify your account|sign in", normalized_body)
        )
        has_urgency_language = bool(
            re.search(r"urgent|immediately|account.{0,30}(suspend|close|lock)|act now", normalized_body)
        )

        if has_password_form:
            contributions["WEBSITE_PASSWORD_FORM"] = 15
        if has_credential_language:
            contributions["WEBSITE_CREDENTIAL_LANGUAGE"] = 10
        if has_urgency_language:
            contributions["WEBSITE_URGENCY_LANGUAGE"] = 10

        brand_names = ("paypal", "microsoft", "google", "apple", "amazon", "bank")
        title_match = re.search(r"<title[^>]*>(.*?)</title>", normalized_body, re.DOTALL)
        title = title_match.group(1) if title_match else ""
        claimed_brand = next((brand for brand in brand_names if brand in title), None)
        if claimed_brand and claimed_brand not in hostname:
            contributions["WEBSITE_BRAND_DOMAIN_MISMATCH"] = 20
    except (requests.RequestException, OSError, UnicodeError, ValueError):
        return contributions
    return contributions

# Google Safe Browsing helper
def _query_google_safe_browsing(url: str) -> int:
    """Query Google Safe Browsing for a single URL.

    Returns an integer threat score (0-100). Higher values indicate more malicious
    content. If the API key is missing or request fails, 0 is returned.
    """
    from .. import config
    api_key = config.SAFE_BROWSING_API_KEY
    if not api_key:
        return 0

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "cyberguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, params={"key": api_key}, json=payload, timeout=5)
        if resp.status_code != 200:
            return 0
        data = resp.json()
        if data.get("matches"):
            max_score = 0
            for match in data["matches"]:
                threat = match.get("threatType", "")
                if threat == "SOCIAL_ENGINEERING":
                    max_score = max(max_score, 90)
                elif threat == "MALWARE":
                    max_score = max(max_score, 80)
                else:
                    max_score = max(max_score, 70)
            return max_score
        return 0
    except Exception:
        return 0


def _score_url(url: str) -> Dict[str, int]:
    """Score a URL based on presence in the block‑list.
    Returns a dict mapping the domain (if malicious) to its weight.
    """
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    contributions: Dict[str, int] = {}
    if domain in MALICIOUS_DOMAINS:
        contributions[domain.upper()] = MALICIOUS_DOMAINS[domain]
    return contributions


def analyze_url(url: str) -> Dict:
    """Analyze a URL and return a ``ThreatEvent`` dict.
    Parameters
    ----------
    url: str
        The URL to evaluate.
    """
    url = _validate_url(url)
    contributions = _score_url(url)
    safe_score = _query_google_safe_browsing(url)
    if safe_score:
        contributions["GOOGLE_SAFE_BROWSING"] = safe_score

    from .virustotal_service import _query_virustotal_url
    vt_score = _query_virustotal_url(url)
    if vt_score:
        contributions["VIRUSTOTAL_SCAN"] = vt_score

    contributions.update(_inspect_website(url))

    overall_risk, risk_level = compute_overall_risk(contributions)

    evidence: List[EvidenceItem] = [
        EvidenceItem(name=domain, value=weight) for domain, weight in contributions.items()
    ]

    recommendations = [
        "Do not click the link until verified",
        "Run the URL through a sandbox or URL‑reputation service",
        "Alert the security team",
    ]

    threat = ThreatEvent(
        threat_category="MALICIOUS_URL",
        risk_score=overall_risk,
        risk_level=risk_level,
        evidence=evidence,
        recommendations=recommendations,
        explanation=None,
        source="url_service",
    )
    return threat.model_dump()

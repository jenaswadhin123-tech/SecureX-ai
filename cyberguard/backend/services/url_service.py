# backend/services/url_service.py
"""Simple URL reputation analysis service.

For the prototype we use a tiny hard‑coded block‑list of malicious domains.
The service returns a unified ``ThreatEvent`` using the shared risk engine.
"""

from __future__ import annotations

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
    contributions = _score_url(url)
    safe_score = _query_google_safe_browsing(url)
    if safe_score:
        contributions["GOOGLE_SAFE_BROWSING"] = safe_score

    from .virustotal_service import _query_virustotal_url
    vt_score = _query_virustotal_url(url)
    if vt_score:
        contributions["VIRUSTOTAL_SCAN"] = vt_score

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

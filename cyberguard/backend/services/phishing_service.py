# backend/services/phishing_service.py
"""Simple phishing text analysis service.

This prototype looks for common phishing cues in a text message (email or SMS).
It produces a unified ``ThreatEvent`` payload using the shared risk engine
and Pydantic models.
"""

from __future__ import annotations

from typing import Dict, List

# Shared utilities
from ..risk_engine import compute_overall_risk
from ..models import ThreatEvent, EvidenceItem

# ---------------------------------------------------------------------------
# Very small keyword‑based heuristics – replace with a proper ML model later.
# ---------------------------------------------------------------------------
PHISHING_KEYWORDS = {
    "urgent": 10,
    "immediately": 10,
    "account": 5,
    "password": 5,
    "login": 5,
    "verify": 5,
    "click": 5,
    "link": 5,
    "http": 5,
    "https": 5,
    "bank": 5,
    "paypal": 5,
    "transfer": 5,
    "money": 5,
    "gift": 5,
    "prize": 5,
    "winner": 5,
    "lottery": 5,
}


def _score_text(content: str) -> Dict[str, int]:
    """Score the text based on presence of phishing keywords.
    Returns a dict mapping each found keyword to its weight.
    """
    lowered = content.lower()
    contributions: Dict[str, int] = {}
    for kw, weight in PHISHING_KEYWORDS.items():
        if kw in lowered:
            contributions[kw.upper()] = weight
    return contributions


def analyze_phishing_text(content: str) -> Dict:
    """Analyze a text snippet and return a ``ThreatEvent`` dict.

    Parameters
    ----------
    content: str
        The raw email, SMS, or chat message to evaluate.
    """
    # Keyword contributions
    keyword_contrib = _score_text(content)

    # Check if text contains raw email headers
    from .email_header_service import parse_email_headers
    header_contrib, _ = parse_email_headers(content)
    keyword_contrib.update(header_contrib)

    # Overall risk – sum of weights (capped at 100) and map to level.
    overall_risk, risk_level = compute_overall_risk(keyword_contrib)

    # Evidence list – each keyword that contributed
    evidence: List[EvidenceItem] = [
        EvidenceItem(name=kw, value=val) for kw, val in keyword_contrib.items()
    ]

    # Simple static recommendations for phishing
    recommendations = [
        "Do not click any links in the message",
        "Verify the sender through an out‑of‑band channel",
        "Report the message to the security team",
    ]

    threat = ThreatEvent(
        threat_category="PHISHING",
        risk_score=overall_risk,
        risk_level=risk_level,
        evidence=evidence,
        recommendations=recommendations,
        explanation=None,
        # No voice‑specific fields – they remain omitted (None)
        source="phishing_service",
    )

    return threat.model_dump()

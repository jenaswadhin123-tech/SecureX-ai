# backend/services/phishing_service.py
"""Simple phishing text analysis service.

This prototype looks for common phishing cues in a text message (email or SMS).
It produces a unified ``ThreatEvent`` payload using the shared risk engine
and Pydantic models.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import re

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


def _score_communication_pattern(
    content: str, context: Optional[Dict[str, Any]] = None
) -> Dict[str, int]:
    """Score message-shape and supplied baseline deviations."""
    context = context or {}
    contributions: Dict[str, int] = {}
    letters = [char for char in content if char.isalpha()]
    if len(letters) >= 20 and sum(char.isupper() for char in letters) / len(letters) >= 0.65:
        contributions["UNUSUAL_ALL_CAPS_PATTERN"] = 8
    if len(content) >= 80 and sum(not char.isalnum() and not char.isspace() for char in content) / len(content) >= 0.18:
        contributions["UNUSUAL_PUNCTUATION_PATTERN"] = 6
    if len(re.findall(r"https?://|www\.", content, re.IGNORECASE)) >= 3:
        contributions["UNUSUAL_LINK_FREQUENCY"] = 8
    if re.search(r"([!?])\1{2,}|(.)\2{4,}", content):
        contributions["REPEATED_CHARACTER_PATTERN"] = 5

    sender_domain = str(context.get("sender_domain", "")).lower().strip()
    expected_domain = str(context.get("expected_sender_domain", "")).lower().strip()
    if sender_domain and expected_domain and sender_domain != expected_domain:
        contributions["SENDER_DOMAIN_DEVIATION"] = 20

    reply_to = str(context.get("reply_to_email", "")).lower().strip()
    reply_to_domain = reply_to.rsplit("@", 1)[-1] if "@" in reply_to else ""
    if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        contributions["REPLY_TO_DOMAIN_DEVIATION"] = 15

    sent_hour = context.get("sent_hour")
    usual_hours = context.get("usual_hours", [])
    if sent_hour is not None and usual_hours:
        try:
            if int(sent_hour) not in {int(hour) for hour in usual_hours}:
                contributions["UNUSUAL_SEND_TIME"] = 8
        except (TypeError, ValueError):
            pass

    recent_count = context.get("recent_message_count")
    typical_count = context.get("typical_message_count")
    try:
        if recent_count is not None and typical_count and int(recent_count) > max(5, int(typical_count) * 3):
            contributions["UNUSUAL_MESSAGE_FREQUENCY"] = 10
    except (TypeError, ValueError):
        pass

    if context.get("new_sender") is True:
        contributions["NEW_SENDER_PATTERN"] = 8
    return contributions


def analyze_phishing_text(
    content: str, communication_context: Optional[Dict[str, Any]] = None
) -> Dict:
    """Analyze a text snippet and return a ``ThreatEvent`` dict.

    Parameters
    ----------
    content: str
        The raw email, SMS, or chat message to evaluate.
    """
    # Keyword contributions
    keyword_contrib = _score_text(content)
    keyword_contrib.update(_score_communication_pattern(content, communication_context))

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

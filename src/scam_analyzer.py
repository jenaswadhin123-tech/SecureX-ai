"""Rule-based scam intent analysis for voice transcripts."""

from dataclasses import dataclass
import re
from typing import Dict, List


@dataclass(frozen=True)
class ScamIndicator:
    key: str
    label: str
    risk: int
    patterns: tuple[str, ...]


INDICATORS = (
    ScamIndicator(
        "money_request",
        "Money request",
        25,
        (r"send\s+(?:me\s+)?money", r"transfer\s+(?:the\s+)?money", r"(?:₹|rs\.?|rupees?)", r"upi", r"payment", r"bank account"),
    ),
    ScamIndicator(
        "otp_request",
        "OTP or verification code request",
        30,
        (r"\botp\b", r"verification code", r"6[- ]?digit code", r"authentication code"),
    ),
    ScamIndicator(
        "banking_credentials",
        "Banking information request",
        30,
        (r"account number", r"\bpin\b", r"\bcvv\b", r"card number", r"net banking", r"password", r"kyc", r"pan", r"aadhaar"),
    ),
    ScamIndicator(
        "urgency",
        "Urgent request",
        15,
        (r"urgent", r"immediately", r"right now", r"don't tell anyone", r"quickly"),
    ),
    ScamIndicator(
        "impersonation",
        "Possible impersonation",
        20,
        (r"i(?:[' ]m| am) your brother", r"i(?:[' ]m| am) your father", r"i(?:[' ]m| am) from the bank", r"i(?:[' ]m| am) from police", r"government officer"),
    ),
    ScamIndicator(
        "threatening_language",
        "Threatening language",
        20,
        (r"you will be arrested", r"legal action", r"account will be blocked", r"police case", r"consequences"),
    ),
    ScamIndicator(
        "emergency_claim",
        "Emergency claim",
        15,
        (r"emergency", r"accident", r"hospital", r"i(?:[' ]m| am) in trouble", r"need help immediately", r"lost my phone"),
    ),
)


def analyze_scam_intent(transcript: str) -> Dict[str, object]:
    """Return matched indicators, a capped score, and a risk level."""
    normalized = " ".join(transcript.lower().split())
    detected: List[Dict[str, object]] = []

    for indicator in INDICATORS:
        if any(re.search(pattern, normalized) for pattern in indicator.patterns):
            detected.append(
                {"key": indicator.key, "label": indicator.label, "risk": indicator.risk}
            )

    score = min(100, sum(int(item["risk"]) for item in detected))
    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "indicators": detected,
        "transcript": transcript.strip(),
    }


def determine_overall_risk(
    scam_analysis: Dict[str, object], voice_label: str, ai_probability: float
) -> str:
    """Combine the two assessments without adding unrelated probabilities."""
    scam_level = str(scam_analysis["level"])
    if scam_level == "HIGH":
        return "HIGH"
    if scam_level == "MEDIUM" or (voice_label == "AI" and ai_probability >= 0.75):
        return "ELEVATED"
    return "LOW"
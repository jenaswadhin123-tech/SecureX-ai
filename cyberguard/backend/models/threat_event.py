# backend/models/threat_event.py
"""Pydantic models representing the unified threat event schema.

The schema consolidates output from any detector (voice, phishing, URL, …)
into a single JSON structure that the frontend can consume.
"""

from __future__ import annotations

from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    name: str = Field(..., description="Human‑readable name of the evidence component")
    value: Any = Field(..., description="Numeric or textual value representing the evidence")


class ThreatEvent(BaseModel):
    """Unified threat event payload returned by every analyzer endpoint.

    Fields are deliberately generic so new detectors can be added without
    breaking the contract.
    """

    # Core classification
    threat_category: str = Field(..., description="High‑level category, e.g. VOICE_IMPERSONATION")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score 0‑100")
    risk_level: str = Field(..., description="One of SAFE, LOW, MEDIUM, HIGH, CRITICAL")

    # Detector‑specific results – kept optional because not every detector
    # provides all of them.
    voice_verdict: Optional[str] = None
    voice_confidence: Optional[int] = None
    scam_score: Optional[int] = None
    acoustic_features: Optional[Dict[str, Any]] = None
    transcript: Optional[str] = None

    # Generic collections
    evidence: List[EvidenceItem] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    explanation: Optional[str] = None

    # Timestamp/metadata (optional for now)
    timestamp: Optional[str] = None
    source: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "threat_category": "VOICE_IMPERSONATION",
                "risk_score": 91,
                "risk_level": "CRITICAL",
                "voice_verdict": "AI_GENERATED",
                "voice_confidence": 94,
                "scam_score": 82,
                "acoustic_features": {"spectral_centroid": 2200},
                "transcript": "Please transfer $5000 immediately",
                "evidence": [
                    {"name": "AI probability", "value": 94},
                    {"name": "Scam intent score", "value": 82},
                ],
                "recommendations": [
                    "Flag the communication for manual review",
                    "Warn the intended recipient",
                ],
                "explanation": "The audio exhibits high AI-voice probability...",
            }
        }
    }

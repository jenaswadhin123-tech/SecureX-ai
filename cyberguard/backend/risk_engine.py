# backend/risk_engine.py
"""Simple risk scoring engine used by all detectors.

The engine receives a dictionary of *contributions* – numeric values 0‑100 –
and returns a tuple ``(risk_score, risk_level)`` where ``risk_score`` is a
integer 0‑100 and ``risk_level`` is one of ``SAFE, LOW, MEDIUM, HIGH,
CRITICAL``.

The logic mirrors the prototype used in the voice service and can be
re‑used by future detectors.
"""

from __future__ import annotations

from typing import Dict, Tuple


def _score_to_level(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 30:
        return "LOW"
    return "SAFE"


def compute_overall_risk(contributions: Dict[str, int]) -> Tuple[int, str]:
    """Aggregate contribution scores into a final risk score & level.

    Parameters
    ----------
    contributions: dict
        Mapping from contribution name to an integer 0‑100 weight.

    Returns
    -------
    (risk_score, risk_level): tuple[int, str]
        ``risk_score`` is capped at 100.
        ``risk_level`` is derived from the score via thresholds.
    """
    # Simple weighted sum – each contribution already expressed as a 0‑100
    # contribution. In a real system we would apply configurable weights.
    raw_score = sum(contributions.values())
    risk_score = min(100, raw_score)
    risk_level = _score_to_level(risk_score)
    return risk_score, risk_level

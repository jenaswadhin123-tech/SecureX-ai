# backend/services/explanation_service.py
"""Explanation service – generates human‑readable explanations for a ThreatEvent.

This implementation uses the Gemini Interaction API (google‑generativeai
SDK). If the ``GEMINI_API_KEY`` environment variable is not set, it falls
back to a simple templated explanation.
"""

from __future__ import annotations

import os
import json
from typing import Dict, Any

# Pydantic model is only needed for type hints – we work with dicts.
from ..models import ThreatEvent

# Attempt to import the Gemini SDK. If unavailable, we will use the fallback.
try:
    import google.generativeai as genai  # type: ignore
except Exception:  # pragma: no cover – SDK not installed in the environment
    genai = None  # type: ignore


def _configure_gemini() -> bool:
    """Configure the Gemini client if an API key is available.

    Returns
    -------
    bool
        ``True`` if the client is ready for use, ``False`` otherwise.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or genai is None:
        return False
    try:
        genai.configure(api_key=api_key)
        # Test the configuration by creating a lightweight model instance.
        _ = genai.GenerativeModel("gemini-1.5-flash")
        return True
    except Exception:
        return False


_GEMINI_READY = _configure_gemini()


def _call_gemini(event: Dict[str, Any]) -> str:
    """Call the Gemini model to produce an explanation.

    Parameters
    ----------
    event: dict
        The ``ThreatEvent`` payload.

    Returns
    -------
    str
        The generated explanation text.
    """
    if not _GEMINI_READY:
        raise RuntimeError("Gemini client not configured")
    model = genai.GenerativeModel("gemini-1.5-flash")
    # Build a concise prompt – we pass the JSON as a code block for clarity.
    prompt = (
        "Explain the following cyber‑security threat event in plain language, "
        "including why it is risky and what actions should be taken.\n\n"
        f"```json\n{json.dumps(event, indent=2)}\n```"
    )
    response = model.generate_content(prompt)
    # ``response.text`` holds the generated string.
    return response.text.strip()


def generate_explanation(event: Dict[str, Any]) -> str:
    """Return a human‑readable explanation for the given threat event.

    If the Gemini API is configured, we delegate to it; otherwise we fall
    back to a simple templated message.
    """
    # First try the Gemini LLM.
    if _GEMINI_READY:
        try:
            return _call_gemini(event)
        except Exception:  # pragma: no cover – unexpected API error
            # In a production system we would log the error; here we just fall back.
            pass

    # Simple fallback – this ensures the endpoint works even without a key.
    category = event.get("threat_category", "UNKNOWN")
    risk = event.get("risk_score", 0)
    level = event.get("risk_level", "SAFE")
    evidence_names = ", ".join(e.get("name", "") for e in event.get("evidence", []))
    return (
        f"The system detected a **{category}** threat with a risk score of {risk} "
        f"({level}). The main evidence items are: {evidence_names}."
    )

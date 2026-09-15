# backend/services/voice_service.py
"""Voice Service – thin wrapper around the existing voice‑detection engine.

This module imports the original voice‑engine code (which lives under
`src/` in the repository) and exposes a single function
`analyze_voice_file` that receives a FastAPI ``UploadFile`` and returns a
``ThreatEvent`` instance (a Pydantic model defined in ``backend.models``).
"""

from pathlib import Path
from typing import Any, Dict

import joblib
from fastapi import UploadFile

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]  # cyberguard

# Search multiple potential locations for model.joblib
CANDIDATE_MODEL_PATHS = [
    PROJECT_ROOT / "model.joblib",
    PROJECT_ROOT.parent / "model.joblib",
    PROJECT_ROOT / "src" / "model.joblib",
    PROJECT_ROOT.parent / "src" / "model.joblib",
]

# Make the original ``src`` package importable
import sys
EXISTING_SRC = PROJECT_ROOT.parent / "src" if (PROJECT_ROOT.parent / "src").exists() else PROJECT_ROOT / "src"
if str(EXISTING_SRC) not in sys.path:
    sys.path.append(str(EXISTING_SRC))

# Import the canonical project modules. Using the package-qualified path avoids
# accidentally loading the legacy cyberguard/src placeholder implementation.
from src.inference import analyze_audio
from src.scam_analyzer import analyze_scam_intent
from src.transcription import transcribe_audio

# CYBERGUARD shared utilities
from ..risk_engine import compute_overall_risk
from ..models import ThreatEvent, EvidenceItem

# ---------------------------------------------------------------------------
# Lazy‑load the RandomForest model (singleton)
# ---------------------------------------------------------------------------
_MODEL = None

def _load_model() -> Any:
    """Load the trained model from ``model.joblib`` on first use.
    Searches multiple candidate paths to find the file.
    """
    global _MODEL
    if _MODEL is None:
        model_file = None
        for path in CANDIDATE_MODEL_PATHS:
            if path.exists():
                model_file = path
                break
        if model_file is None:
            searched_paths = "\n".join(str(p) for p in CANDIDATE_MODEL_PATHS)
            raise FileNotFoundError(
                f"Model file 'model.joblib' not found. Searched paths:\n{searched_paths}"
            )
        _MODEL = joblib.load(model_file)
    return _MODEL

# ---------------------------------------------------------------------------
# Helper to store the uploaded file temporarily
# ---------------------------------------------------------------------------
def _store_upload(upload: UploadFile) -> Path:
    """Write the uploaded audio to ``scratch/`` and return the file path.
    The ``scratch`` directory is created on demand and is ignored by version
    control, making it safe for temporary files.
    """
    scratch_dir = PROJECT_ROOT / "scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)
    temp_path = scratch_dir / f"tmp_{upload.filename}"
    with temp_path.open("wb") as out_fp:
        out_fp.write(upload.file.read())
    return temp_path

# ---------------------------------------------------------------------------
# Public API used by the FastAPI router
# ---------------------------------------------------------------------------
def analyze_voice_file(
    upload: UploadFile,
    model_name: str = "base",
    language: str = "auto",
) -> Dict[str, Any]:
    """Run the voice‑analysis pipeline and return a ``ThreatEvent`` dict.
    The returned dictionary can be directly serialised by FastAPI.
    """
    # 1️⃣ Load model (singleton)
    model = _load_model()

    # 2️⃣ Persist uploaded file for the legacy engine
    audio_path = _store_upload(upload)

    # 3️⃣ Acoustic analysis – label, confidence, acoustic summary, class probs
    label, confidence, acoustic_summary, class_probs = analyze_audio(model, audio_path)

    # 4️⃣ Whisper transcription. The acoustic classifier remains useful when
    # the hosted environment cannot download or load the optional Whisper model.
    transcription_error = None
    try:
        transcript = transcribe_audio(audio_path, model_name=model_name, language=language)
    except RuntimeError as exc:
        transcript = ""
        transcription_error = str(exc)

    # 5️⃣ Scam intent analysis (operates on transcript text)
    scam_result = analyze_scam_intent(transcript)

    # 6️⃣ Normalise engine outputs
    voice_verdict = "AI_GENERATED" if label.upper() == "AI" else "HUMAN"
    voice_confidence = int(round(confidence * 100))
    scam_score = int(scam_result.get("score", 0))

    # -------------------------------------------------------------------
    # Risk calculation – now delegated to the shared risk engine
    # -------------------------------------------------------------------
    contributions = {
        "VOICE_AI_PROBABILITY": int(round(class_probs.get("AI", 0) * 100)),
        "SCAM_INTENT": scam_score,
    }
    # Small urgency bonus based on transcript keywords
    urgency_bonus = 5 if any(word in transcript.lower() for word in ["urgent", "immediately", "asap", "now"]) else 0
    contributions["URGENCY"] = urgency_bonus

    overall_risk, risk_level = compute_overall_risk(contributions)

    # -------------------------------------------------------------------
    # Build evidence list using the shared ``EvidenceItem`` model
    # -------------------------------------------------------------------
    evidence = [
        EvidenceItem(name="AI probability", value=contributions["VOICE_AI_PROBABILITY"]),
        EvidenceItem(name="Scam intent score", value=scam_score),
        EvidenceItem(name="Urgency keyword bonus", value=urgency_bonus),
    ]

    # -------------------------------------------------------------------
    # Static recommendations for the prototype
    # -------------------------------------------------------------------
    recommendations = [
        "Flag the communication for manual review",
        "Warn the intended recipient about possible impersonation",
        "Log the event in the incident tracker",
        "Consider requiring multi‑factor authentication for any requested action",
    ]

    # -------------------------------------------------------------------
    # Assemble the unified ThreatEvent model
    # -------------------------------------------------------------------
    threat = ThreatEvent(
        threat_category="VOICE_IMPERSONATION",
        risk_score=overall_risk,
        risk_level=risk_level,
        voice_verdict=voice_verdict,
        voice_confidence=voice_confidence,
        scam_score=scam_score,
        acoustic_features=acoustic_summary,
        transcript=transcript,
        evidence=evidence,
        recommendations=recommendations,
        explanation=None,
        source=(f"voice_service; transcription unavailable: {transcription_error}" if transcription_error else "voice_service"),
    )

    # FastAPI will automatically convert the Pydantic model to a dict.
    return threat.model_dump()

"""Inference module for AI vs. Human voice classification.

Extracts features from an audio file and generates predictions with confidence scores.
"""

from pathlib import Path
from typing import Any, Dict, Tuple, Union
import numpy as np

from src.feature_extraction import extract_features, extract_features_with_summary


def predict_with_confidence(
    model: Any, audio_path: Union[str, Path]
) -> Tuple[str, float]:
    """Predict whether an audio file is AI-generated or Human speech.

    Parameters
    ----------
    model : Any
        Trained scikit-learn model or pipeline with predict_proba.
    audio_path : Union[str, Path]
        Path to the target audio file.

    Returns
    -------
    Tuple[str, float]
        (label, confidence) where label is 'AI' or 'Human', and confidence is in [0.0, 1.0].
    """
    features = extract_features(audio_path)
    X = np.array([features])

    classes = list(model.classes_)
    probabilities = model.predict_proba(X)[0]

    # Find probability corresponding to class 1 (AI)
    if 1 in classes:
        ai_idx = classes.index(1)
        prob_ai = float(probabilities[ai_idx])
    else:
        prob_ai = float(probabilities[1]) if len(probabilities) > 1 else 0.5

    prob_human = 1.0 - prob_ai

    if prob_ai >= 0.5:
        return "AI", prob_ai
    else:
        return "Human", prob_human


def analyze_audio(
    model: Any, audio_path: Union[str, Path]
) -> Tuple[str, float, Dict[str, float], Dict[str, float]]:
    """Detailed audio analysis returning label, confidence, summary metrics, and probabilities.

    Parameters
    ----------
    model : Any
        Trained scikit-learn model or pipeline with predict_proba.
    audio_path : Union[str, Path]
        Path to the target audio file.

    Returns
    -------
    Tuple[str, float, Dict[str, float], Dict[str, float]]
        (label, confidence, metrics_summary, class_probabilities)
    """
    features, summary = extract_features_with_summary(audio_path)
    X = np.array([features])

    classes = list(model.classes_)
    probabilities = model.predict_proba(X)[0]

    ai_idx = classes.index(1) if 1 in classes else 1
    prob_ai = float(probabilities[ai_idx])
    prob_human = float(1.0 - prob_ai)

    if prob_ai >= 0.5:
        label = "AI"
        confidence = prob_ai
    else:
        label = "Human"
        confidence = prob_human

    probs = {
        "AI": prob_ai,
        "Human": prob_human,
    }

    return label, confidence, summary, probs

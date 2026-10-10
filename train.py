"""Training script for AI vs. Human voice classification.

Scans data/sample_audio for audio files, extracts acoustic features,
trains a Random Forest classifier, and saves the serialized model pipeline.
"""

import os
import tempfile
from pathlib import Path

import joblib
import numpy as np

from src.feature_extraction import extract_features
from src.model import train_model

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data" / "sample_audio"
MODEL_PATH = PROJECT_ROOT / "model.joblib"
AUDIO_EXTENSIONS = {".wav", ".mp3", ".flac", ".ogg", ".m4a"}


def load_dataset():
    """Load audio files from data/sample_audio and extract feature vectors and labels.

    Filenames containing 'ai' (case-insensitive) are labeled 1 (AI-generated).
    All other filenames are labeled 0 (Human speech).

    Returns
    -------
    Tuple[list, np.ndarray, np.ndarray]
        (file_paths, feature_matrix, labels_array)
    """
    if not DATA_DIR.exists():
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        return [], np.empty((0, 0)), np.empty((0,))

    files = sorted(
        path for path in DATA_DIR.iterdir() if path.suffix.lower() in AUDIO_EXTENSIONS
    )
    if not files:
        return [], np.empty((0, 0)), np.empty((0,))

    labels = np.array([1 if "ai" in path.name.lower() else 0 for path in files], dtype=int)
    feature_list = []
    for i, path in enumerate(files, start=1):
        lbl = "AI" if labels[i - 1] == 1 else "Human"
        print(f"[{i}/{len(files)}] Extracting features from {path.name} ({lbl})...")
        feat = extract_features(path)
        feature_list.append(feat)

    features = np.array(feature_list, dtype=np.float32)
    return files, features, labels


def retrain_from_samples(model_path: Path = MODEL_PATH):
    """Train from the sample-audio dataset and atomically persist the model."""
    files, features, labels = load_dataset()
    if not files:
        raise ValueError(f"No audio samples found in {DATA_DIR}.")

    human_count = int(np.sum(labels == 0))
    ai_count = int(np.sum(labels == 1))
    if human_count == 0 or ai_count == 0:
        raise ValueError(
            "Dataset must contain both Human and AI audio clips. "
            "Filenames containing 'ai' are labeled AI; all others are labeled Human."
        )

    model, accuracy = train_model(features, labels)
    destination = Path(model_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
        delete=False,
    ) as temporary_file:
        temporary_path = Path(temporary_file.name)

    try:
        joblib.dump(model, temporary_path)
        os.replace(temporary_path, destination)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    return model, accuracy, human_count, ai_count


if __name__ == "__main__":
    print(f"=== Voice Authenticity Classifier Training ===")
    print(f"Looking for audio files in: {DATA_DIR}")

    print("Extracting features and training model pipeline...")
    try:
        _, accuracy, human_count, ai_count = retrain_from_samples()
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"Dataset breakdown: {human_count} Human clips, {ai_count} AI clips.")
    print(f"Model successfully saved to: {MODEL_PATH}")
    print(f"Validation accuracy: {accuracy:.1%}")

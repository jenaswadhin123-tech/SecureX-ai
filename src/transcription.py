"""Speech-to-text support using the OpenAI Whisper package."""

from pathlib import Path
from functools import lru_cache
from typing import Union
import hashlib
import re
import socket
from urllib.error import URLError

import librosa


def _cached_model_path(model_name: str) -> Path:
    return Path.home() / ".cache" / "whisper" / f"{model_name}.pt"


def _is_model_download_error(error: Exception) -> bool:
    message = str(error).lower()
    return any(
        marker in message
        for marker in ("getaddrinfo", "urlopen error", "11001", "download")
    )


def _cache_is_valid(model_name: str, whisper) -> bool:
    model_path = _cached_model_path(model_name)
    model_url = whisper._MODELS.get(model_name, "")
    expected_match = re.search(r"/models/([0-9a-f]{64})/", model_url)
    if not model_path.exists() or not expected_match:
        return False

    digest = hashlib.sha256()
    with model_path.open("rb") as model_file:
        for chunk in iter(lambda: model_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest() == expected_match.group(1)


@lru_cache(maxsize=4)
def _load_whisper_model(model_name: str):
    try:
        import whisper
    except ImportError as exc:
        raise RuntimeError(
            "Speech-to-text is unavailable. Install the 'openai-whisper' package."
        ) from exc

    cached_path = _cached_model_path(model_name)
    if cached_path.exists() and not _cache_is_valid(model_name, whisper):
        cached_path.unlink()

    try:
        return whisper.load_model(model_name)
    except Exception as exc:
        if not isinstance(exc, (OSError, URLError, socket.gaierror)) and not _is_model_download_error(exc):
            raise

        # Keep transcription usable offline when a larger model is not cached.
        # Whisper's default Windows cache is shared by all model selections.
        fallback_models = [
            name
            for name in ("base", "tiny")
            if name != model_name and _cache_is_valid(name, whisper)
        ]
        for fallback_name in fallback_models:
            try:
                return whisper.load_model(fallback_name)
            except Exception as fallback_error:
                if not isinstance(fallback_error, (OSError, URLError, socket.gaierror)) and not _is_model_download_error(fallback_error):
                    raise
                continue

        raise RuntimeError(
            f"Whisper model '{model_name}' is not downloaded and could not be "
            "downloaded. Check your internet/DNS connection, then retry."
        ) from exc


def transcribe_audio(
    audio_path: Union[str, Path],
    model_name: str = "base",
    language: str | None = None,
) -> str:
    """Transcribe an audio file with Whisper.

    Whisper is imported lazily because loading the application should not
    require the model or its large runtime until transcription is requested.
    """
    try:
        model = _load_whisper_model(model_name)
        # Pass decoded samples instead of a file path so hosted Streamlit
        # deployments do not require a system-level ffmpeg executable.
        audio, _ = librosa.load(str(audio_path), sr=16000, mono=True)
        if audio.size == 0:
            raise ValueError("Audio file is empty.")

        # Remove only surrounding silence and normalize quiet recordings. This
        # gives Whisper more speech in its context window without cutting words.
        trimmed_audio, _ = librosa.effects.trim(audio, top_db=35)
        if trimmed_audio.size > 0:
            audio = trimmed_audio
        peak = float(abs(audio).max())
        if peak > 0:
            audio = audio * min(0.95 / peak, 1.0)

        options = {
            "fp16": False,
            "temperature": (0.0, 0.2, 0.4),
            "condition_on_previous_text": False,
        }
        if language and language != "auto":
            options["language"] = language
        result = model.transcribe(audio, **options)
    except Exception as exc:
        raise RuntimeError(f"Speech-to-text failed: {exc}") from exc

    transcript = result.get("text", "") if isinstance(result, dict) else ""
    return " ".join(str(transcript).split())
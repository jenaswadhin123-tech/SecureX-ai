"""Bounded visual media pre-screening and video audio extraction helpers."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import cv2
import numpy as np
from PIL import ExifTags, Image, UnidentifiedImageError

from ..models import EvidenceItem, ThreatEvent

MAX_IMAGE_BYTES = 25 * 1024 * 1024
MAX_VIDEO_BYTES = 150 * 1024 * 1024
MAX_IMAGE_PIXELS = 50_000_000
MAX_VIDEO_SECONDS = 180
MAX_VIDEO_SAMPLED_FRAMES = 16
MAX_EXTRACTED_AUDIO_BYTES = 15 * 1024 * 1024
AI_PROVENANCE_MARKERS = (
    "stable diffusion",
    "midjourney",
    "dall-e",
    "dall·e",
    "adobe firefly",
    "runway",
    "openai sora",
    "google veo",
    "comfyui",
    "generative fill",
    "ai-generated",
    "ai generated",
)
VIDEO_EXTENSIONS = {".mp4", ".mov", ".mkv", ".avi", ".webm", ".m4v"}


def _find_ai_provenance(values: Iterable[Any]) -> str:
    metadata = " ".join(str(value).lower() for value in values)
    return next((marker for marker in AI_PROVENANCE_MARKERS if marker in metadata), "")


def _image_metadata_values(image: Image.Image) -> List[str]:
    values = [str(value) for value in image.info.values() if isinstance(value, (str, bytes))]
    try:
        exif = image.getexif()
        values.extend(
            str(value)
            for tag, value in exif.items()
            if ExifTags.TAGS.get(tag, "") in {"Software", "ImageDescription", "UserComment"}
        )
    except (AttributeError, OSError, ValueError):
        pass
    return values


def _jpeg_recompression_profile(image: Image.Image) -> Dict[str, float]:
    original = np.asarray(image.convert("RGB"), dtype=np.int16)
    buffer = io.BytesIO()
    image.convert("RGB").save(buffer, format="JPEG", quality=90)
    buffer.seek(0)
    recompressed = np.asarray(Image.open(buffer).convert("RGB"), dtype=np.int16)
    error = np.abs(original - recompressed).mean(axis=2)
    tile_errors = [
        float(error[y:y + 32, x:x + 32].mean())
        for y in range(0, error.shape[0], 32)
        for x in range(0, error.shape[1], 32)
    ]
    mean_error = float(error.mean())
    variation = float(np.std(tile_errors) / max(float(np.mean(tile_errors)), 0.001))
    return {"mean_recompression_error": round(mean_error, 3), "regional_variation": round(variation, 3)}


def _build_visual_event(
    media_kind: str,
    evidence: List[EvidenceItem],
    ai_marker: str,
    explanation: str,
) -> Dict[str, Any]:
    score = 55 if ai_marker else 0
    level = "MEDIUM" if score >= 50 else "SAFE"
    recommendations = [
        "Treat metadata and compression analysis as review signals, not proof of manipulation",
        "Verify the media against its original source and an independent capture when possible",
        "For recorded calls, assess the audio track separately and preserve the original file",
    ]
    return ThreatEvent(
        threat_category="DEEPFAKE_MEDIA_ASSESSMENT",
        risk_score=score,
        risk_level=level,
        evidence=evidence,
        recommendations=recommendations,
        explanation=explanation,
        source=f"media_forensics_service:{media_kind}",
    ).model_dump()


def analyze_image_bytes(image_bytes: bytes, filename: str = "uploaded-image") -> Dict[str, Any]:
    """Inspect image provenance metadata and JPEG recompression characteristics."""
    if not image_bytes or len(image_bytes) > MAX_IMAGE_BYTES:
        raise ValueError("Upload a non-empty image no larger than 25 MB.")

    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            width, height = image.size
            if width * height > MAX_IMAGE_PIXELS:
                raise ValueError("Image dimensions exceed the 50-megapixel inspection limit.")
            image.load()
            media_format = (image.format or Path(filename).suffix.lstrip(".")).upper()
            metadata_values = _image_metadata_values(image)
            evidence = [
                EvidenceItem(
                    name="IMAGE_FILE_PROFILE",
                    value={"format": media_format, "width": width, "height": height},
                )
            ]
            if media_format in {"JPEG", "JPG"}:
                evidence.append(EvidenceItem(
                    name="JPEG_RECOMPRESSION_PROFILE",
                    value=_jpeg_recompression_profile(image),
                ))
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        if isinstance(exc, ValueError) and "50-megapixel" in str(exc):
            raise
        raise ValueError("The uploaded file is not a supported, readable image.") from exc

    ai_marker = _find_ai_provenance(metadata_values)
    if ai_marker:
        evidence.append(EvidenceItem(name="AI_GENERATION_METADATA", value=ai_marker))

    return _build_visual_event(
        "image",
        evidence,
        ai_marker,
        f"Inspected {media_format} image metadata and available recompression signals. "
        "Metadata may be absent or edited, so this assessment cannot establish authenticity.",
    )


def _video_metadata_values(video_path: Path) -> List[str]:
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        return []
    try:
        result = subprocess.run(
            [
                ffprobe, "-v", "error", "-show_entries", "format_tags:stream_tags",
                "-of", "json", str(video_path),
            ],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if result.returncode != 0:
            return []
        metadata = json.loads(result.stdout or "{}")
        values = [str(value) for value in metadata.get("format", {}).get("tags", {}).values()]
        for stream in metadata.get("streams", []):
            values.extend(str(value) for value in stream.get("tags", {}).values())
        return values
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return []


def analyze_video_bytes(video_bytes: bytes, filename: str = "uploaded-video") -> Dict[str, Any]:
    """Sample video frames and inspect available container provenance metadata."""
    if not video_bytes or len(video_bytes) > MAX_VIDEO_BYTES:
        raise ValueError("Upload a non-empty video no larger than 150 MB.")

    extension = Path(filename).suffix.lower()
    if extension not in VIDEO_EXTENSIONS:
        extension = ".mp4"

    with tempfile.TemporaryDirectory(prefix="cyberguard-video-") as temp_dir:
        video_path = Path(temp_dir) / f"upload{extension}"
        video_path.write_bytes(video_bytes)
        metadata_values = _video_metadata_values(video_path)
        capture = cv2.VideoCapture(str(video_path))
        if not capture.isOpened():
            capture.release()
            raise ValueError("The uploaded video could not be decoded.")

        fps = float(capture.get(cv2.CAP_PROP_FPS) or 0)
        frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
        height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
        duration = frame_count / fps if fps > 0 and frame_count > 0 else 0.0
        if duration > MAX_VIDEO_SECONDS:
            capture.release()
            raise ValueError("Video inspection is limited to clips of 180 seconds or less.")

        sample_count = min(MAX_VIDEO_SAMPLED_FRAMES, max(frame_count, 1))
        frame_positions = np.linspace(0, max(frame_count - 1, 0), sample_count, dtype=int)
        sampled_frames = []
        for frame_position in frame_positions:
            capture.set(cv2.CAP_PROP_POS_FRAMES, int(frame_position))
            success, frame = capture.read()
            if success and frame is not None:
                gray = cv2.cvtColor(cv2.resize(frame, (160, 90)), cv2.COLOR_BGR2GRAY)
                sampled_frames.append(gray)
        capture.release()

    if not sampled_frames:
        raise ValueError("The uploaded video contains no readable frames.")

    frame_differences = [
        float(cv2.absdiff(previous, current).mean())
        for previous, current in zip(sampled_frames, sampled_frames[1:])
    ]
    scene_change_candidates = sum(value >= 40 for value in frame_differences)
    evidence = [EvidenceItem(
        name="VIDEO_FRAME_PROFILE",
        value={
            "width": width,
            "height": height,
            "fps": round(fps, 2),
            "duration_seconds": round(duration, 2),
            "sampled_frames": len(sampled_frames),
            "scene_change_candidates": scene_change_candidates,
        },
    )]
    ai_marker = _find_ai_provenance(metadata_values)
    if ai_marker:
        evidence.append(EvidenceItem(name="AI_GENERATION_METADATA", value=ai_marker))

    return _build_visual_event(
        "video",
        evidence,
        ai_marker,
        f"Sampled {len(sampled_frames)} frames and inspected available container metadata. "
        "Scene changes may be normal edits; this screen does not classify face-level deepfakes.",
    )


def extract_video_audio(video_bytes: bytes, filename: str = "uploaded-video") -> bytes:
    """Extract a bounded mono WAV track from a video when FFmpeg is available."""
    if not video_bytes or len(video_bytes) > MAX_VIDEO_BYTES:
        raise ValueError("Upload a non-empty video no larger than 150 MB.")
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise RuntimeError("FFmpeg is unavailable; the video can be assessed visually only.")

    extension = Path(filename).suffix.lower()
    if extension not in VIDEO_EXTENSIONS:
        extension = ".mp4"
    with tempfile.TemporaryDirectory(prefix="cyberguard-audio-") as temp_dir:
        video_path = Path(temp_dir) / f"upload{extension}"
        video_path.write_bytes(video_bytes)
        try:
            result = subprocess.run(
                [
                    ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-i", str(video_path),
                    "-map", "0:a:0", "-vn", "-ac", "1", "-ar", "16000", "-t",
                    str(MAX_VIDEO_SECONDS), "-c:a", "pcm_s16le", "-f", "wav", "pipe:1",
                ],
                capture_output=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("Could not extract the video's audio track.") from exc

    if result.returncode != 0 or not result.stdout:
        raise ValueError("No decodable audio track was found in the video.")
    if len(result.stdout) > MAX_EXTRACTED_AUDIO_BYTES:
        raise ValueError("Extracted audio exceeds the 15 MB voice-analysis limit.")
    return result.stdout
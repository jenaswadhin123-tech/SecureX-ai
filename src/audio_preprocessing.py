"""Audio cleanup shared by voice detection and speech-to-text."""

from pathlib import Path
from typing import Union

import librosa
import numpy as np
import soundfile as sf


def denoise_audio_file(
    input_path: Union[str, Path], output_path: Union[str, Path], sr: int = 22050
) -> None:
    """Reduce stationary background noise and write a cleaned WAV file.

    The quietest frames provide a conservative noise profile. A soft spectral
    gate removes only energy clearly above that profile, preserving more speech
    detail when a recording starts with speech.
    """
    audio, sample_rate = librosa.load(str(input_path), sr=sr, mono=True)
    if audio.size == 0:
        raise ValueError("Audio file is empty.")

    n_fft = 1024
    hop_length = 256
    stft = librosa.stft(audio, n_fft=n_fft, hop_length=hop_length)
    magnitude = np.abs(stft)
    phase = np.angle(stft)

    noise_frames = max(1, min(magnitude.shape[1], int(0.35 * sample_rate / hop_length)))
    frame_energy = np.mean(magnitude, axis=0)
    quiet_indices = np.argsort(frame_energy)[:noise_frames]
    noise_profile = np.median(magnitude[:, quiet_indices], axis=1, keepdims=True)
    threshold = noise_profile * 1.35
    excess = np.maximum(magnitude - threshold, 0.0)
    gated_magnitude = threshold + excess * 0.8
    gated_magnitude = np.where(magnitude > threshold, gated_magnitude, magnitude * 0.18)

    cleaned = librosa.istft(
        gated_magnitude * np.exp(1j * phase),
        hop_length=hop_length,
        length=len(audio),
    )
    peak = float(np.max(np.abs(cleaned)))
    if peak > 0:
        cleaned = cleaned * min(0.95 / peak, 1.0)

    sf.write(str(output_path), cleaned.astype(np.float32), sample_rate)
"""Audio feature extraction module for AI vs. Human voice detection.

Extracts pitch (fundamental frequency), spectral traits, and MFCC features
from an audio file to characterize acoustic signatures.
"""

from pathlib import Path
from typing import Dict, Tuple, Union
import numpy as np
import librosa


def extract_features(audio_path: Union[str, Path], sr: int = 22050) -> np.ndarray:
    """Extract a flattened feature vector from an audio file.

    Parameters
    ----------
    audio_path : Union[str, Path]
        Path to the target audio file.
    sr : int, optional
        Sampling rate for audio loading, defaults to 22050 Hz.

    Returns
    -------
    np.ndarray
        1D feature vector of acoustic descriptors.
    """
    vector, _ = extract_features_with_summary(audio_path, sr=sr)
    return vector


def extract_features_with_summary(
    audio_path: Union[str, Path], sr: int = 22050
) -> Tuple[np.ndarray, Dict[str, float]]:
    """Extract a flattened feature vector and a human-readable dictionary of metrics.

    Parameters
    ----------
    audio_path : Union[str, Path]
        Path to the target audio file.
    sr : int, optional
        Sampling rate for audio loading, defaults to 22050 Hz.

    Returns
    -------
    Tuple[np.ndarray, Dict[str, float]]
        (feature_vector, metrics_summary)
    """
    audio_path = str(audio_path)

    # Load audio as mono
    y, sample_rate = librosa.load(audio_path, sr=sr, mono=True)

    if len(y) == 0:
        y = np.zeros(sample_rate, dtype=np.float32)

    # Minimum audio length padding if less than 0.5 seconds
    min_length = int(sample_rate * 0.5)
    if len(y) < min_length:
        y = np.pad(y, (0, min_length - len(y)), mode="constant")

    features = []

    # 1. Fundamental Frequency (Pitch / f0)
    # Pitch tracking in typical human speech range: 50Hz - 500Hz
    try:
        f0, voiced_flag, _ = librosa.pyin(
            y,
            fmin=float(librosa.note_to_hz("C2")),   # ~65 Hz
            fmax=float(librosa.note_to_hz("C6")),   # ~1046 Hz
            sr=sample_rate,
            frame_length=2048,
        )
        voiced_f0 = f0[voiced_flag] if voiced_flag is not None else np.array([])
    except Exception:
        voiced_f0 = np.array([])
        voiced_flag = np.zeros(1, dtype=bool)

    if len(voiced_f0) > 0 and not np.all(np.isnan(voiced_f0)):
        valid_f0 = voiced_f0[~np.isnan(voiced_f0)]
        if len(valid_f0) > 0:
            f0_mean = float(np.mean(valid_f0))
            f0_std = float(np.std(valid_f0))
            f0_min = float(np.min(valid_f0))
            f0_max = float(np.max(valid_f0))
            # Jitter approximation: mean absolute difference between successive pitch periods
            f0_diff = np.abs(np.diff(valid_f0))
            f0_jitter = float(np.mean(f0_diff)) if len(f0_diff) > 0 else 0.0
        else:
            f0_mean, f0_std, f0_min, f0_max, f0_jitter = 0.0, 0.0, 0.0, 0.0, 0.0
    else:
        f0_mean, f0_std, f0_min, f0_max, f0_jitter = 0.0, 0.0, 0.0, 0.0, 0.0

    voicing_ratio = float(np.mean(voiced_flag)) if voiced_flag is not None and len(voiced_flag) > 0 else 0.0

    features.extend([f0_mean, f0_std, f0_min, f0_max, f0_jitter, voicing_ratio])

    # 2. Spectral Traits
    # Spectral Centroid (timbral brightness)
    centroid = librosa.feature.spectral_centroid(y=y, sr=sample_rate)
    centroid_mean = float(np.mean(centroid))
    centroid_std = float(np.std(centroid))
    features.extend([centroid_mean, centroid_std])

    # Spectral Bandwidth (spread of frequencies around centroid)
    bandwidth = librosa.feature.spectral_bandwidth(y=y, sr=sample_rate)
    bandwidth_mean = float(np.mean(bandwidth))
    bandwidth_std = float(np.std(bandwidth))
    features.extend([bandwidth_mean, bandwidth_std])

    # Spectral Flatness (tonality vs noise; vocoders often exhibit specific flatness curves)
    flatness = librosa.feature.spectral_flatness(y=y)
    flatness_mean = float(np.mean(flatness))
    flatness_std = float(np.std(flatness))
    features.extend([flatness_mean, flatness_std])

    # Spectral Rolloff (frequency under which 85% of energy is concentrated)
    rolloff = librosa.feature.spectral_rolloff(y=y, sr=sample_rate, roll_percent=0.85)
    rolloff_mean = float(np.mean(rolloff))
    rolloff_std = float(np.std(rolloff))
    features.extend([rolloff_mean, rolloff_std])

    # Spectral Contrast (valley to peak energy difference across 7 octave bands)
    contrast = librosa.feature.spectral_contrast(y=y, sr=sample_rate)
    contrast_mean = np.mean(contrast, axis=1)  # 7 values
    contrast_std = np.std(contrast, axis=1)   # 7 values
    features.extend(contrast_mean.tolist())
    features.extend(contrast_std.tolist())

    # Zero Crossing Rate (unvoiced sounds / noise)
    zcr = librosa.feature.zero_crossing_rate(y)
    zcr_mean = float(np.mean(zcr))
    zcr_std = float(np.std(zcr))
    features.extend([zcr_mean, zcr_std])

    # RMS Energy (signal loudness dynamics)
    rms = librosa.feature.rms(y=y)
    rms_mean = float(np.mean(rms))
    rms_std = float(np.std(rms))
    features.extend([rms_mean, rms_std])

    # 3. MFCC (Mel-Frequency Cepstral Coefficients)
    # Extract 20 MFCCs (means and standard deviations)
    mfcc = librosa.feature.mfcc(y=y, sr=sample_rate, n_mfcc=20)
    mfcc_mean = np.mean(mfcc, axis=1)
    mfcc_std = np.std(mfcc, axis=1)
    features.extend(mfcc_mean.tolist())
    features.extend(mfcc_std.tolist())

    # Delta MFCCs (first derivative - temporal velocity of spectral envelope)
    mfcc_delta = librosa.feature.delta(mfcc)
    delta_mean = np.mean(mfcc_delta, axis=1)
    delta_std = np.std(mfcc_delta, axis=1)
    features.extend(delta_mean.tolist())
    features.extend(delta_std.tolist())

    # 4. Chroma STFT (pitch class profile)
    chroma = librosa.feature.chroma_stft(y=y, sr=sample_rate)
    chroma_mean = np.mean(chroma, axis=1)
    features.extend(chroma_mean.tolist())

    # Clean up and ensure numpy float array
    vector = np.array(features, dtype=np.float32)
    vector = np.nan_to_num(vector, nan=0.0, posinf=0.0, neginf=0.0)

    summary = {
        "duration_sec": float(len(y) / sample_rate),
        "f0_mean_hz": round(f0_mean, 1),
        "f0_std_hz": round(f0_std, 1),
        "f0_jitter": round(f0_jitter, 2),
        "voicing_ratio": round(voicing_ratio, 2),
        "spectral_centroid_hz": round(centroid_mean, 1),
        "spectral_bandwidth_hz": round(bandwidth_mean, 1),
        "spectral_flatness": round(flatness_mean, 5),
        "spectral_rolloff_hz": round(rolloff_mean, 1),
        "zcr_mean": round(zcr_mean, 4),
        "rms_energy": round(rms_mean, 4),
    }

    return vector, summary

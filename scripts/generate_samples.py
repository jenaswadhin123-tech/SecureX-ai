"""Script to generate realistic synthetic audio sample clips for human vs. AI voice detection.

Creates demo audio files in data/sample_audio:
- human_sample_*.wav: simulated human speech with pitch drift, formant resonance, jitter, and pauses
- ai_sample_*.wav: simulated AI/TTS speech with rigid pitch, vocoder harmonics, and static flatness
"""

from pathlib import Path
import numpy as np
import soundfile as sf

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data" / "sample_audio"


def generate_human_voice(
    duration: float = 3.0,
    base_f0: float = 140.0,
    sample_rate: int = 22050,
    seed: int = 42,
) -> np.ndarray:
    """Simulate human speech acoustic characteristics."""
    rng = np.random.default_rng(seed)
    n_samples = int(duration * sample_rate)
    t = np.linspace(0, duration, n_samples, endpoint=False)

    # 1. Natural intonation contour (rising and falling prosody curve + micro-jitter)
    prosody = 15.0 * np.sin(2 * np.pi * 0.8 * t) + 8.0 * np.sin(2 * np.pi * 1.7 * t)
    micro_jitter = rng.normal(0, 1.8, n_samples)
    f0_contour = base_f0 + prosody + micro_jitter
    f0_contour = np.clip(f0_contour, 70.0, 350.0)

    # Integrate instantaneous frequency to get phase
    phase = 2 * np.pi * np.cumsum(f0_contour) / sample_rate

    # 2. Formant resonators simulating human vocal tract (F1 ~ 600Hz, F2 ~ 1400Hz, F3 ~ 2400Hz)
    glottal_pulse = np.zeros(n_samples)
    for harmonic in range(1, 15):
        harmonic_freq = harmonic * base_f0
        # Formant weighting
        f1_gain = np.exp(-((harmonic_freq - 650) ** 2) / (2 * (150**2)))
        f2_gain = 0.6 * np.exp(-((harmonic_freq - 1450) ** 2) / (2 * (200**2)))
        f3_gain = 0.3 * np.exp(-((harmonic_freq - 2500) ** 2) / (2 * (250**2)))
        glottal_slope = 1.0 / (harmonic**1.2)
        total_gain = glottal_slope * (1.0 + 3.0 * f1_gain + 2.0 * f2_gain + 1.5 * f3_gain)

        # Harmonic phase with natural random dispersion
        glottal_pulse += total_gain * np.sin(harmonic * phase + rng.uniform(0, np.pi))

    # 3. Dynamic syllables and speech pauses
    envelope = (
        0.5 * (1 + np.sin(2 * np.pi * 3.2 * t - np.pi / 2))
        * (0.8 + 0.2 * np.sin(2 * np.pi * 0.5 * t))
    )
    # Natural smooth attack and decay
    fade = int(0.05 * sample_rate)
    envelope[:fade] *= np.linspace(0, 1, fade)
    envelope[-fade:] *= np.linspace(1, 0, fade)

    # 4. Aspiration / breath noise (pink-filtered noise)
    noise = rng.normal(0, 0.03, n_samples)
    signal = (glottal_pulse * envelope) + (noise * envelope)

    # Normalize to [-0.9, 0.9]
    max_val = np.max(np.abs(signal))
    if max_val > 0:
        signal = 0.85 * (signal / max_val)

    return signal.astype(np.float32)


def generate_ai_voice(
    duration: float = 3.0,
    base_f0: float = 140.0,
    sample_rate: int = 22050,
    seed: int = 100,
) -> np.ndarray:
    """Simulate AI/TTS vocoder speech characteristics."""
    rng = np.random.default_rng(seed)
    n_samples = int(duration * sample_rate)
    t = np.linspace(0, duration, n_samples, endpoint=False)

    # 1. Robotic, rigid pitch (constant frequency with negligible or quantized variation)
    quantized_steps = np.floor(t * 4.0) / 4.0
    f0_contour = base_f0 + 2.0 * np.sin(2 * np.pi * 0.5 * quantized_steps)
    phase = 2 * np.pi * np.cumsum(f0_contour) / sample_rate

    # 2. Additive vocoder harmonics with locked static phases (buzzing timbre)
    vocoder_signal = np.zeros(n_samples)
    for harmonic in range(1, 22):
        # Steeper, uniform spectral falloff typical of pulse-train vocoders
        weight = 1.0 / (harmonic**0.85)
        vocoder_signal += weight * np.sin(harmonic * phase)

    # 3. High-frequency digital artifact / quantization buzz
    hf_artifact = 0.08 * np.sin(2 * np.pi * 4000.0 * t) + 0.05 * np.sin(
        2 * np.pi * 6000.0 * t
    )

    # 4. Mechanical syllable envelope (rapid transitions, rigid timing)
    syllables = np.abs(np.sin(2 * np.pi * 3.5 * t)) ** 0.5
    fade = int(0.02 * sample_rate)
    syllables[:fade] *= np.linspace(0, 1, fade)
    syllables[-fade:] *= np.linspace(1, 0, fade)

    signal = (vocoder_signal * syllables) + (hf_artifact * syllables)

    # Normalize to [-0.9, 0.9]
    max_val = np.max(np.abs(signal))
    if max_val > 0:
        signal = 0.85 * (signal / max_val)

    return signal.astype(np.float32)


def generate_dataset():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Generating sample audio files in {OUTPUT_DIR}...")

    # Generate Human Samples
    human_configs = [
        ("human_male_natural_01.wav", 125.0, 3.2, 10),
        ("human_female_natural_02.wav", 210.0, 2.8, 20),
        ("human_male_conversational_03.wav", 115.0, 3.5, 30),
        ("human_female_conversational_04.wav", 195.0, 3.0, 40),
        ("human_expressive_speech_05.wav", 155.0, 3.1, 50),
    ]

    for fname, f0, dur, seed in human_configs:
        path = OUTPUT_DIR / fname
        audio = generate_human_voice(duration=dur, base_f0=f0, seed=seed)
        sf.write(str(path), audio, 22050)
        print(f"  Created: {fname} (Human, f0={f0}Hz, dur={dur}s)")

    # Generate AI / Synthetic Samples (filename contains 'ai')
    ai_configs = [
        ("ai_generated_tts_male_01.wav", 130.0, 3.2, 110),
        ("ai_generated_tts_female_02.wav", 205.0, 2.8, 120),
        ("ai_cloned_voice_speech_03.wav", 120.0, 3.5, 130),
        ("ai_deepfake_audio_clip_04.wav", 190.0, 3.0, 140),
        ("ai_synthetic_neural_voice_05.wav", 150.0, 3.1, 150),
    ]

    for fname, f0, dur, seed in ai_configs:
        path = OUTPUT_DIR / fname
        audio = generate_ai_voice(duration=dur, base_f0=f0, seed=seed)
        sf.write(str(path), audio, 22050)
        print(f"  Created: {fname} (AI-generated, f0={f0}Hz, dur={dur}s)")

    print("Sample dataset generation complete!")


if __name__ == "__main__":
    generate_dataset()

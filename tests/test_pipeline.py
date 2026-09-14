"""Unit tests for the AI Voice Detection pipeline."""

import tempfile
import unittest
from pathlib import Path
import joblib
import numpy as np
import soundfile as sf

from src.feature_extraction import extract_features, extract_features_with_summary
from src.model import train_model
from src.inference import predict_with_confidence, analyze_audio
from src.scam_analyzer import analyze_scam_intent, determine_overall_risk
from src.transcription import transcribe_audio
from src.audio_preprocessing import denoise_audio_file


class TestVoiceDetectionPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_dir = Path(cls.temp_dir.name)

        # Create a test audio file
        sr = 22050
        duration = 1.0
        t = np.linspace(0, duration, int(sr * duration), endpoint=False)
        audio_data = 0.5 * np.sin(2 * np.pi * 220.0 * t).astype(np.float32)

        cls.sample_wav = cls.test_dir / "test_sample.wav"
        sf.write(str(cls.sample_wav), audio_data, sr)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_feature_extraction(self):
        features = extract_features(self.sample_wav)
        self.assertIsInstance(features, np.ndarray)
        self.assertEqual(features.ndim, 1)
        self.assertGreater(len(features), 30)
        self.assertFalse(np.isnan(features).any(), "Features must not contain NaNs")
        self.assertFalse(np.isinf(features).any(), "Features must not contain Infs")

    def test_feature_extraction_with_summary(self):
        vector, summary = extract_features_with_summary(self.sample_wav)
        self.assertEqual(len(vector.shape), 1)
        self.assertIn("f0_mean_hz", summary)
        self.assertIn("spectral_centroid_hz", summary)
        self.assertIn("spectral_flatness", summary)
        self.assertIn("duration_sec", summary)
        self.assertGreater(summary["duration_sec"], 0.8)

    def test_model_training_and_serialization(self):
        n_samples = 10
        n_features = 58
        rng = np.random.default_rng(42)
        X = rng.normal(0, 1, size=(n_samples, n_features)).astype(np.float32)
        y = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])

        model, accuracy = train_model(X, y, random_state=42)
        self.assertIsNotNone(model)
        self.assertGreaterEqual(accuracy, 0.0)
        self.assertLessEqual(accuracy, 1.0)

        # Test joblib persistence
        model_path = self.test_dir / "temp_model.joblib"
        joblib.dump(model, model_path)
        loaded_model = joblib.load(model_path)
        pred = loaded_model.predict(X[:2])
        self.assertEqual(len(pred), 2)

    def test_inference(self):
        # Create a trained model with 2 synthetic samples
        feat = extract_features(self.sample_wav)
        X = np.vstack([feat, feat + 0.1, feat - 0.1, feat + 0.2])
        y = np.array([0, 0, 1, 1])
        model, _ = train_model(X, y, random_state=42)

        label, confidence = predict_with_confidence(model, self.sample_wav)
        self.assertIn(label, ["AI", "Human"])
        self.assertGreaterEqual(confidence, 0.5)
        self.assertLessEqual(confidence, 1.0)

        label, confidence, metrics, probs = analyze_audio(model, self.sample_wav)
        self.assertIn(label, ["AI", "Human"])
        self.assertIn("AI", probs)
        self.assertIn("Human", probs)
        self.assertAlmostEqual(probs["AI"] + probs["Human"], 1.0, places=3)
        self.assertIn("f0_mean_hz", metrics)

    def test_scam_intent_scoring(self):
        transcript = (
            "Hello, I'm your brother. I lost my phone. Please send ₹50,000 "
            "immediately."
        )
        result = analyze_scam_intent(transcript)

        self.assertEqual(result["score"], 75)
        self.assertEqual(result["level"], "HIGH")
        self.assertEqual(
            {item["key"] for item in result["indicators"]},
            {"money_request", "urgency", "impersonation", "emergency_claim"},
        )

    def test_scam_intent_is_independent_from_voice_features(self):
        result = analyze_scam_intent("Please send the report when you have time.")

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "LOW")
        self.assertEqual(result["indicators"], [])

    def test_overall_risk_keeps_voice_and_scam_layers_separate(self):
        high_scam = analyze_scam_intent("Send money immediately. I am your brother.")

        self.assertEqual(determine_overall_risk(high_scam, "Human", 0.05), "HIGH")
        self.assertEqual(determine_overall_risk({"level": "LOW"}, "AI", 0.91), "ELEVATED")

    def test_transcription_passes_selected_language(self):
        import src.transcription as transcription

        class FakeWhisperModel:
            def __init__(self):
                self.options = None

            def transcribe(self, _audio_path, **options):
                self.options = options
                return {"text": " नमस्कार "}

        fake_model = FakeWhisperModel()
        original_loader = transcription._load_whisper_model
        transcription._load_whisper_model = lambda _model_name: fake_model
        try:
            result = transcribe_audio(self.sample_wav, model_name="tiny", language="hi")
        finally:
            transcription._load_whisper_model = original_loader

        self.assertEqual(result, "नमस्कार")
        self.assertEqual(fake_model.options["language"], "hi")
        self.assertFalse(fake_model.options["fp16"])

    def test_audio_denoising_writes_valid_audio(self):
        cleaned_path = self.test_dir / "cleaned.wav"
        denoise_audio_file(self.sample_wav, cleaned_path)
        cleaned, sample_rate = sf.read(cleaned_path)

        self.assertEqual(sample_rate, 22050)
        self.assertGreater(len(cleaned), 0)
        self.assertTrue(np.isfinite(cleaned).all())


if __name__ == "__main__":
    unittest.main()

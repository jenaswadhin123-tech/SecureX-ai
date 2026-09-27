import io
import unittest
from unittest.mock import MagicMock, patch

import cv2
import numpy as np
from PIL import Image, PngImagePlugin

from cyberguard.backend.services.media_forensics_service import (
    analyze_image_bytes,
    analyze_video_bytes,
    extract_video_audio,
)


def _png_bytes(software=None):
    image = Image.new("RGB", (64, 48), color=(40, 90, 130))
    output = io.BytesIO()
    metadata = PngImagePlugin.PngInfo()
    if software:
        metadata.add_text("Software", software)
    image.save(output, format="PNG", pnginfo=metadata)
    return output.getvalue()


class TestMediaForensicsService(unittest.TestCase):
    def test_image_with_ai_generator_provenance_is_flagged_for_review(self):
        result = analyze_image_bytes(_png_bytes("ComfyUI Stable Diffusion"), "generated.png")

        evidence_names = {item["name"] for item in result["evidence"]}
        self.assertIn("AI_GENERATION_METADATA", evidence_names)
        self.assertEqual(result["risk_score"], 55)

    def test_image_without_generator_metadata_has_no_deepfake_verdict(self):
        result = analyze_image_bytes(_png_bytes(), "photo.png")

        self.assertEqual(result["risk_score"], 0)
        self.assertIn("IMAGE_FILE_PROFILE", {item["name"] for item in result["evidence"]})

    def test_unreadable_image_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "readable image"):
            analyze_image_bytes(b"not an image", "broken.png")

    @patch("cyberguard.backend.services.media_forensics_service._video_metadata_values", return_value=[])
    @patch("cyberguard.backend.services.media_forensics_service.cv2.VideoCapture")
    def test_video_reports_sampled_frame_profile(self, mock_capture, _mock_metadata):
        capture = MagicMock()
        capture.isOpened.return_value = True
        capture.get.side_effect = [2.0, 2, 64, 48]
        frame = np.zeros((48, 64, 3), dtype=np.uint8)
        capture.read.side_effect = [(True, frame), (True, frame)]
        mock_capture.return_value = capture

        result = analyze_video_bytes(b"video bytes", "clip.mp4")

        profile = next(item["value"] for item in result["evidence"] if item["name"] == "VIDEO_FRAME_PROFILE")
        self.assertEqual(profile["sampled_frames"], 2)
        self.assertEqual(result["risk_score"], 0)

    @patch("cyberguard.backend.services.media_forensics_service.shutil.which", return_value=None)
    def test_audio_extraction_reports_missing_ffmpeg(self, _mock_which):
        with self.assertRaisesRegex(RuntimeError, "FFmpeg is unavailable"):
            extract_video_audio(b"video bytes", "clip.mp4")


if __name__ == "__main__":
    unittest.main()
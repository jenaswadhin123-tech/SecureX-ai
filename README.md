# AI Voice Detection Application 🎙️

An end-to-end Python application and interactive web interface to determine whether an audio clip is **Human Speech** or **AI-Generated Speech**.

The system extracts key acoustic features—including fundamental frequency ($f_0$) pitch tracking, pitch jitter, spectral traits (centroid, bandwidth, flatness, rolloff, contrast, zero-crossing rate), and Mel-Frequency Cepstral Coefficients (MFCCs with delta dynamics)—and classifies them using a trained Random Forest pipeline with confidence estimation.

---

## 🌟 Key Features

- **Acoustic Feature Extraction**:
  - **Pitch & Intonation**: $f_0$ fundamental frequency mean, standard deviation, jitter, and voicing ratio.
  - **Spectral Traits**: Spectral centroid (brightness), bandwidth, spectral flatness (tonality vs. vocoder noise), rolloff, and octave contrast.
  - **MFCCs & Temporal Dynamics**: 20 MFCCs and delta velocity coefficients capturing phonetic transitions.
- **Machine Learning Pipeline**:
  - `StandardScaler` + `RandomForestClassifier` with balanced class weights and probability calibration.
  - Cross-validation evaluation and model persistence via `joblib`.
- **Interactive Streamlit Web App (`app.py`)**:
  - Upload audio (`.wav`, `.mp3`, `.ogg`, `.flac`, `.m4a`) or record directly via microphone.
  - Test pre-packaged demo samples with one click.
  - Clear verdict banner with confidence percentage.
  - Detailed visual breakdown of acoustic properties ($f_0$ pitch, spectral flatness, centroid, jitter).
  - One-click model retraining directly from the sidebar.
- **Speech-to-Text and Scam Intent Analysis**:
  - Transcribes analyzed audio with Whisper (`tiny`, `base`, `small`, or `medium` model), with silence trimming, normalization, and fallback decoding for noisy recordings.
  - Supports automatic detection plus English, Hindi, Odia, Bengali, Telugu, Tamil, Marathi, Gujarati, Punjabi, Urdu, Kannada, Malayalam, Spanish, French, German, Portuguese, Arabic, Russian, Chinese, Japanese, and Korean transcription.
  - Detects money requests, OTP requests, banking credentials, urgency, impersonation, threats, and emergency claims.
  - Assigns weighted scam indicators and a capped score from 0 to 100.
  - Keeps voice authenticity and scam intent separate, then derives a conservative overall risk level.
- **Standalone Training Script (`train.py`)**:
  - Retrain the model on any dataset in `data/sample_audio/` at any time.

---

## 📁 Project Structure

```
ai_voice_detection/
├── data/
│   └── sample_audio/         # Audio dataset (files with 'ai' in name = AI, others = Human)
├── src/
│   ├── __init__.py
│   ├── feature_extraction.py # Audio feature extractor (pitch, spectral, MFCCs)
│   ├── model.py              # Scaler + Random Forest pipeline & cross-validation
│   └── inference.py          # Prediction and confidence calculation
│   ├── transcription.py      # Whisper speech-to-text adapter
│   └── scam_analyzer.py      # Weighted rule-based scam intent analysis
├── scripts/
│   └── generate_samples.py   # Synthesizes demo audio files for instant testing
├── tests/
│   ├── __init__.py
│   └── test_pipeline.py      # Automated unit tests
├── train.py                  # Standalone training CLI
├── app.py                    # Streamlit web application
├── model.joblib              # Serialized trained model
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## 🚀 Quickstart

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Whisper downloads the selected model the first time transcription is used. The app offers `tiny`, `base`, and `small`; `small` is the default for better transcription accuracy, while `tiny` is fastest and `base` is a middle ground.

### 2. Generate Demo Audio Dataset (Optional)

If you don't already have audio samples in `data/sample_audio/`, generate 10 synthetic demo samples:

```bash
python scripts/generate_samples.py
```

### 3. Train the Model

Train on files in `data/sample_audio/`:

```bash
python train.py
```

> **Dataset labeling rule**: Any audio file in `data/sample_audio/` whose filename contains `ai` (case-insensitive, e.g. `ai_sample_01.wav`) is labeled as **AI-Generated**. All other files (e.g. `human_sample_01.wav`, `speaker_02.mp3`) are labeled as **Human**.

### 4. Run the Web Application

Launch the Streamlit app:

```bash
streamlit run app.py
```

Open your browser at `http://localhost:8501`. You can now:
1. Upload your own `.wav` or `.mp3` clip, record your voice, or select a demo sample.
2. Click **Analyze voice** to inspect the verdict, confidence score, and acoustic feature breakdown.
3. Review the transcript, scam indicators, scam score, and overall risk assessment.
4. Drop new recordings into `data/sample_audio/` and hit **Train model** in the sidebar to retrain on the fly.

---

## 🧪 Running Tests

To run the automated unit test suite:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 🛡️ CyberGuard Backend & Google Safe Browsing Integration

The `cyberguard/backend` directory houses a FastAPI application providing cybersecurity threat detection APIs (URL reputation, phishing analysis, voice threat analysis, and account risk evaluation).

### Environment Configuration

- **`SAFE_BROWSING_API_KEY`**: Set this environment variable to enable Google Safe Browsing v4 API lookups for URL reputation analysis.
  ```bash
  # Windows PowerShell
  $env:SAFE_BROWSING_API_KEY="YOUR_GOOGLE_SAFE_BROWSING_API_KEY"

  # Linux / macOS
  export SAFE_BROWSING_API_KEY="YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
  ```
- If `SAFE_BROWSING_API_KEY` is not provided or empty, the URL reputation service gracefully falls back to the internal domain block-list.

### Running the Backend

```bash
uvicorn cyberguard.backend.main:app --reload
```

The API will be available at `http://127.0.0.1:8000/api`.

### Running Backend Unit Tests

```bash
python -m unittest cyberguard/backend/tests/test_url_service.py
```

---

## 💻 CyberGuard React + Vite Enterprise Web UI

The `cyberguard/frontend` directory contains a production React + Vite single-page application styled with Tailwind CSS, Lucide icons, and Recharts.

### Running the React Frontend

1. Install Node dependencies (if first time):
   ```bash
   cd cyberguard/frontend
   npm install
   ```

2. Start the Vite development server:
   ```bash
   npm run dev
   ```

   Open your browser at `http://localhost:3000`. API requests to `/api` are automatically proxied to the FastAPI backend (`http://127.0.0.1:8000`).

3. Build for production:
   ```bash
   npm run build
   ```

---

## 🐳 Docker Multi-Container Deployment

CyberGuard includes ready-to-run Docker configuration files for automated multi-container orchestration.

```bash
# Start MongoDB, FastAPI Backend, and React Frontend in Docker
docker compose up -d --build
```

- **React Web UI**: `http://localhost:3000`
- **FastAPI Backend**: `http://localhost:8000/api`
- **MongoDB Database**: `localhost:27017`




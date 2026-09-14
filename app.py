"""Voice Authenticity Check - AI vs. Human Voice Detection.

Clean, professional, and well-aligned interface for audio screening,
risk assessment, and acoustic feature analysis.
"""

from pathlib import Path
import tempfile
import io
import base64
import joblib
import librosa
import numpy as np
import matplotlib.pyplot as plt
import streamlit as st

from src.inference import analyze_audio
from src.audio_preprocessing import denoise_audio_file
from src.scam_analyzer import analyze_scam_intent, determine_overall_risk
from src.transcription import transcribe_audio
from train import load_dataset, DATA_DIR
from src.model import train_model

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_MODEL_PATH = PROJECT_ROOT / "model.joblib"
TEMP_MODEL_PATH = Path(tempfile.gettempdir()) / "model.joblib"


def get_model_path() -> Path:
    if TEMP_MODEL_PATH.exists():
        return TEMP_MODEL_PATH
    if DEFAULT_MODEL_PATH.exists():
        return DEFAULT_MODEL_PATH
    return DEFAULT_MODEL_PATH


def save_trained_model(model):
    try:
        joblib.dump(model, DEFAULT_MODEL_PATH)
    except (PermissionError, OSError):
        joblib.dump(model, TEMP_MODEL_PATH)


def render_risk_pie_chart(p_human: float, p_ai: float) -> str:
    """Generate a clean, high-resolution risk pie chart."""
    fig, ax = plt.subplots(figsize=(3.3, 3.3), facecolor="none")
    sizes = [p_human, p_ai]
    colors = ["#20E39A", "#FF5268"]

    wedges, _ = ax.pie(
        sizes,
        colors=colors,
        startangle=90,
        wedgeprops=dict(width=0.42, edgecolor="#11152D", linewidth=2.5),
    )

    is_low_risk = p_human >= 0.5
    risk_label = "LOW\nRISK" if is_low_risk else "HIGH\nRISK"
    risk_color = "#20E39A" if is_low_risk else "#FF5268"

    ax.text(
        0,
        0,
        risk_label,
        ha="center",
        va="center",
        color=risk_color,
        fontsize=9,
        fontweight="bold",
        linespacing=0.9,
    )

    ax.axis("equal")
    plt.tight_layout(pad=0.2)

    buf = io.BytesIO()
    plt.savefig(buf, format="png", transparent=True, dpi=180)
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()


def render_waveform(audio_source) -> str:
    """Render an audio waveform as a dashboard-styled transparent PNG."""
    if hasattr(audio_source, "getvalue"):
        audio_source = io.BytesIO(audio_source.getvalue())

    waveform, _ = librosa.load(audio_source, sr=22050, mono=True)
    if len(waveform) == 0:
        waveform = np.zeros(1, dtype=np.float32)

    max_points = 1400
    if len(waveform) > max_points:
        indices = np.linspace(0, len(waveform) - 1, max_points).astype(int)
        waveform = waveform[indices]

    fig, ax = plt.subplots(figsize=(7.2, 1.35), facecolor="#11152D")
    ax.set_facecolor("#11152D")
    ax.plot(waveform, color="#8C4DFF", linewidth=1.15)
    ax.fill_between(np.arange(len(waveform)), waveform, 0, color="#8C4DFF", alpha=0.18)
    ax.axhline(0, color="#292E54", linewidth=0.8)
    ax.axis("off")
    plt.tight_layout(pad=0.15)

    buf = io.BytesIO()
    plt.savefig(
        buf,
        format="png",
        transparent=False,
        facecolor="#11152D",
        dpi=180,
        bbox_inches="tight",
        pad_inches=0.05,
    )
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()


# --- Streamlit Configuration ---
st.set_page_config(
    page_title="AI Voice Detection | Voice Authenticity Check",
    page_icon="🎙️",
    layout="wide",
)

# --- Professional Styling & Typography ---
CUSTOM_CSS = """
<style>
/* Base theme */
.stApp {
    background: radial-gradient(circle at 75% 15%, #251347 0%, #0c0920 45%, #070716 100%) !important;
    color: #F7F7FF;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: linear-gradient(to bottom, #17133B, #0D0D25) !important;
    border-right: 1px solid rgba(255, 255, 255, 0.05) !important;
}

header[data-testid="stHeader"] {
    background: transparent !important;
}
footer {visibility: hidden;}

/* Professional Card Container */
.pro-card {
    background: #11152D;
    border: 1px solid #25294A;
    border-radius: 18px;
    padding: 24px;
    margin-bottom: 20px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
}

.pro-card-title {
    font-size: 1.1rem;
    font-weight: 600;
    color: #F7F7FF;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
    border-bottom: 1px solid #25294A;
    padding-bottom: 10px;
}

/* Verdict Banners */
.verdict-human {
    background: linear-gradient(to right, #075338, #096645, #0D7A54);
    border: 1px solid rgba(32, 227, 154, 0.4);
    border-radius: 14px;
    padding: 18px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
}

.verdict-ai {
    background: linear-gradient(to right, #59141D, #751B27, #8C2230);
    border: 1px solid rgba(255, 82, 104, 0.4);
    border-radius: 14px;
    padding: 18px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
}

.verdict-text {
    font-size: 1.35rem;
    font-weight: 700;
    line-height: 1.2;
}

.verdict-sub {
    font-size: 0.9rem;
    color: #9295B5;
    margin-top: 4px;
}

/* Progress bar container */
.bar-box {
    background: #171B38;
    border: 1px solid #292E54;
    border-radius: 12px;
    padding: 12px 14px;
    margin-bottom: 12px;
}

.bar-header {
    display: flex;
    justify-content: space-between;
    font-size: 0.85rem;
    font-weight: 600;
    margin-bottom: 6px;
}

.bar-track {
    width: 100%;
    height: 8px;
    background-color: #0C0F24;
    border-radius: 4px;
    overflow: hidden;
}

.bar-fill-green {
    height: 100%;
    background-color: #20E39A;
    border-radius: 4px;
}

.bar-fill-red {
    height: 100%;
    background-color: #FF5268;
    border-radius: 4px;
}

/* Analysis metric item */
.metric-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
    margin-top: 14px;
}

.metric-item {
    background-color: #171B38;
    border: 1px solid #292E54;
    border-radius: 12px;
    padding: 12px;
    text-align: center;
}

.metric-label {
    font-size: 0.78rem;
    color: #9295B5;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 4px;
}

.metric-val {
    font-size: 1.05rem;
    font-weight: 700;
    color: #F7F7FF;
}

.waveform-card {
    background: #11152D;
    border: 1px solid #25294A;
    border-radius: 14px;
    padding: 14px 16px 12px;
    margin-top: 14px;
}

.waveform-title {
    color: #9295B5;
    font-size: 0.78rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 8px;
}

.waveform-image {
    display: block;
    width: 100%;
    height: 78px;
    object-fit: fill;
    border-radius: 8px;
}

/* Keep native Streamlit controls readable when the OS theme is light. */
[data-testid="stFileUploader"],
[data-testid="stFileUploaderDropzone"] {
    background-color: #11152D !important;
    border: 1px solid #25294A !important;
    color: #F7F7FF !important;
}

[data-testid="stFileUploaderDropzone"] * {
    color: #F7F7FF !important;
}

[data-testid="stFileUploaderDropzone"] button {
    background-color: #25294A !important;
    border: 1px solid #3b3f6d !important;
    color: #ffffff !important;
}

[data-testid="stFileUploaderFile"] {
    background-color: #171B38 !important;
    color: #F7F7FF !important;
}

[data-testid="stFileUploaderFile"] * {
    background-color: transparent !important;
    color: #F7F7FF !important;
}

[data-testid="stFileUploaderFile"] button {
    background-color: #25294A !important;
    border-color: #3b3f6d !important;
    color: #F7F7FF !important;
}

[data-testid="stButton"] button[kind="secondary"] {
    background-color: #25294A !important;
    border: 1px solid #3b3f6d !important;
    color: #F7F7FF !important;
}

[data-testid="stButton"] button[kind="secondary"]:hover {
    background-color: #334155 !important;
    border-color: #64748b !important;
    color: #ffffff !important;
}

[data-testid="stButton"] button {
    position: relative;
    overflow: hidden;
    isolation: isolate;
    transition: transform 0.2s ease, box-shadow 0.2s ease !important;
}

[data-testid="stButton"] button::after {
    content: "";
    position: absolute;
    inset: 50%;
    width: 0;
    height: 0;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.22);
    transform: translate(-50%, -50%);
    opacity: 0;
    pointer-events: none;
}

[data-testid="stButton"] button:hover::after {
    animation: streamlit-button-wave 0.7s ease-out;
}

[data-testid="stButton"] button:hover {
    transform: translateY(-1px);
    box-shadow: 0 0 22px rgba(140, 77, 255, 0.35);
}

@keyframes streamlit-button-wave {
    0% { width: 0; height: 0; opacity: 0.45; }
    100% { width: 220%; height: 220%; opacity: 0; }
}

[data-testid="stRadio"] label,
[data-testid="stRadio"] label p,
[data-testid="stWidgetLabel"] p,
[data-testid="stSelectbox"] label,
[data-testid="stSelectbox"] label p {
    color: #F7F7FF !important;
}

[data-baseweb="select"] > div {
    background-color: #11152D !important;
    border-color: #25294A !important;
    color: #F7F7FF !important;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# --- App Header ---
st.markdown(
    """
    <div style="margin-bottom: 24px;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 18px;">
            <div style="display: flex; align-items: center; gap: 3px; height: 28px;">
                <span style="display: block; width: 4px; height: 10px; border-radius: 3px; background: #8C4DFF;"></span>
                <span style="display: block; width: 4px; height: 18px; border-radius: 3px; background: #8C4DFF;"></span>
                <span style="display: block; width: 4px; height: 27px; border-radius: 3px; background: #B184FF;"></span>
                <span style="display: block; width: 4px; height: 18px; border-radius: 3px; background: #8C4DFF;"></span>
                <span style="display: block; width: 4px; height: 10px; border-radius: 3px; background: #8C4DFF;"></span>
            </div>
            <div style="font-size: 1.45rem; font-weight: 800; letter-spacing: 0.2px; color: #ffffff; line-height: 1;">
                Vox<span style="color: #8C4DFF;">Guard</span>
            </div>
        </div>
        <h1 style="font-size: 2rem; font-weight: 700; color: #ffffff; margin: 0 0 4px 0;">
            Voice Authenticity Check
        </h1>
        <p style="color: #9295B5; font-size: 0.95rem; margin: 0;">
            Acoustic screening system to detect whether an audio clip is human speech or AI-generated.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# --- Sidebar: Model Status & Retraining Only ---
active_model = get_model_path()
with st.sidebar:
    st.markdown("### Model Settings")
    if active_model.exists():
        st.success("Trained Model: Ready")
    else:
        st.warning("No Model Loaded")

    existing_samples = (
        list(DATA_DIR.glob("*.wav"))
        + list(DATA_DIR.glob("*.mp3"))
        + list(DATA_DIR.glob("*.ogg"))
        + list(DATA_DIR.glob("*.flac"))
        if DATA_DIR.exists()
        else []
    )
    ai_count = len([p for p in existing_samples if "ai" in p.name.lower()])
    human_count = len([p for p in existing_samples if "ai" not in p.name.lower()])

    st.caption(f"Dataset: {human_count} Human clips | {ai_count} AI clips")

    whisper_model = st.selectbox(
        "Speech-to-text model",
        ["tiny", "base", "small", "medium"],
        index=2,
        help="Small is the recommended balance. Medium is more accurate for accents but needs much more memory and time.",
    )
    whisper_language = st.selectbox(
        "Speech language",
        [
            ("Auto detect", "auto"),
            ("English", "en"),
            ("Hindi", "hi"),
            ("Odia", "or"),
            ("Bengali", "bn"),
            ("Telugu", "te"),
            ("Tamil", "ta"),
            ("Marathi", "mr"),
            ("Gujarati", "gu"),
            ("Punjabi", "pa"),
            ("Urdu", "ur"),
            ("Kannada", "kn"),
            ("Malayalam", "ml"),
            ("Spanish", "es"),
            ("French", "fr"),
            ("German", "de"),
            ("Portuguese", "pt"),
            ("Arabic", "ar"),
            ("Russian", "ru"),
            ("Chinese", "zh"),
            ("Japanese", "ja"),
            ("Korean", "ko"),
        ],
        format_func=lambda option: option[0],
        help="Choose the spoken language for better accuracy. Use Auto detect for unknown or mixed-language audio.",
    )[1]

    if st.button("Retrain Model", use_container_width=True):
        with st.spinner("Retraining model..."):
            try:
                files, features, labels = load_dataset()
                if len(files) == 0:
                    st.error("No audio samples in data/sample_audio.")
                else:
                    model, accuracy = train_model(features, labels)
                    save_trained_model(model)
                    st.success(f"Trained! Accuracy: {accuracy:.1%}")
                    st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")

# --- State Management ---
if "active_tab" not in st.session_state:
    st.session_state.active_tab = "Upload"
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

# --- Main 2-Column Balanced Layout ---
col_input, col_results = st.columns([1, 1], gap="large")

# ==============================================================================
# LEFT COLUMN: Audio Input & Controls
# ==============================================================================
with col_input:
    st.markdown(
        """
        <div class="pro-card">
            <div class="pro-card-title">🎙️ Audio Input</div>
        """,
        unsafe_allow_html=True,
    )

    input_choice = st.radio(
        "Select Input Method",
        ["Upload File", "Record Mic", "Sample Audio"],
        horizontal=True,
        label_visibility="collapsed",
    )

    uploaded_audio = None
    recorded_audio = None
    sample_file_path = None

    if input_choice == "Upload File":
        uploaded_audio = st.file_uploader(
            "Upload audio file",
            type=["wav", "mp3", "m4a", "flac", "ogg"],
            label_visibility="collapsed",
            key="file_uploader_widget",
        )
    elif input_choice == "Record Mic":
        if hasattr(st, "audio_input"):
            recorded_audio = st.audio_input("Record voice clip", label_visibility="collapsed")
        else:
            st.info("Direct recording requires Streamlit >= 1.34. Use Upload File instead.")
    else:
        if existing_samples:
            sample_options = [s.name for s in existing_samples]
            chosen_sample = st.selectbox(
                "Select a sample audio file",
                sample_options,
                label_visibility="collapsed",
            )
            if chosen_sample:
                sample_file_path = DATA_DIR / chosen_sample
        else:
            st.info("No sample files found in data/sample_audio.")

    # Playback audio preview
    active_clip = uploaded_audio or recorded_audio
    if active_clip:
        st.audio(active_clip)
    elif sample_file_path:
        st.audio(str(sample_file_path))

    has_audio = (active_clip is not None) or (sample_file_path is not None)

    # Action Buttons: Analyze and Reset
    btn_col1, btn_col2 = st.columns([2, 1])
    with btn_col1:
        analyze_btn = st.button(
            "Analyze Voice",
            type="primary",
            use_container_width=True,
            disabled=not has_audio,
        )
    with btn_col2:
        reset_btn = st.button(
            "Reset",
            use_container_width=True,
        )

    if reset_btn:
        st.session_state.analysis_result = None
        st.rerun()

    waveform_source = active_clip if active_clip is not None else sample_file_path
    if waveform_source is not None:
        try:
            waveform_b64 = render_waveform(waveform_source)
            st.markdown(
                f"""
                <div class="waveform-card">
                    <div class="waveform-title">Acoustic Waveform</div>
                    <img class="waveform-image" src="data:image/png;base64,{waveform_b64}" alt="Audio waveform" />
                </div>
                """,
                unsafe_allow_html=True,
            )
        except (OSError, ValueError, RuntimeError) as err:
            st.warning(f"Waveform preview unavailable: {err}")

    st.markdown("</div>", unsafe_allow_html=True)

# Process Audio Analysis
if analyze_btn and has_audio:
    if not active_model.exists():
        st.error("Model file missing. Please retrain from the sidebar.")
    else:
        with st.spinner("Extracting acoustic features and evaluating..."):
            is_temp = False
            cleaned_file = None
            if sample_file_path:
                target_file = str(sample_file_path)
            else:
                suffix = Path(active_clip.name).suffix if getattr(active_clip, "name", None) else ".wav"
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(active_clip.getvalue())
                    target_file = tmp.name
                is_temp = True

            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as cleaned_tmp:
                    cleaned_file = cleaned_tmp.name
                denoise_audio_file(target_file, cleaned_file)
                analysis_file = cleaned_file
                model = joblib.load(active_model)
                label, confidence, metrics, probs = analyze_audio(model, analysis_file)
                transcript = ""
                transcription_error = None
                try:
                    transcript = transcribe_audio(
                        analysis_file,
                        model_name=whisper_model,
                        language=whisper_language,
                    )
                except RuntimeError as err:
                    transcription_error = str(err)
                scam_analysis = analyze_scam_intent(transcript)
                overall_level = determine_overall_risk(scam_analysis, label, probs["AI"])
                st.session_state.analysis_result = {
                    "label": label,
                    "confidence": confidence,
                    "metrics": metrics,
                    "probs": probs,
                    "transcript": transcript,
                    "transcription_error": transcription_error,
                    "scam": scam_analysis,
                    "overall_level": overall_level,
                }
            except Exception as err:
                st.error(f"Analysis failed: {err}")
            finally:
                if is_temp:
                    Path(target_file).unlink(missing_ok=True)
                if cleaned_file:
                    Path(cleaned_file).unlink(missing_ok=True)

# ==============================================================================
# RIGHT COLUMN: Analysis, Verdict & Risk Pie Chart
# ==============================================================================
with col_results:
    res = st.session_state.analysis_result

    if res:
        p_human = res["probs"]["Human"]
        p_ai = res["probs"]["AI"]
        label = res["label"]
        confidence = res["confidence"]
        metrics = res["metrics"]
        scam = res["scam"]
        overall_level = res["overall_level"]

        # --- 1. Verdict Banner ---
        if label == "Human":
            st.markdown(
                f"""
                <div class="verdict-human">
                    <div>
                        <div class="verdict-text" style="color: #20E39A;">👤 Likely Human Speech</div>
                        <div class="verdict-sub">Natural pitch drift and organic vocal dynamics detected.</div>
                    </div>
                    <div style="font-size: 1.4rem; font-weight: 700; color: #20E39A;">{confidence:.1%}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div class="verdict-ai">
                    <div>
                        <div class="verdict-text" style="color: #FF5268;">🤖 Likely AI-Generated Voice</div>
                        <div class="verdict-sub">Synthetic frequency characteristics and vocoder signatures detected.</div>
                    </div>
                    <div style="font-size: 1.4rem; font-weight: 700; color: #FF5268;">{confidence:.1%}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # --- 2. Probability Meters & Simple Risk Pie Chart ---
        st.markdown(
            """
            <div class="pro-card">
                <div class="pro-card-title">📊 Risk Assessment & Probabilities</div>
            """,
            unsafe_allow_html=True,
        )

        prob_col, chart_col = st.columns([1, 1], gap="medium")

        with prob_col:
            # Human Bar
            st.markdown(
                f"""
                <div class="bar-box">
                    <div class="bar-header">
                        <span style="color: #9295B5;">Human Probability</span>
                        <span style="color: #20E39A;">{p_human:.1%}</span>
                    </div>
                    <div class="bar-track">
                        <div class="bar-fill-green" style="width: {min(max(p_human*100, 0), 100)}%;"></div>
                    </div>
                </div>
                <div class="bar-box">
                    <div class="bar-header">
                        <span style="color: #9295B5;">AI-Generated Probability</span>
                        <span style="color: #FF5268;">{p_ai:.1%}</span>
                    </div>
                    <div class="bar-track">
                        <div class="bar-fill-red" style="width: {min(max(p_ai*100, 0), 100)}%;"></div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with chart_col:
            pie_b64 = render_risk_pie_chart(p_human, p_ai)
            st.markdown(
                f"""
                <div style="display: flex; justify-content: center; align-items: center;">
                    <img src="data:image/png;base64,{pie_b64}" style="width: 194px; height: 194px;" />
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown(
            f"""
            <div class="pro-card">
                <div class="pro-card-title">⚠ Overall Risk</div>
                <div style="font-size: 1.35rem; font-weight: 700; color: {'#FF5268' if overall_level == 'HIGH' else '#F2C14E' if overall_level == 'ELEVATED' else '#20E39A'};">
                    {overall_level}
                    <span style="float: right; font-size: 0.85rem; font-weight: 500; color: #9295B5;">Voice + scam assessment</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            f"""
            <div class="pro-card">
                <div class="pro-card-title">🛡 Scam Intent Analysis</div>
                <div style="font-size: 1.35rem; font-weight: 700; color: {'#FF5268' if scam['level'] == 'HIGH' else '#F2C14E' if scam['level'] == 'MEDIUM' else '#20E39A'};">
                    {scam['level']} RISK
                    <span style="float: right;">{scam['score']}/100</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if res["transcription_error"]:
            st.warning(res["transcription_error"])
        elif res["transcript"]:
            st.markdown("**Transcript**")
            st.info(res["transcript"])
        else:
            st.info("No speech was detected in the transcript.")

        if scam["indicators"]:
            st.markdown("**Detected indicators**")
            for indicator in scam["indicators"]:
                st.markdown(f"- **{indicator['label']}** (+{indicator['risk']})")
        else:
            st.caption("No configured scam indicators detected.")

        if scam["level"] in {"HIGH", "MEDIUM"}:
            st.warning(
                "Do not transfer money or share OTP or banking information. "
                "Verify the caller through another trusted communication channel."
            )
        else:
            st.success("No strong scam intent indicators detected. Continue to verify unexpected requests.")

        # --- 3. Acoustic Analysis ---
        st.markdown(
            f"""
            <div class="pro-card">
                <div class="pro-card-title">🔬 Acoustic Feature Analysis</div>
                <div class="metric-grid">
                    <div class="metric-item">
                        <div class="metric-label">Mean Pitch (f₀)</div>
                        <div class="metric-val">{metrics['f0_mean_hz']} Hz</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">Pitch Variation</div>
                        <div class="metric-val">±{metrics['f0_std_hz']} Hz</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">Pitch Jitter</div>
                        <div class="metric-val">{metrics['f0_jitter']}</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">Spectral Centroid</div>
                        <div class="metric-val">{metrics['spectral_centroid_hz']} Hz</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">Spectral Flatness</div>
                        <div class="metric-val">{metrics['spectral_flatness']:.5f}</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">Clip Duration</div>
                        <div class="metric-val">{metrics['duration_sec']:.2f}s</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    else:
        # Awaiting State
        st.markdown(
            """
            <div class="pro-card" style="text-align: center; padding: 60px 24px; color: #9295B5;">
                <div style="font-size: 36px; margin-bottom: 12px;">📊</div>
                <div style="font-size: 1.15rem; font-weight: 600; color: #F7F7FF; margin-bottom: 6px;">
                    Awaiting Audio Input
                </div>
                <div style="font-size: 0.9rem; max-width: 380px; margin: 0 auto;">
                    Select or upload an audio file on the left and click <b>Analyze Voice</b> to view authenticity prediction, risk pie chart, and acoustic traits.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

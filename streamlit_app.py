# streamlit_app.py
"""CYBERGUARD / SecureX — Real-Time Autonomous Threat Detection Dashboard.

100% Feature-and-Design Parity with the React + FastAPI CyberGuard Application.
"""

import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
import io
import csv
import hashlib

# Safe Plotly & Librosa import
try:
    import plotly.express as px
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

try:
    import librosa
    HAS_LIBROSA = True
except ImportError:
    HAS_LIBROSA = False

# Import CyberGuard Backend Services
from cyberguard.backend.services.url_service import _validate_url, analyze_url
from cyberguard.backend.services.qr_service import analyze_qr_image
from cyberguard.backend.services.phishing_service import analyze_phishing_text
from cyberguard.backend.services.account_service import analyze_account_log
from cyberguard.backend.services.webhook_service import send_threat_alert

TRANSCRIPTION_PROFILES = {
    "Hyper - Medium": {
        "model": "medium",
        "accuracy": "Highest accuracy",
        "duration": "~30-60 sec per 1 min audio",
        "description": "Best for accents and noisy recordings; requires the most memory.",
    },
    "Base - Small": {
        "model": "small",
        "accuracy": "High accuracy",
        "duration": "~15-35 sec per 1 min audio",
        "description": "Recommended balance of transcript quality and speed.",
    },
    "Base - Base": {
        "model": "base",
        "accuracy": "Balanced accuracy",
        "duration": "~8-20 sec per 1 min audio",
        "description": "Good everyday transcription with lower memory requirements.",
    },
    "Low - Tiny": {
        "model": "tiny",
        "accuracy": "Fastest, lower accuracy",
        "duration": "~5-15 sec per 1 min audio",
        "description": "Best for quick screening and lower-powered machines.",
    },
}


@st.cache_data(show_spinner=False)
def analyze_uploaded_voice(filename, audio_bytes, model_name="base", language="auto"):
    """Cache voice analysis by uploaded audio so results survive reruns."""
    import inspect
    from fastapi import UploadFile
    from cyberguard.backend.services.voice_service import analyze_voice_file

    upload = UploadFile(filename=filename, file=io.BytesIO(audio_bytes))
    if "model_name" in inspect.signature(analyze_voice_file).parameters:
        return analyze_voice_file(upload, model_name=model_name, language=language)
    return analyze_voice_file(upload)

# Page Configuration
st.set_page_config(
    page_title="CYBERGUARD — Autonomous Threat Detection Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# EXACT REACT CYBERGUARD THEME (Tailwind CSS matching palette)
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    @import url("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap");

    html, body, [class*="css"], .stApp {
        font-family: "Inter", sans-serif !important;
        background-color: #151332 !important;
        background-image: linear-gradient(115deg, #11102A 0%, #191641 48%, #302052 100%) !important;
        background-size: 140% 140% !important;
        background-attachment: fixed !important;
        color: #F5F5F5 !important;
    }

    header[data-testid="stHeader"],
    [data-testid="stToolbar"] {
        background: transparent !important;
        box-shadow: none !important;
    }

    [data-testid="stDecoration"] {
        background: transparent !important;
    }

    [data-testid="stCameraInput"] {
        width: 100% !important;
        min-height: 420px;
        padding: 10px !important;
        border: 1px solid rgba(93, 225, 255, 0.38) !important;
        border-radius: 14px !important;
        background: rgba(8, 12, 32, 0.78) !important;
        box-shadow: inset 0 0 28px rgba(93, 225, 255, 0.08), 0 0 22px rgba(124, 58, 237, 0.1);
    }
    [data-testid="stCameraInput"] video,
    [data-testid="stCameraInput"] img {
        width: 100% !important;
        max-height: 62vh !important;
        min-height: 340px;
        object-fit: contain !important;
        border-radius: 10px;
    }

    .stApp::before {
        content: "";
        position: fixed;
        inset: 0;
        z-index: 0;
        pointer-events: none;
        opacity: 0.24;
        background-image:
            radial-gradient(circle at 8% 18%, rgba(93, 225, 255, 0.85) 0 2px, transparent 3px),
            radial-gradient(circle at 24% 72%, rgba(192, 132, 252, 0.75) 0 2px, transparent 3px),
            radial-gradient(circle at 48% 30%, rgba(93, 225, 255, 0.72) 0 2px, transparent 3px),
            radial-gradient(circle at 72% 68%, rgba(192, 132, 252, 0.78) 0 2px, transparent 3px),
            radial-gradient(circle at 92% 22%, rgba(93, 225, 255, 0.78) 0 2px, transparent 3px),
            linear-gradient(28deg, transparent 0 47%, rgba(93, 225, 255, 0.12) 48%, transparent 49%),
            linear-gradient(148deg, transparent 0 47%, rgba(192, 132, 252, 0.11) 48%, transparent 49%),
            linear-gradient(rgba(93, 225, 255, 0.055) 1px, transparent 1px),
            linear-gradient(90deg, rgba(168, 85, 247, 0.05) 1px, transparent 1px);
        background-size: 220px 220px, 260px 260px, 300px 300px, 340px 340px, 280px 280px, 180px 180px, 220px 220px, 72px 72px, 72px 72px;
        animation: cyberguard-network-breathe 8s ease-in-out infinite alternate;
        will-change: transform, opacity;
        transform: translate3d(0, 0, 0);
        backface-visibility: hidden;
    }

    .stApp::after {
        content: "";
        position: fixed;
        inset: -35% -10%;
        z-index: 0;
        pointer-events: none;
        background:
            radial-gradient(ellipse at center, rgba(168, 85, 247, 0.18), transparent 48%),
            linear-gradient(112deg, transparent 37%, rgba(93, 225, 255, 0.02) 45%, rgba(93, 225, 255, 0.16) 50%, rgba(93, 225, 255, 0.02) 55%, transparent 63%),
            linear-gradient(180deg, transparent 0%, rgba(192, 132, 252, 0.06) 50%, transparent 100%);
        background-size: 100% 100%, 240% 100%, 100% 240%;
        animation: cyberguard-scan-pulse 11s ease-in-out infinite;
        will-change: transform, opacity;
        transform: translate3d(0, 0, 0);
        backface-visibility: hidden;
    }

    @keyframes cyberguard-scan-pulse {
        0%, 100% { opacity: 0.30; transform: translate3d(-2%, -1%, 0) scale(0.98); }
        50% { opacity: 0.72; transform: translate3d(2%, 1%, 0) scale(1.02); }
    }

    @keyframes cyberguard-network-breathe {
        0% { opacity: 0.18; transform: translate3d(-0.5%, 0, 0); }
        100% { opacity: 0.30; transform: translate3d(0.5%, 0.3%, 0); }
    }

    @media (prefers-reduced-motion: reduce) {
        html, body, [class*="css"], .stApp,
        .stApp::before, .stApp::after {
            animation: none !important;
        }
    }

    /* Cards */
    .card-panel {
        background-color: #11152F;
        border: 1px solid #292852;
        border-radius: 14px;
        padding: 24px;
        margin-bottom: 20px;
    }
    .metric-panel {
        background-color: #11152F;
        border: 1px solid #292852;
        border-radius: 12px;
        padding: 18px 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .metric-title {
        font-size: 11px;
        font-weight: 600;
        color: #9B9AB8;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }
    .metric-number {
        font-size: 26px;
        font-weight: 800;
        font-family: "JetBrains Mono", monospace;
        color: #FFFFFF;
        margin-top: 4px;
    }

    .acoustic-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 14px;
        margin: 12px 0 22px;
    }
    .acoustic-card {
        min-height: 86px;
        background: #0B081A;
        border: 1px solid #292852;
        border-left: 5px solid var(--feature-color);
        border-radius: 14px;
        padding: 18px 22px;
    }
    .acoustic-label {
        color: #64748B;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 0.3px;
        text-transform: uppercase;
    }
    .acoustic-value {
        color: #F8FAFC;
        font-family: "JetBrains Mono", monospace;
        font-size: 28px;
        font-weight: 800;
        line-height: 1.25;
        margin-top: 10px;
    }
    .acoustic-unit {
        color: #A1A1AA;
        font-size: 15px;
        font-weight: 600;
        margin-left: 8px;
    }
    @media (max-width: 900px) {
        .acoustic-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }
    }
    @media (max-width: 600px) {
        .acoustic-grid {
            grid-template-columns: 1fr;
        }
    }

    [data-testid="stMetric"] {
        overflow: visible !important;
    }
    [data-testid="stMetricValue"],
    [data-testid="stMetricValue"] > div {
        font-size: 1.35rem !important;
        line-height: 1.2 !important;
        white-space: normal !important;
        overflow: visible !important;
        text-overflow: clip !important;
        overflow-wrap: anywhere !important;
    }

    /* Badges */
    .risk-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 11px;
        font-weight: 800;
        font-family: "JetBrains Mono", monospace;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }
    .badge-critical { background: rgba(244, 63, 94, 0.12); color: #FB7185; border: 1px solid rgba(244, 63, 94, 0.35); }
    .badge-high     { background: rgba(249, 115, 22, 0.12); color: #FB923C; border: 1px solid rgba(249, 115, 22, 0.35); }
    .badge-medium   { background: rgba(245, 158, 11, 0.12); color: #FBBF24; border: 1px solid rgba(245, 158, 11, 0.35); }
    .badge-low      { background: rgba(59, 130, 246, 0.12); color: #60A5FA; border: 1px solid rgba(59, 130, 246, 0.35); }
    .badge-safe     { background: rgba(16, 185, 129, 0.12); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.35); }

    /* Evidence & Guidance Rows */
    .evidence-item {
        background: #0B081A;
        border: 1px solid #292852;
        padding: 10px 16px;
        border-radius: 8px;
        margin-bottom: 6px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-family: "JetBrains Mono", monospace;
        font-size: 12px;
    }
    .rec-item {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 13px;
        color: #E2E8F0;
        margin-bottom: 6px;
    }
    .rec-dot {
        width: 6px;
        height: 6px;
        background-color: #A855F7;
        border-radius: 50%;
        flex-shrink: 0;
    }

    /* AI Explanation Box */
    .ai-box {
        background-color: #0B081A;
        border: 1px solid rgba(168, 85, 247, 0.35);
        border-radius: 12px;
        padding: 16px;
        margin-top: 16px;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #292852;
    }
    .stTabs [data-baseweb="tab"] {
        height: 48px;
        color: #A1A1AA;
        font-weight: 500;
        font-size: 13px;
        padding: 0 16px;
        background-color: transparent;
        border-radius: 8px 8px 0 0;
    }
    .stTabs [aria-selected="true"] {
        color: #A855F7 !important;
        font-weight: 700 !important;
        border-bottom: 2px solid #A855F7 !important;
        background-color: rgba(168, 85, 247, 0.08) !important;
    }

    [data-testid="stSidebar"] {
        background-color: #090B20 !important;
        background-image:
            linear-gradient(rgba(93, 225, 255, 0.035) 1px, transparent 1px),
            linear-gradient(90deg, rgba(93, 225, 255, 0.035) 1px, transparent 1px),
            radial-gradient(circle at 15% 4%, rgba(124, 58, 237, 0.28), transparent 32%),
            linear-gradient(180deg, #15143A 0%, #090B20 62%) !important;
        background-size: 28px 28px, 28px 28px, auto, auto !important;
        border-right: 1px solid rgba(93, 225, 255, 0.22) !important;
        box-shadow: 12px 0 40px rgba(5, 7, 22, 0.32);
    }
    [data-testid="stSidebar"]::after {
        content: "SECUREX // CONTROL PLANE";
        position: fixed;
        left: 15px;
        bottom: 12px;
        color: rgba(93, 225, 255, 0.32);
        font-family: "JetBrains Mono", monospace;
        font-size: 8px;
        letter-spacing: 1.5px;
        pointer-events: none;
    }
    .sidebar-brand {
        display: flex;
        align-items: center;
        gap: 11px;
        padding: 13px 8px 18px 6px;
        margin-bottom: 9px;
        border-bottom: 1px solid rgba(93, 225, 255, 0.16);
    }
    .sidebar-brand-mark {
        display: flex;
        align-items: center;
        gap: 3px;
        height: 27px;
        padding: 0 5px;
        border-left: 1px solid #5DE1FF;
        border-right: 1px solid rgba(168, 85, 247, 0.7);
        transform: skew(-12deg);
    }
    .sidebar-brand-mark span {
        display: block;
        width: 3px;
        background: #5DE1FF;
        box-shadow: 0 0 7px rgba(93, 225, 255, 0.75);
    }
    .sidebar-brand-mark span:nth-child(1) { height: 10px; opacity: 0.65; }
    .sidebar-brand-mark span:nth-child(2) { height: 22px; }
    .sidebar-brand-mark span:nth-child(3) { height: 15px; background: #C084FC; }
    .sidebar-brand-name {
        color: #FFFFFF;
        font-family: "JetBrains Mono", monospace;
        font-size: 16px;
        font-weight: 800;
        letter-spacing: 0.5px;
    }
    .sidebar-brand-name b {
        color: #C084FC;
        font-size: 8px;
        letter-spacing: 1px;
        vertical-align: top;
        margin-left: 3px;
    }
    .sidebar-brand-sub {
        display: flex;
        align-items: center;
        gap: 5px;
        margin-top: 5px;
        color: #7F8AA8;
        font-family: "JetBrains Mono", monospace;
        font-size: 8px;
        letter-spacing: 0.7px;
    }
    .sidebar-brand-sub i {
        width: 5px;
        height: 5px;
        border-radius: 50%;
        background: #34D399;
        box-shadow: 0 0 8px #34D399;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > label {
        color: #7F8AA8 !important;
        font-size: 10px !important;
        font-weight: 800 !important;
        letter-spacing: 0.9px !important;
        text-transform: uppercase !important;
        margin: 0 0 8px 4px !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > div {
        gap: 7px !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > div > label {
        position: relative;
        min-height: 44px;
        box-sizing: border-box;
        display: flex !important;
        align-items: center;
        padding: 0 12px 0 18px !important;
        border: 1px solid rgba(76, 94, 150, 0.42);
        border-radius: 9px;
        background: linear-gradient(90deg, rgba(16, 22, 52, 0.92), rgba(10, 14, 34, 0.74));
        color: #C4CAE0 !important;
        overflow: hidden;
        transition: color 160ms ease, border-color 160ms ease, background 160ms ease, transform 160ms ease;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > div > label::before {
        content: "";
        position: absolute;
        left: 0;
        top: 7px;
        bottom: 7px;
        width: 3px;
        border-radius: 0 4px 4px 0;
        background: #34405F;
        transition: background 160ms ease, box-shadow 160ms ease;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > div > label::after {
        content: "";
        position: absolute;
        inset: 0;
        pointer-events: none;
        background: linear-gradient(105deg, transparent 0%, rgba(93, 225, 255, 0.06) 48%, transparent 100%);
        transform: translateX(-110%);
        transition: transform 420ms ease;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > div > label:hover {
        color: #FFFFFF !important;
        border-color: rgba(93, 225, 255, 0.55);
        background: rgba(20, 29, 63, 0.9);
        transform: translateX(2px);
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > div > label:hover::after {
        transform: translateX(110%);
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > div > label:has(input:checked) {
        color: #FFFFFF !important;
        border-color: rgba(168, 85, 247, 0.78);
        background: linear-gradient(90deg, rgba(111, 52, 194, 0.34), rgba(22, 29, 67, 0.9));
        box-shadow: inset 0 0 22px rgba(124, 58, 237, 0.13), 0 0 18px rgba(124, 58, 237, 0.12);
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > div > label:has(input:checked)::after {
        transform: translateX(110%);
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > div > label:has(input:checked)::before {
        background: #5DE1FF;
        box-shadow: 0 0 10px #5DE1FF, 0 0 18px rgba(93, 225, 255, 0.7);
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > div > label > div:first-child {
        position: relative;
        z-index: 1;
        flex-shrink: 0;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] > div > label > div:last-child {
        position: relative;
        z-index: 1;
        white-space: nowrap;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] input {
        accent-color: #5DE1FF;
    }

    /* Streamlit renders radio choices inside a role=radiogroup wrapper. */
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] {
        gap: 7px !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label {
        position: relative !important;
        display: flex !important;
        align-items: center !important;
        width: 100% !important;
        min-height: 44px !important;
        box-sizing: border-box !important;
        padding: 0 12px 0 18px !important;
        border: 1px solid rgba(76, 94, 150, 0.42) !important;
        border-radius: 9px !important;
        background: linear-gradient(90deg, rgba(16, 22, 52, 0.92), rgba(10, 14, 34, 0.74)) !important;
        color: #C4CAE0 !important;
        overflow: hidden !important;
        transition: color 160ms ease, border-color 160ms ease, background 160ms ease, transform 160ms ease !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label::before {
        content: "";
        position: absolute;
        left: 0;
        top: 7px;
        bottom: 7px;
        width: 3px;
        border-radius: 0 4px 4px 0;
        background: #34405F;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label:hover {
        color: #FFFFFF !important;
        border-color: rgba(93, 225, 255, 0.7) !important;
        background: rgba(20, 29, 63, 0.96) !important;
        transform: translateX(2px);
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked) {
        color: #FFFFFF !important;
        border-color: rgba(168, 85, 247, 0.82) !important;
        background: linear-gradient(90deg, rgba(111, 52, 194, 0.42), rgba(22, 29, 67, 0.96)) !important;
        box-shadow: inset 0 0 22px rgba(124, 58, 237, 0.16), 0 0 18px rgba(124, 58, 237, 0.14) !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked)::before {
        background: #5DE1FF;
        box-shadow: 0 0 10px #5DE1FF, 0 0 18px rgba(93, 225, 255, 0.7);
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label p {
        color: inherit !important;
        margin: 0 !important;
        font-weight: 600 !important;
    }

    /* Fallback selectors for Streamlit/BaseWeb radio markup variations. */
    [data-testid="stSidebar"] [role="radiogroup"] label {
        position: relative !important;
        display: flex !important;
        align-items: center !important;
        min-height: 44px !important;
        box-sizing: border-box !important;
        padding: 0 12px 0 18px !important;
        margin: 0 !important;
        border: 1px solid rgba(76, 94, 150, 0.42) !important;
        border-radius: 9px !important;
        background: linear-gradient(90deg, rgba(16, 22, 52, 0.94), rgba(10, 14, 34, 0.78)) !important;
        color: #C4CAE0 !important;
        overflow: hidden !important;
        transition: all 160ms ease !important;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label::before {
        content: "" !important;
        position: absolute !important;
        left: 0 !important;
        top: 6px !important;
        bottom: 6px !important;
        width: 3px !important;
        border-radius: 0 4px 4px 0 !important;
        background: #34405F !important;
        box-shadow: none !important;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label::after {
        content: "" !important;
        position: absolute !important;
        inset: 0 !important;
        pointer-events: none !important;
        background: linear-gradient(105deg, transparent 20%, rgba(93, 225, 255, 0.18) 50%, transparent 80%) !important;
        transform: translateX(-120%) !important;
        transition: transform 420ms ease !important;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label:hover {
        color: #FFFFFF !important;
        border-color: rgba(93, 225, 255, 0.78) !important;
        background: rgba(20, 29, 63, 0.98) !important;
        transform: translateX(3px) !important;
        box-shadow: 0 0 14px rgba(93, 225, 255, 0.12) !important;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label:hover::after {
        transform: translateX(120%) !important;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked),
    [data-testid="stSidebar"] [role="radiogroup"] label:has([aria-checked="true"]),
    [data-testid="stSidebar"] [role="radiogroup"] label:has([data-checked="true"]) {
        color: #FFFFFF !important;
        border-color: rgba(168, 85, 247, 0.9) !important;
        background: linear-gradient(90deg, rgba(111, 52, 194, 0.48), rgba(22, 29, 67, 0.98)) !important;
        box-shadow: inset 0 0 22px rgba(124, 58, 237, 0.18), 0 0 20px rgba(124, 58, 237, 0.2) !important;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked)::before,
    [data-testid="stSidebar"] [role="radiogroup"] label:has([aria-checked="true"])::before,
    [data-testid="stSidebar"] [role="radiogroup"] label:has([data-checked="true"])::before {
        background: #5DE1FF !important;
        box-shadow: 0 0 10px #5DE1FF, 0 0 18px rgba(93, 225, 255, 0.7) !important;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked)::after,
    [data-testid="stSidebar"] [role="radiogroup"] label:has([aria-checked="true"])::after,
    [data-testid="stSidebar"] [role="radiogroup"] label:has([data-checked="true"])::after {
        transform: translateX(120%) !important;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label p,
    [data-testid="stSidebar"] [role="radiogroup"] label span {
        position: relative !important;
        z-index: 1 !important;
        color: inherit !important;
    }

    /* Inputs and Buttons */
    .stTextInput input, .stTextArea textarea {
        background-color: #0B081A !important;
        border: 1px solid #292852 !important;
        color: #FFFFFF !important;
        border-radius: 10px !important;
    }
    .stTextInput input:focus, .stTextArea textarea:focus {
        border-color: #A855F7 !important;
    }
    .stButton button {
        background-color: #A855F7 !important;
        color: #FFFFFF !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        padding: 8px 18px !important;
    }
    .stButton button:hover {
        background-color: #7C3AED !important;
    }

    .cyber-earth-logo {
        position: relative;
        width: 44px;
        height: 44px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        color: #C084FC;
        border: 2px solid #A855F7;
        border-radius: 50%;
        background: radial-gradient(circle at 35% 30%, #5B21B6, #17133B 72%);
        box-shadow: 0 0 18px rgba(168, 85, 247, 0.32);
        overflow: hidden;
    }
    .cyber-earth-logo::before,
    .cyber-earth-logo::after {
        content: "";
        position: absolute;
        border: 1px solid rgba(216, 180, 254, 0.72);
        border-radius: 50%;
    }
    .cyber-earth-logo::before {
        width: 19px;
        height: 40px;
    }
    .cyber-earth-logo::after {
        width: 38px;
        height: 14px;
    }
    .cyber-earth-shield {
        position: absolute;
        right: -3px;
        bottom: -3px;
        z-index: 2;
        width: 23px;
        height: 26px;
        color: #FFFFFF;
        background: #A855F7;
        border: 2px solid #E9D5FF;
        clip-path: polygon(50% 0, 92% 15%, 86% 63%, 50% 100%, 14% 63%, 8% 15%);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 12px;
        font-weight: 800;
    }
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# PERSISTENT SESSION STATE
# -----------------------------------------------------------------------------
if "events_store" not in st.session_state:
    st.session_state.events_store = []

def add_event_to_store(evt):
    evt["id"] = evt.get("id", f"65ef{len(st.session_state.events_store)+1:06x}a90c")
    evt["timestamp"] = evt.get("timestamp", datetime.utcnow().isoformat())
    st.session_state.events_store.insert(0, evt)

def get_badge_html(level, score=None):
    lvl = (level or "SAFE").upper()
    cls_map = {"CRITICAL": "badge-critical", "HIGH": "badge-high", "MEDIUM": "badge-medium", "LOW": "badge-low"}
    badge_cls = cls_map.get(lvl, "badge-safe")
    score_str = f" ({score}/100)" if score is not None else ""
    return f'<span class="risk-badge {badge_cls}">{lvl}{score_str}</span>'

# -----------------------------------------------------------------------------
# TOP HEADER COMPONENT
# -----------------------------------------------------------------------------
header_col1, header_col2 = st.columns([3, 1])
with header_col1:
    st.markdown("""
    <div style="display:flex; align-items:center; gap:16px;">
        <div class="cyber-earth-logo"><span class="cyber-earth-shield">✓</span></div>
        <div>
            <div style="font-size:22px; font-weight:800; color:#FFFFFF; display:flex; align-items:center; gap:8px;">
                CYBERGUARD <span style="font-size:11px; font-family:'JetBrains Mono', monospace; background:rgba(168,85,247,0.1); color:#A855F7; border:1px solid rgba(168,85,247,0.2); padding:2px 6px; border-radius:4px;">v1.0</span>
            </div>
            <div style="font-size:12px; color:#A1A1AA; margin-top:2px;">Real-Time Autonomous Threat Detection Engine</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with header_col2:
    st.markdown("""
    <div style="display:flex; justify-content:flex-end; align-items:center; gap:10px; margin-top:6px;">
        <div style="font-size:11px; font-family:'JetBrains Mono', monospace; background:#0B081A; border:1px solid #292852; padding:6px 12px; border-radius:8px; display:flex; align-items:center; gap:6px;">
            <span style="color:#A1A1AA;">Backend API:</span>
            <span style="color:#34D399; font-weight:700;">● ONLINE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<hr style='border:0; border-top:1px solid #232730; margin:14px 0 20px 0;'>", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# TAB NAVIGATION
# -----------------------------------------------------------------------------
navigation_items = [
    "📊 Overview & Analytics",
    "🔗 URL Scanner",
    "📱 QR Phishing Scanner",
    "📧 Phishing Analyzer",
    "👤 Account Log Analyzer",
    "🎙️ Voice Analyzer",
    "🗄️ Event Inspector",
    "🔔 Alert Webhooks",
]

with st.sidebar:
    st.markdown(
        """
        <div class="sidebar-brand">
            <div class="sidebar-brand-mark"><span></span><span></span><span></span></div>
            <div>
                <div class="sidebar-brand-name">CYBERGUARD <b>V1.0</b></div>
                <div class="sidebar-brand-sub"><i></i> SECURITY OPERATIONS CENTER</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    selected_navigation = st.radio(
        "Main navigation",
        navigation_items,
        label_visibility="collapsed",
        key="main_navigation",
    )

st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

# TAB 1: OVERVIEW & ANALYTICS
if selected_navigation == navigation_items[0]:
    events = st.session_state.events_store
    total_count = len(events)
    high_crit = len([e for e in events if e.get("risk_level") in ["HIGH", "CRITICAL"]])
    latest_cat = events[0].get("threat_category", "N/A") if events else "N/A"
    active_sources = len(set(e.get("source", "system") for e in events)) if events else 1

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f'<div class="metric-panel"><div><div class="metric-title">Total Events Logged</div><div class="metric-number">{total_count}</div></div><div style="font-size:24px;">📁</div></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="metric-panel"><div><div class="metric-title">High / Critical Threats</div><div class="metric-number" style="color:#FB7185;">{high_crit}</div></div><div style="font-size:24px;">🚨</div></div>', unsafe_allow_html=True)
    with m3:
        st.markdown(f'<div class="metric-panel"><div><div class="metric-title">Latest Threat Type</div><div class="metric-number" style="font-size:15px; color:#FBBF24;">{latest_cat[:16]}</div></div><div style="font-size:24px;">⚡</div></div>', unsafe_allow_html=True)
    with m4:
        st.markdown(f'<div class="metric-panel"><div><div class="metric-title">Active Services</div><div class="metric-number" style="color:#34D399;">{active_sources}</div></div><div style="font-size:24px;">🛡️</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    chart_col1, chart_col2 = st.columns(2)
    levels = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    counts = [len([e for e in events if (e.get("risk_level") or "").upper() == lvl]) for lvl in levels]
    df_risk = pd.DataFrame({"level": levels, "count": counts})

    with chart_col1:
        st.markdown('<div class="card-panel">', unsafe_allow_html=True)
        st.markdown("<h4 style='font-size:14px; font-weight:600; color:#FFFFFF; margin-bottom:12px;'>⚠️ Risk Level Distribution</h4>", unsafe_allow_html=True)
        if HAS_PLOTLY:
            fig_bar = px.bar(
                df_risk, x="level", y="count", color="level",
                color_discrete_map={"SAFE": "#10B981", "LOW": "#3B82F6", "MEDIUM": "#F59E0B", "HIGH": "#F97316", "CRITICAL": "#F43F5E"},
            )
            fig_bar.update_layout(paper_bgcolor="#141820", plot_bgcolor="#141820", font_color="#A1A1AA", showlegend=False, margin=dict(t=10, b=10, l=10, r=10), height=260)
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.bar_chart(df_risk.set_index("level"))
        st.markdown('</div>', unsafe_allow_html=True)

    with chart_col2:
        st.markdown('<div class="card-panel">', unsafe_allow_html=True)
        st.markdown("<h4 style='font-size:14px; font-weight:600; color:#FFFFFF; margin-bottom:12px;'>⚡ Threat Frequency Timeline (24h Stream)</h4>", unsafe_allow_html=True)
        hours = [f"{i:02d}:00" for i in range(24)]
        hour_counts = [0] * 24
        for e in events:
            if e.get("timestamp"):
                try:
                    dt = datetime.fromisoformat(e["timestamp"].replace("Z", ""))
                    hour_counts[dt.hour] += 1
                except Exception:
                    pass
        df_time = pd.DataFrame({"time": hours, "count": hour_counts})
        if HAS_PLOTLY:
            fig_line = px.line(df_time, x="time", y="count", markers=True)
            fig_line.update_traces(line_color="#10B981")
            fig_line.update_layout(paper_bgcolor="#141820", plot_bgcolor="#141820", font_color="#A1A1AA", margin=dict(t=10, b=10, l=10, r=10), height=260)
            st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.line_chart(df_time.set_index("time"))
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="card-panel">', unsafe_allow_html=True)
    st.markdown("<h4 style='font-size:14px; font-weight:600; color:#FFFFFF; margin-bottom:14px;'>Recent Threat Stream (Latest 10)</h4>", unsafe_allow_html=True)
    if events:
        df_show = pd.DataFrame(events[:10])[["id", "timestamp", "threat_category", "risk_level", "risk_score", "source"]]
        st.dataframe(df_show, use_container_width=True, hide_index=True)
    else:
        st.markdown("<div style='text-align:center; padding:30px; color:#A1A1AA; font-size:13px;'>No threat events logged yet. Use the scanner tabs above to test!</div>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# TAB 2: URL SCANNER
if selected_navigation == navigation_items[1]:
    st.markdown('<div class="card-panel">', unsafe_allow_html=True)
    st.markdown("""
    <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
        <div style="padding:8px; background:rgba(59,158,255,0.1); border:1px solid rgba(59,158,255,0.2); border-radius:10px; font-size:20px;">🔗</div>
        <div>
            <h3 style="font-size:17px; font-weight:700; color:#FFFFFF; margin:0;">Live URL Reputation Scanner</h3>
            <p style="font-size:12px; color:#A1A1AA; margin:0;">Inspects target domains against Google Safe Browsing and local blocklists.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    url_val = st.text_input(
        "Target URL:",
        placeholder="e.g. http://phishingsite.com or https://example.com",
        label_visibility="collapsed",
        key="url_scanner_input",
    )
    if st.button("Scan URL Reputation", type="primary"):
        normalized_url = url_val.strip()
        if normalized_url:
            with st.spinner("Scanning URL Reputation..."):
                try:
                    res = analyze_url(normalized_url)
                except ValueError as exc:
                    st.session_state.pop("last_url_result", None)
                    st.session_state.pop("last_url_input", None)
                    st.warning(str(exc))
                else:
                    add_event_to_store(res)
                    st.session_state["last_url_result"] = res
                    st.session_state["last_url_input"] = normalized_url
        else:
            st.session_state.pop("last_url_result", None)
            st.session_state.pop("last_url_input", None)
            st.warning("Please enter a valid URL.")
    st.markdown('</div>', unsafe_allow_html=True)

    try:
        _validate_url(url_val)
        current_url_is_valid = True
    except ValueError:
        current_url_is_valid = False

    if (
        current_url_is_valid
        and "last_url_result" in st.session_state
        and st.session_state.get("last_url_input") == url_val.strip()
    ):
        res = st.session_state["last_url_result"]
        st.markdown('<div class="card-panel">', unsafe_allow_html=True)
        st.markdown(f'<div style="font-size:11px; font-family:\'JetBrains Mono\', monospace; color:#A1A1AA; text-transform:uppercase;">Analysis Result</div><div style="font-size:20px; font-weight:700; color:#FFFFFF; margin-top:4px;">Verdict: {get_badge_html(res["risk_level"], res["risk_score"])}</div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:8px;'>Detected Threat Evidence</h5>", unsafe_allow_html=True)
        if res.get("evidence"):
            for item in res["evidence"]:
                st.markdown(f'<div class="evidence-item"><span style="color:#FB7185; font-weight:700;">{item["name"]}</span><span style="color:#A1A1AA;">Weight: +{item["value"]}</span></div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.2); padding:12px; border-radius:8px; color:#34D399; font-size:12px;">✅ No malicious domain hits or Google Safe Browsing flags detected.</div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        if res.get("recommendations"):
            st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:8px;'>Recommended Actions</h5>", unsafe_allow_html=True)
            for rec in res["recommendations"]:
                st.markdown(f'<div class="rec-item"><span class="rec-dot"></span><span>{rec}</span></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# TAB 3: QR PHISHING SCANNER
if selected_navigation == navigation_items[2]:
    st.markdown('<div class="card-panel">', unsafe_allow_html=True)
    st.markdown("""
    <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
        <div style="padding:8px; background:rgba(59,158,255,0.1); border:1px solid rgba(59,158,255,0.2); border-radius:10px; font-size:20px;">📱</div>
        <div>
            <h3 style="font-size:17px; font-weight:700; color:#FFFFFF; margin:0;">QR-Code Phishing Scanner</h3>
            <p style="font-size:12px; color:#A1A1AA; margin:0;">Decode a QR destination and inspect it for malicious links, redirects, and impersonation.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    qr_input_mode = st.radio(
        "QR image source",
        ["Upload image", "Use camera"],
        horizontal=True,
        key="qr_input_mode",
    )
    if qr_input_mode == "Use camera":
        qr_image = st.camera_input(
            "Capture a QR code",
            key="qr_camera_capture",
        )
        qr_filename = "camera_qr_capture.png"
    else:
        qr_image = st.file_uploader(
            "Upload a QR-code image",
            type=["png", "jpg", "jpeg", "webp"],
            key="qr_image_upload",
        )
        qr_filename = qr_image.name if qr_image is not None else "uploaded_qr_image"

    camera_capture_hash = None
    if qr_image is not None:
        camera_capture_hash = hashlib.sha256(qr_image.getvalue()).hexdigest()
        if qr_input_mode == "Use camera":
            st.caption("Capture received. Searching the image for a QR code automatically...")
        else:
            st.caption("Image ready. Scan it to decode the destination and check its reputation.")

    should_scan_qr = qr_image is not None and (
        qr_input_mode == "Use camera"
        or st.button("Scan QR Code", type="primary")
    )
    is_new_camera_capture = (
        qr_input_mode == "Use camera"
        and camera_capture_hash
        != st.session_state.get("last_qr_capture_hash")
    )
    if is_new_camera_capture:
        st.session_state["last_qr_capture_hash"] = camera_capture_hash

    if should_scan_qr and (qr_input_mode != "Use camera" or is_new_camera_capture):
        with st.spinner("Decoding and analyzing QR destination..."):
            try:
                qr_result = analyze_qr_image(qr_image.getvalue(), qr_filename)
            except (ValueError, RuntimeError) as exc:
                st.session_state.pop("last_qr_result", None)
                st.error(str(exc))
            else:
                add_event_to_store(qr_result)
                st.session_state["last_qr_result"] = qr_result
    st.markdown('</div>', unsafe_allow_html=True)

    if "last_qr_result" in st.session_state:
        res = st.session_state["last_qr_result"]
        if HAS_PLOTLY:
            risk_score = max(0, min(100, int(res.get("risk_score", 0))))
            risk_level = (res.get("risk_level") or "SAFE").upper()
            risk_colors = {
                "SAFE": "#10B981",
                "LOW": "#3B82F6",
                "MEDIUM": "#F59E0B",
                "HIGH": "#F97316",
                "CRITICAL": "#F43F5E",
            }
            fig_qr_risk = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_score,
                number={"suffix": "/100", "font": {"color": "#FFFFFF", "size": 28}},
                title={"text": f"QR RISK SCORE | {risk_level}", "font": {"color": "#A1A1AA", "size": 11}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#71717A", "tickfont": {"color": "#A1A1AA"}},
                    "bar": {"color": risk_colors.get(risk_level, "#A855F7")},
                    "bgcolor": "#0B081A",
                    "bordercolor": "#292852",
                    "steps": [
                        {"range": [0, 30], "color": "rgba(16,185,129,0.18)"},
                        {"range": [30, 50], "color": "rgba(59,130,246,0.18)"},
                        {"range": [50, 70], "color": "rgba(245,158,11,0.18)"},
                        {"range": [70, 90], "color": "rgba(249,115,22,0.18)"},
                        {"range": [90, 100], "color": "rgba(244,63,94,0.18)"},
                    ],
                },
            ))
            fig_qr_risk.update_layout(
                paper_bgcolor="#11152F",
                plot_bgcolor="#11152F",
                height=220,
                margin=dict(t=48, b=10, l=28, r=28),
                font_color="#FFFFFF",
            )
            st.plotly_chart(fig_qr_risk, use_container_width=True, config={"displayModeBar": False})
        st.markdown('<div class="card-panel">', unsafe_allow_html=True)
        st.markdown(f'<div style="font-size:11px; font-family:\'JetBrains Mono\', monospace; color:#A1A1AA; text-transform:uppercase;">QR Analysis Result</div><div style="font-size:20px; font-weight:700; color:#FFFFFF; margin-top:4px;">Verdict: {get_badge_html(res["risk_level"], res["risk_score"])}</div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        for item in res.get("evidence", []):
            st.markdown(f'<div class="evidence-item"><span style="color:#FB7185; font-weight:700;">{item["name"]}</span><span style="color:#A1A1AA;">{item["value"]}</span></div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

# TAB 4: PHISHING ANALYZER
if selected_navigation == navigation_items[3]:
    st.markdown("""
    <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
        <div style="padding:8px; background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.2); border-radius:10px; font-size:20px;">📧</div>
        <div>
            <h3 style="font-size:17px; font-weight:700; color:#FFFFFF; margin:0;">Phishing Text & Email Analyzer</h3>
            <p style="font-size:12px; color:#A1A1AA; margin:0;">Detects social engineering, urgency cues, and credential solicitation patterns.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    header_mode = st.checkbox("Raw Email Header Mode", value=False)
    p_ph = "Paste raw email headers here (SPF, DKIM, DMARC)..." if header_mode else "Paste email content or suspicious SMS text here..."
    communication_context = {}
    with st.expander("Communication context (optional)"):
        sender_email = st.text_input("Sender email", placeholder="sender@example.com")
        expected_sender_domain = st.text_input("Expected sender domain", placeholder="company.com")
        reply_to_email = st.text_input("Reply-to email", placeholder="support@example.com")
        context_col1, context_col2 = st.columns(2)
        with context_col1:
            sent_hour = st.number_input("Sent hour (0-23)", min_value=0, max_value=23, value=12)
            recent_message_count = st.number_input("Messages in recent period", min_value=0, value=0)
        with context_col2:
            usual_hours_text = st.text_input("Usual hours", placeholder="9,10,11,12,13,14,15,16,17")
            typical_message_count = st.number_input("Typical messages in period", min_value=0, value=0)
        new_sender = st.checkbox("Sender is new or unrecognized")
        sender_domain = sender_email.rsplit("@", 1)[-1].strip().lower() if "@" in sender_email else ""
        try:
            usual_hours = [int(hour.strip()) for hour in usual_hours_text.split(",") if hour.strip()]
        except ValueError:
            usual_hours = []
            st.warning("Usual hours must be comma-separated numbers from 0 to 23.")
        communication_context = {
            "sender_domain": sender_domain,
            "expected_sender_domain": expected_sender_domain.strip().lower(),
            "reply_to_email": reply_to_email.strip().lower(),
            "sent_hour": sent_hour,
            "usual_hours": usual_hours,
            "recent_message_count": recent_message_count,
            "typical_message_count": typical_message_count,
            "new_sender": new_sender,
        }
    p_text = st.text_area("Input Content:", placeholder=p_ph, height=140, label_visibility="collapsed")
    if st.button("Analyze Phishing Traits", type="primary"):
        if p_text.strip():
            with st.spinner("Analyzing Content..."):
                res = analyze_phishing_text(p_text.strip(), communication_context)
                add_event_to_store(res)
                st.session_state["last_phish_result"] = res
        else:
            st.warning("Please paste email or message content.")
    if "last_phish_result" in st.session_state:
        res = st.session_state["last_phish_result"]
        if HAS_PLOTLY:
            risk_score = max(0, min(100, int(res.get("risk_score", 0))))
            risk_level = (res.get("risk_level") or "SAFE").upper()
            risk_colors = {
                "SAFE": "#10B981",
                "LOW": "#3B82F6",
                "MEDIUM": "#F59E0B",
                "HIGH": "#F97316",
                "CRITICAL": "#F43F5E",
            }
            fig_risk = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_score,
                number={"suffix": "/100", "font": {"color": "#FFFFFF", "size": 28}},
                title={"text": f"PHISHING RISK | {risk_level}", "font": {"color": "#A1A1AA", "size": 11}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#71717A", "tickfont": {"color": "#A1A1AA"}},
                    "bar": {"color": risk_colors.get(risk_level, "#A855F7")},
                    "bgcolor": "#0B081A",
                    "bordercolor": "#292852",
                    "steps": [
                        {"range": [0, 30], "color": "rgba(16,185,129,0.18)"},
                        {"range": [30, 50], "color": "rgba(59,130,246,0.18)"},
                        {"range": [50, 70], "color": "rgba(245,158,11,0.18)"},
                        {"range": [70, 90], "color": "rgba(249,115,22,0.18)"},
                        {"range": [90, 100], "color": "rgba(244,63,94,0.18)"},
                    ],
                },
            ))
            fig_risk.update_layout(
                paper_bgcolor="#11152F",
                plot_bgcolor="#11152F",
                height=220,
                margin=dict(t=48, b=10, l=28, r=28),
                font_color="#FFFFFF",
            )
            st.plotly_chart(fig_risk, use_container_width=True, config={"displayModeBar": False})
        st.markdown('<div class="card-panel">', unsafe_allow_html=True)
        st.markdown(f'<div style="font-size:11px; font-family:\'JetBrains Mono\', monospace; color:#A1A1AA; text-transform:uppercase;">Phishing Risk Assessment</div><div style="font-size:20px; font-weight:700; color:#FFFFFF; margin-top:4px;">Verdict: {get_badge_html(res["risk_level"], res["risk_score"])}</div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:8px;'>Social Engineering Indicators</h5>", unsafe_allow_html=True)
        if res.get("evidence"):
            for item in res["evidence"]:
                st.markdown(f'<div class="evidence-item"><span style="color:#FBBF24; font-weight:700;">{item["name"]}</span><span style="color:#A1A1AA;">Weight: +{item["value"]}</span></div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.2); padding:12px; border-radius:8px; color:#34D399; font-size:12px;">✅ No overt phishing keywords or social engineering triggers identified.</div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        if res.get("recommendations"):
            st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:8px;'>Recommendations</h5>", unsafe_allow_html=True)
            for rec in res["recommendations"]:
                st.markdown(f'<div class="rec-item"><span class="rec-dot"></span><span>{rec}</span></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# TAB 5: ACCOUNT ANALYZER
if selected_navigation == navigation_items[4]:
    st.markdown('<div class="card-panel">', unsafe_allow_html=True)
    st.markdown("""
    <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
        <div style="padding:8px; background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.2); border-radius:10px; font-size:20px;">👤</div>
        <div>
            <h3 style="font-size:17px; font-weight:700; color:#FFFFFF; margin:0;">Account Authentication Log Analyzer</h3>
            <p style="font-size:12px; color:#A1A1AA; margin:0;">Inspects login attempt patterns for brute-force attacks, AbuseIPDB, or impossible travel anomalies.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    default_log = "\n".join([
        "2026-01-01T00:00:00 alice 1.1.1.1 nyc success",
        "2026-01-01T01:00:00 alice 3.3.3.3 tokyo success",
        "2026-01-01T01:05:00 attacker 192.168.1.100 failed",
        "2026-01-01T01:06:00 attacker 192.168.1.100 failed",
        "2026-01-01T01:07:00 attacker 192.168.1.100 failed",
        "2026-01-01T01:08:00 attacker 192.168.1.100 failed",
        "2026-01-01T01:09:00 attacker 192.168.1.100 failed"
    ])
    log_text = st.text_area("Authentication Log Stream:", value=default_log, height=140, label_visibility="collapsed")
    if st.button("Analyze Authentication Log", type="primary"):
        if log_text.strip():
            with st.spinner("Analyzing Log Entries..."):
                res = analyze_account_log(log_text.strip())
                add_event_to_store(res)
                st.session_state["last_acc_result"] = res
        else:
            st.warning("Please paste auth logs.")
    st.markdown('</div>', unsafe_allow_html=True)

    if "last_acc_result" in st.session_state:
        res = st.session_state["last_acc_result"]
        st.markdown('<div class="card-panel">', unsafe_allow_html=True)
        st.markdown(f'<div style="font-size:11px; font-family:\'JetBrains Mono\', monospace; color:#A1A1AA; text-transform:uppercase;">Account Risk Verdict</div><div style="font-size:20px; font-weight:700; color:#FFFFFF; margin-top:4px;">Verdict: {get_badge_html(res["risk_level"], res["risk_score"])}</div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:8px;'>Suspicious Log Evidence</h5>", unsafe_allow_html=True)
        if res.get("evidence"):
            for item in res["evidence"]:
                st.markdown(f'<div class="evidence-item"><span style="color:#FB7185; font-weight:700;">{item["name"]}</span><span style="color:#A1A1AA;">Weight: +{item["value"]}</span></div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.2); padding:12px; border-radius:8px; color:#34D399; font-size:12px;">✅ Authentication pattern appears normal. No brute-force or malicious log indicators detected.</div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        if res.get("recommendations"):
            st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:8px;'>Security Guidelines</h5>", unsafe_allow_html=True)
            for rec in res["recommendations"]:
                st.markdown(f'<div class="rec-item"><span class="rec-dot"></span><span>{rec}</span></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# TAB 6: VOICE ANALYZER
if selected_navigation == navigation_items[5]:
    def reset_voice_analyzer():
        """Clear voice inputs, cached result, and derived display state."""
        for state_key in (
            "voice_upload",
            "voice_recording",
            "last_voice_result",
            "last_voice_file_key",
            "last_audio_bytes",
        ):
            st.session_state.pop(state_key, None)

    st.markdown('<div class="card-panel">', unsafe_allow_html=True)
    st.markdown("""
    <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
        <div style="padding:8px; background:rgba(168,85,247,0.1); border:1px solid rgba(168,85,247,0.2); border-radius:10px; font-size:20px;">🎙️</div>
        <div>
            <h3 style="font-size:17px; font-weight:700; color:#FFFFFF; margin:0;">AI Voice & Vishing Detector</h3>
            <p style="font-size:12px; color:#A1A1AA; margin:0;">Upload a voice recording to detect AI-synthesized speech, deepfakes, or vishing attempts.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    profile_col, language_col = st.columns([1, 1])
    with profile_col:
        selected_profile = st.selectbox(
            "Transcription profile",
            list(TRANSCRIPTION_PROFILES),
            index=3,
            key="voice_transcription_profile",
            help="Low is recommended for Streamlit Cloud. Hyper and Base models need substantially more memory and download time.",
        )
    with language_col:
        selected_language = st.selectbox(
            "Speech language",
            [("Auto detect", "auto"), ("English", "en"), ("Hindi", "hi"), ("Spanish", "es"), ("French", "fr"), ("German", "de")],
            format_func=lambda option: option[0],
            key="voice_transcription_language",
        )[1]
    selected_profile_details = TRANSCRIPTION_PROFILES[selected_profile]
    st.caption(
        f"{selected_profile_details['accuracy']} | {selected_profile_details['duration']} | "
        f"{selected_profile_details['description']}"
    )
    if selected_profile != "Low - Tiny":
        st.info("Larger Whisper models can exceed Streamlit Cloud memory limits. Use Low - Tiny for the most reliable deployment performance.")
    input_col, reset_col = st.columns([5, 1])
    with input_col:
        audio_file = st.file_uploader(
            "Upload Voice Recording (WAV, MP3, OGG, M4A, FLAC):",
            type=["wav", "mp3", "ogg", "m4a", "flac", "webm"],
            key="voice_upload",
        )
        recorded_audio = st.audio_input("Or record a voice sample", key="voice_recording")
    with reset_col:
        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
        st.button("Reset", key="reset_voice", on_click=reset_voice_analyzer, use_container_width=True)

    selected_audio = recorded_audio or audio_file
    if selected_audio is not None:
        st.audio(selected_audio)
        audio_bytes = selected_audio.getvalue()
        audio_name = selected_audio.name or "recorded_voice.wav"
        analysis_key = f"{hashlib.sha256(audio_bytes).hexdigest()}:{selected_profile_details['model']}:{selected_language}"
        if st.button("Analyze Voice Recording", type="primary"):
            with st.spinner("Analyzing Audio Recording..."):
                res = analyze_uploaded_voice(
                    audio_name,
                    audio_bytes,
                    model_name=selected_profile_details["model"],
                    language=selected_language,
                )
                add_event_to_store(res)
                st.session_state["last_voice_result"] = dict(res)
                st.session_state["last_voice_file_key"] = analysis_key
                if "transcription unavailable:" in res.get("source", ""):
                    st.warning("Voice classification completed, but transcription is unavailable in this deployment.")
                st.success("Voice analysis complete")
                result_cols = st.columns(4)
                result_cols[0].metric("Verdict", res.get("voice_verdict", "N/A"))
                result_cols[1].metric("AI confidence", f"{res.get('voice_confidence', 0)}%")
                result_cols[2].metric("Scam score", f"{res.get('scam_score', 0)}/100")
                result_cols[3].metric("Risk", f"{res.get('risk_level', 'SAFE')} ({res.get('risk_score', 0)}/100)")
                # Save raw audio bytes for waveform rendering
                try:
                    st.session_state["last_audio_bytes"] = audio_bytes
                except Exception:
                    pass

        # Restore the cached result after any Streamlit rerun or app refresh.
        if st.session_state.get("last_voice_file_key") != analysis_key:
            with st.spinner("Preparing voice analysis results..."):
                res = analyze_uploaded_voice(
                    audio_name,
                    audio_bytes,
                    model_name=selected_profile_details["model"],
                    language=selected_language,
                )
            add_event_to_store(res)
            st.session_state["last_voice_result"] = dict(res)
            st.session_state["last_voice_file_key"] = analysis_key
            st.rerun()

        # ---------------------------------------------------------------------
        # AUDIO WAVEFORM & SPECTROGRAM GRAPHS UNDER ANALYZE BUTTON
        # ---------------------------------------------------------------------
        st.markdown("<br>", unsafe_allow_html=True)
        if HAS_LIBROSA and HAS_PLOTLY:
            try:
                audio_file.seek(0)
                raw_bytes = audio_file.read()
                y, sr = librosa.load(io.BytesIO(raw_bytes), sr=None)
                duration = len(y) / sr
                time_axis = np.linspace(0, duration, len(y))
                downsample = max(1, len(y) // 1500)
                t_sub = time_axis[::downsample]
                y_sub = y[::downsample]

                # Graphical Waveform Representation
                fig_wave = go.Figure()
                fig_wave.add_trace(go.Scatter(
                    x=t_sub, y=y_sub, mode="lines",
                    line=dict(color="#38BDF8", width=1.5),
                    fill="tozeroy", fillcolor="rgba(56, 189, 248, 0.15)",
                    name="Signal Amplitude"
                ))
                fig_wave.update_layout(
                    title="🌊 Input Voice Signal Waveform (Amplitude vs. Time)",
                    xaxis_title="Time (seconds)",
                    yaxis_title="Amplitude",
                    paper_bgcolor="#141820",
                    plot_bgcolor="#141820",
                    font_color="#F8FAFC",
                    height=200,
                    margin=dict(t=35, b=25, l=25, r=25)
                )
                st.plotly_chart(fig_wave, use_container_width=True)

                # Frequency Spectrogram Representation
                D = librosa.amplitude_to_db(np.abs(librosa.stft(y)), ref=np.max)
                freq_bins = np.linspace(0, sr / 2, D.shape[0])
                time_bins = np.linspace(0, duration, D.shape[1])

                fig_spec = go.Figure(data=go.Heatmap(
                    z=D[::2, ::2], x=time_bins[::2], y=freq_bins[::2],
                    colorscale="Viridis",
                    colorbar=dict(title="dB")
                ))
                fig_spec.update_layout(
                    title="📡 Input Voice Spectral Density (Spectrogram)",
                    xaxis_title="Time (seconds)",
                    yaxis_title="Frequency (Hz)",
                    paper_bgcolor="#141820",
                    plot_bgcolor="#141820",
                    font_color="#F8FAFC",
                    height=220,
                    margin=dict(t=35, b=25, l=25, r=25)
                )
                st.plotly_chart(fig_spec, use_container_width=True)
            except Exception as e:
                pass
    st.markdown('</div>', unsafe_allow_html=True)

    if "last_voice_result" in st.session_state:
        res = st.session_state["last_voice_result"]
        st.markdown('<div class="card-panel">', unsafe_allow_html=True)
        st.markdown(f'<div style="font-size:11px; font-family:\'JetBrains Mono\', monospace; color:#A1A1AA; text-transform:uppercase;">Voice Threat Verdict</div><div style="font-size:20px; font-weight:700; color:#FFFFFF; margin-top:4px;">Risk Level: {get_badge_html(res["risk_level"], res["risk_score"])}</div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        st.subheader("Voice analysis results")
        result_cols = st.columns(4)
        result_cols[0].metric("Verdict", res.get("voice_verdict", "N/A"))
        result_cols[1].metric("AI confidence", f"{res.get('voice_confidence', 0)}%")
        result_cols[2].metric("Scam score", f"{res.get('scam_score', 0)}/100")
        result_cols[3].metric("Risk", f"{res.get('risk_level', 'SAFE')} ({res.get('risk_score', 0)}/100)")
        acoustic_features = res.get("acoustic_features") or {}
        if acoustic_features:
            feature_specs = [
                ("duration_sec", "Duration", "sec", "#38BDF8"),
                ("f0_mean_hz", "Fundamental pitch mean", "Hz", "#818CF8"),
                ("f0_std_hz", "Pitch variation (std)", "Hz", "#C084FC"),
                ("f0_jitter", "Pitch jitter", "ratio", "#F472B6"),
                ("voicing_ratio", "Voicing ratio", "%", "#34D399"),
                ("spectral_centroid_hz", "Spectral centroid", "Hz", "#FBBF24"),
                ("spectral_bandwidth_hz", "Spectral bandwidth", "Hz", "#FB923C"),
                ("spectral_flatness", "Spectral flatness", "index", "#F87171"),
                ("spectral_rolloff_hz", "Spectral rolloff frequency", "Hz", "#E879F9"),
                ("zcr_mean", "Zero crossing rate", "zcr", "#A7F3D0"),
                ("rms_energy", "RMS energy intensity", "rms", "#67E8F9"),
            ]
            feature_cards = []
            for feature_name, feature_label, feature_unit, feature_color in feature_specs:
                if feature_name not in acoustic_features:
                    continue
                feature_value = acoustic_features[feature_name]
                if feature_unit == "%":
                    display_value = f"{float(feature_value) * 100:.1f}"
                else:
                    display_value = f"{float(feature_value):.4f}"
                feature_cards.append(
                    f'<div class="acoustic-card" style="--feature-color:{feature_color}">'
                    f'<div class="acoustic-label">{feature_label}</div>'
                    f'<div class="acoustic-value">{display_value}<span class="acoustic-unit">{feature_unit}</span></div>'
                    "</div>"
                )
            st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin:20px 0 8px;'>Acoustic Feature Matrix</h5>", unsafe_allow_html=True)
            st.markdown(f'<div class="acoustic-grid">{"".join(feature_cards)}</div>', unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns(4)
        c1.markdown(f'<div class="metric-panel"><div><div class="metric-title">Voice Verdict</div><div class="metric-number" style="font-size:16px; color:#FB7185;">{res.get("voice_verdict", "N/A")}</div></div></div>', unsafe_allow_html=True)
        c2.markdown(f'<div class="metric-panel"><div><div class="metric-title">AI Confidence</div><div class="metric-number">{res.get("voice_confidence", 0)}%</div></div></div>', unsafe_allow_html=True)
        c3.markdown(f'<div class="metric-panel"><div><div class="metric-title">Scam Score</div><div class="metric-number" style="color:#FBBF24;">{res.get("scam_score", 0)}/100</div></div></div>', unsafe_allow_html=True)
        c4.markdown(f'<div class="metric-panel"><div><div class="metric-title">Category</div><div class="metric-number" style="font-size:13px; color:#3B9EFF;">{res.get("threat_category", "N/A")}</div></div></div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        p_col1, p_col2 = st.columns([1.2, 1])
        with p_col1:
            st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:8px;'>Speech Authenticity Breakdown (AI vs. Human)</h5>", unsafe_allow_html=True)
            ai_prob = next(
                (item.get("value", 50) for item in res.get("evidence", []) if item.get("name") == "AI probability"),
                50,
            )
            ai_prob = max(0, min(100, float(ai_prob)))
            human_prob = max(0, 100 - ai_prob)
            if HAS_PLOTLY:
                fig_donut = px.pie(
                    names=["AI Generated", "Human Genuine"], values=[ai_prob, human_prob], hole=0.55,
                    color=["AI Generated", "Human Genuine"], color_discrete_map={"AI Generated": "#F43F5E", "Human Genuine": "#10B981"}
                )
                fig_donut.update_traces(textinfo="percent+label", hoverinfo="label+value")
                fig_donut.update_layout(paper_bgcolor="#141820", font_color="#FFFFFF", showlegend=True, margin=dict(t=20, b=20, l=20, r=20), height=260)
                st.plotly_chart(fig_donut, use_container_width=True)
        with p_col2:
            if res.get("transcript"):
                st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:8px;'>Audio Transcript</h5>", unsafe_allow_html=True)
                st.markdown(f'<div style="background:#0B081A; border:1px solid #292852; padding:16px; border-radius:10px; font-style:italic; font-family:\'JetBrains Mono\', monospace; color:#E2E8F0; font-size:12px; line-height:1.6;">"{res["transcript"]}"</div>', unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:8px;'>Acoustic Evidence</h5>", unsafe_allow_html=True)
            for item in res.get("evidence", []):
                st.markdown(f'<div class="evidence-item"><span style="color:#FB7185; font-weight:700;">{item["name"]}</span><span style="color:#A1A1AA;">Weight: +{item["value"]}</span></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# TAB 7: EVENT INSPECTOR
if selected_navigation == navigation_items[6]:
    st.markdown('<div class="card-panel">', unsafe_allow_html=True)
    st.markdown("""
    <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:16px;">
        <div style="display:flex; align-items:center; gap:12px;">
            <div style="padding:8px; background:rgba(59,158,255,0.1); border:1px solid rgba(59,158,255,0.2); border-radius:10px; font-size:20px;">🗄️</div>
            <div>
                <h3 style="font-size:17px; font-weight:700; color:#FFFFFF; margin:0;">Threat Event Deep Inspector</h3>
                <p style="font-size:12px; color:#A1A1AA; margin:0;">Inspect detailed ThreatEvent document schemas and generate AI root-cause analysis.</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    events = st.session_state.events_store
    if events:
        event_options = {f"{e['id']} — {e.get('threat_category', 'EVENT')} [{e.get('risk_level', 'UNKNOWN')}]": e for e in events}
        selected_label = st.selectbox("Select Event ID:", list(event_options.keys()))
        selected_evt = event_options[selected_label]
        st.markdown("<div style='font-size:11px; font-family:monospace; color:#A1A1AA; margin-bottom:4px;'>💻 RAW ThreatEvent Payload</div>", unsafe_allow_html=True)
        st.json(selected_evt)
        st.markdown("<br>", unsafe_allow_html=True)
        csv_out = io.StringIO()
        writer = csv.writer(csv_out)
        writer.writerow(["ID", "Timestamp", "Category", "Risk Level", "Risk Score", "Source", "Evidence Count"])
        for e in events:
            writer.writerow([e.get("id"), e.get("timestamp"), e.get("threat_category"), e.get("risk_level"), e.get("risk_score"), e.get("source"), len(e.get("evidence", []))])
        st.download_button(
            label="📥 Export Security Events CSV",
            data=csv_out.getvalue(),
            file_name="cyberguard_events_report.csv",
            mime="text/csv",
            type="primary"
        )
    else:
        st.markdown("<div style='text-align:center; padding:30px; color:#A1A1AA; font-size:13px;'>No logged threat events available in the system yet. Run scans using the other tabs first!</div>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# TAB 8: ALERT WEBHOOKS
if selected_navigation == navigation_items[7]:
    st.markdown('<div class="card-panel">', unsafe_allow_html=True)
    st.markdown("""
    <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
        <div style="padding:8px; background:rgba(244,63,94,0.1); border:1px solid rgba(244,63,94,0.2); border-radius:10px; font-size:20px;">🔔</div>
        <div>
            <h3 style="font-size:17px; font-weight:700; color:#FFFFFF; margin:0;">Real-Time Threat Alerting & Webhooks</h3>
            <p style="font-size:12px; color:#A1A1AA; margin:0;">Configure Slack, Discord, or custom HTTP POST webhooks for HIGH/CRITICAL incident alerts.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    wh_url = st.text_input("Webhook Endpoint URL:", placeholder="e.g. https://hooks.slack.com/services/... or https://discord.com/api/webhooks/...")
    if st.button("Dispatch Test Alert", type="primary"):
        if wh_url.strip():
            with st.spinner("Sending Test Alert..."):
                test_evt = {
                    "id": "65efa123test",
                    "threat_category": "MALICIOUS_URL",
                    "risk_score": 90,
                    "risk_level": "CRITICAL",
                    "source": "webhook_test",
                    "recommendations": ["Verify target URL in sandbox", "Block domain on firewall"]
                }
                success = send_threat_alert(test_evt, target_webhook=wh_url.strip())
                if success:
                    st.success(f"✅ Test alert successfully sent to {wh_url.strip()}")
                else:
                    st.error(f"❌ Failed to deliver alert to {wh_url.strip()}. Verify URL.")
        else:
            st.warning("Please enter a webhook URL.")
    st.markdown('</div>', unsafe_allow_html=True)

# Footer
st.markdown("""
<div style="text-align:center; padding:24px 0 10px 0; border-top:1px solid #232730; font-size:12px; color:#71717A;">
    CYBERGUARD Enterprise Security System — Real-time Autonomous Threat Monitoring Engine
</div>
""", unsafe_allow_html=True)
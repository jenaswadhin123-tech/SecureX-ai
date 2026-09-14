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
from cyberguard.backend.services.url_service import analyze_url
from cyberguard.backend.services.phishing_service import analyze_phishing_text
from cyberguard.backend.services.account_service import analyze_account_log
from cyberguard.backend.services.explanation_service import generate_explanation
from cyberguard.backend.services.webhook_service import send_threat_alert

# Page Configuration
st.set_page_config(
    page_title="CYBERGUARD — Autonomous Threat Detection Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# -----------------------------------------------------------------------------
# EXACT REACT CYBERGUARD THEME (Tailwind CSS matching palette)
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    @import url("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap");

    html, body, [class*="css"], .stApp {
        font-family: "Inter", sans-serif !important;
        background-color: #0B0E14 !important;
        color: #F5F5F5 !important;
    }

    /* Cards */
    .card-panel {
        background-color: #141820;
        border: 1px solid #232730;
        border-radius: 14px;
        padding: 24px;
        margin-bottom: 20px;
    }
    .metric-panel {
        background-color: #141820;
        border: 1px solid #232730;
        border-radius: 12px;
        padding: 18px 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .metric-title {
        font-size: 11px;
        font-weight: 600;
        color: #A1A1AA;
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
        background: #0B0E14;
        border: 1px solid #232730;
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
        background-color: #3B9EFF;
        border-radius: 50%;
        flex-shrink: 0;
    }

    /* AI Explanation Box */
    .ai-box {
        background-color: #0B0E14;
        border: 1px solid rgba(59, 158, 255, 0.3);
        border-radius: 12px;
        padding: 16px;
        margin-top: 16px;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #232730;
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
        color: #3B9EFF !important;
        font-weight: 700 !important;
        border-bottom: 2px solid #3B9EFF !important;
        background-color: rgba(59, 158, 255, 0.05) !important;
    }

    /* Inputs and Buttons */
    .stTextInput input, .stTextArea textarea {
        background-color: #0B0E14 !important;
        border: 1px solid #232730 !important;
        color: #FFFFFF !important;
        border-radius: 10px !important;
    }
    .stTextInput input:focus, .stTextArea textarea:focus {
        border-color: #3B9EFF !important;
    }
    .stButton button {
        background-color: #3B9EFF !important;
        color: #FFFFFF !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        padding: 8px 18px !important;
    }
    .stButton button:hover {
        background-color: #2563EB !important;
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
        <div style="padding:10px; background:rgba(59,158,255,0.1); border:1px solid rgba(59,158,255,0.2); border-radius:12px; font-size:24px;">🛡️</div>
        <div>
            <div style="font-size:22px; font-weight:800; color:#FFFFFF; display:flex; align-items:center; gap:8px;">
                CYBERGUARD <span style="font-size:11px; font-family:'JetBrains Mono', monospace; background:rgba(59,158,255,0.1); color:#3B9EFF; border:1px solid rgba(59,158,255,0.2); padding:2px 6px; border-radius:4px;">v1.0</span>
            </div>
            <div style="font-size:12px; color:#A1A1AA; margin-top:2px;">Real-Time Autonomous Threat Detection Engine</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with header_col2:
    st.markdown("""
    <div style="display:flex; justify-content:flex-end; align-items:center; gap:10px; margin-top:6px;">
        <div style="font-size:11px; font-family:'JetBrains Mono', monospace; background:#0B0E14; border:1px solid #232730; padding:6px 12px; border-radius:8px; display:flex; align-items:center; gap:6px;">
            <span style="color:#A1A1AA;">Backend API:</span>
            <span style="color:#34D399; font-weight:700;">● ONLINE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<hr style='border:0; border-top:1px solid #232730; margin:14px 0 20px 0;'>", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# TAB NAVIGATION
# -----------------------------------------------------------------------------
tabs = st.tabs([
    "📊 Overview & Analytics",
    "🔗 URL Scanner",
    "📧 Phishing Analyzer",
    "👤 Account Log Analyzer",
    "🎙️ Voice Analyzer",
    "🗄️ Event Inspector",
    "🔔 Alert Webhooks",
])

# TAB 1: OVERVIEW & ANALYTICS
with tabs[0]:
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
with tabs[1]:
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
    url_val = st.text_input("Target URL:", placeholder="e.g. http://phishingsite.com or https://example.com", label_visibility="collapsed")
    if st.button("Scan URL Reputation", type="primary"):
        if url_val.strip():
            with st.spinner("Scanning URL Reputation..."):
                res = analyze_url(url_val.strip())
                add_event_to_store(res)
                st.session_state["last_url_result"] = res
        else:
            st.warning("Please enter a valid URL.")
    st.markdown('</div>', unsafe_allow_html=True)

    if "last_url_result" in st.session_state:
        res = st.session_state["last_url_result"]
        st.markdown('<div class="card-panel">', unsafe_allow_html=True)
        v_col1, v_col2 = st.columns([3, 1])
        with v_col1:
            st.markdown(f'<div style="font-size:11px; font-family:\'JetBrains Mono\', monospace; color:#A1A1AA; text-transform:uppercase;">Analysis Result</div><div style="font-size:20px; font-weight:700; color:#FFFFFF; margin-top:4px;">Verdict: {get_badge_html(res["risk_level"], res["risk_score"])}</div>', unsafe_allow_html=True)
        with v_col2:
            if st.button("✨ Explain with AI", key="explain_url"):
                with st.spinner("Generating AI Analysis..."):
                    st.session_state["last_url_expl"] = generate_explanation(res)
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
        if "last_url_expl" in st.session_state:
            st.markdown(f'<div class="ai-box"><div style="color:#3B9EFF; font-weight:700; font-size:12px; margin-bottom:4px;">✨ AI Security Explanation</div><div style="color:#CBD5E1; font-size:12px; line-height:1.6;">{st.session_state["last_url_expl"]}</div></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# TAB 3: PHISHING ANALYZER
with tabs[2]:
    st.markdown('<div class="card-panel">', unsafe_allow_html=True)
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
    p_text = st.text_area("Input Content:", placeholder=p_ph, height=140, label_visibility="collapsed")
    if st.button("Analyze Phishing Traits", type="primary"):
        if p_text.strip():
            with st.spinner("Analyzing Content..."):
                res = analyze_phishing_text(p_text.strip())
                add_event_to_store(res)
                st.session_state["last_phish_result"] = res
        else:
            st.warning("Please paste email or message content.")
    st.markdown('</div>', unsafe_allow_html=True)

    if "last_phish_result" in st.session_state:
        res = st.session_state["last_phish_result"]
        st.markdown('<div class="card-panel">', unsafe_allow_html=True)
        v_col1, v_col2 = st.columns([3, 1])
        with v_col1:
            st.markdown(f'<div style="font-size:11px; font-family:\'JetBrains Mono\', monospace; color:#A1A1AA; text-transform:uppercase;">Phishing Risk Assessment</div><div style="font-size:20px; font-weight:700; color:#FFFFFF; margin-top:4px;">Verdict: {get_badge_html(res["risk_level"], res["risk_score"])}</div>', unsafe_allow_html=True)
        with v_col2:
            if st.button("✨ Explain Risk", key="explain_phish"):
                with st.spinner("Generating AI Analysis..."):
                    st.session_state["last_phish_expl"] = generate_explanation(res)
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
        if "last_phish_expl" in st.session_state:
            st.markdown(f'<div class="ai-box"><div style="color:#3B9EFF; font-weight:700; font-size:12px; margin-bottom:4px;">✨ AI Risk Context</div><div style="color:#CBD5E1; font-size:12px; line-height:1.6;">{st.session_state["last_phish_expl"]}</div></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# TAB 4: ACCOUNT ANALYZER
with tabs[3]:
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
        v_col1, v_col2 = st.columns([3, 1])
        with v_col1:
            st.markdown(f'<div style="font-size:11px; font-family:\'JetBrains Mono\', monospace; color:#A1A1AA; text-transform:uppercase;">Account Risk Verdict</div><div style="font-size:20px; font-weight:700; color:#FFFFFF; margin-top:4px;">Verdict: {get_badge_html(res["risk_level"], res["risk_score"])}</div>', unsafe_allow_html=True)
        with v_col2:
            if st.button("✨ Explain Log Risk", key="explain_acc"):
                with st.spinner("Generating AI Analysis..."):
                    st.session_state["last_acc_expl"] = generate_explanation(res)
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
        if "last_acc_expl" in st.session_state:
            st.markdown(f'<div class="ai-box"><div style="color:#3B9EFF; font-weight:700; font-size:12px; margin-bottom:4px;">✨ AI Threat Assessment</div><div style="color:#CBD5E1; font-size:12px; line-height:1.6;">{st.session_state["last_acc_expl"]}</div></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# TAB 5: VOICE ANALYZER
with tabs[4]:
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
    audio_file = st.file_uploader("Select Voice Recording (WAV, MP3, OGG, M4A, FLAC):", type=["wav", "mp3", "ogg", "m4a", "flac", "webm"])
    if audio_file is not None:
        st.audio(audio_file)
        if st.button("Analyze Voice Recording", type="primary"):
            with st.spinner("Analyzing Audio Recording..."):
                from fastapi import UploadFile
                fastapi_upload = UploadFile(filename=audio_file.name, file=audio_file)
                from cyberguard.backend.services.voice_service import analyze_voice_file
                res = analyze_voice_file(fastapi_upload)
                add_event_to_store(res)
                st.session_state["last_voice_result"] = res
                if "transcription unavailable:" in res.get("source", ""):
                    st.warning("Voice classification completed, but transcription is unavailable in this deployment.")
                # Save raw audio bytes for waveform rendering
                try:
                    audio_file.seek(0)
                    st.session_state["last_audio_bytes"] = audio_file.read()
                except Exception:
                    pass

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
        v_col1, v_col2 = st.columns([3, 1])
        with v_col1:
            st.markdown(f'<div style="font-size:11px; font-family:\'JetBrains Mono\', monospace; color:#A1A1AA; text-transform:uppercase;">Voice Threat Verdict</div><div style="font-size:20px; font-weight:700; color:#FFFFFF; margin-top:4px;">Risk Level: {get_badge_html(res["risk_level"], res["risk_score"])}</div>', unsafe_allow_html=True)
        with v_col2:
            if st.button("✨ Explain Voice Risk", key="explain_voice"):
                with st.spinner("Generating AI Analysis..."):
                    st.session_state["last_voice_expl"] = generate_explanation(res)
        st.markdown("<br>", unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns(4)
        c1.markdown(f'<div class="metric-panel"><div><div class="metric-title">Voice Verdict</div><div class="metric-number" style="font-size:16px; color:#FB7185;">{res.get("voice_verdict", "N/A")}</div></div></div>', unsafe_allow_html=True)
        c2.markdown(f'<div class="metric-panel"><div><div class="metric-title">AI Confidence</div><div class="metric-number">{res.get("voice_confidence", 0)}%</div></div></div>', unsafe_allow_html=True)
        c3.markdown(f'<div class="metric-panel"><div><div class="metric-title">Scam Score</div><div class="metric-number" style="color:#FBBF24;">{res.get("scam_score", 0)}/100</div></div></div>', unsafe_allow_html=True)
        c4.markdown(f'<div class="metric-panel"><div><div class="metric-title">Category</div><div class="metric-number" style="font-size:13px; color:#3B9EFF;">{res.get("threat_category", "N/A")}</div></div></div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        p_col1, p_col2 = st.columns([1.2, 1])
        with p_col1:
            st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:8px;'>Speech Authenticity Breakdown (AI vs. Human)</h5>", unsafe_allow_html=True)
            ai_prob = res.get("voice_confidence", 50)
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
                st.markdown(f'<div style="background:#0B0E14; border:1px solid #232730; padding:16px; border-radius:10px; font-style:italic; font-family:\'JetBrains Mono\', monospace; color:#E2E8F0; font-size:12px; line-height:1.6;">"{res["transcript"]}"</div>', unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:8px;'>Acoustic Evidence</h5>", unsafe_allow_html=True)
            for item in res.get("evidence", []):
                st.markdown(f'<div class="evidence-item"><span style="color:#FB7185; font-weight:700;">{item["name"]}</span><span style="color:#A1A1AA;">Weight: +{item["value"]}</span></div>', unsafe_allow_html=True)
        if res.get("acoustic_features"):
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<h5 style='font-size:12px; font-weight:700; color:#A1A1AA; text-transform:uppercase; margin-bottom:12px;'>Acoustic Feature Matrix</h5>", unsafe_allow_html=True)
            FEATURE_CONFIG = {
                "duration_sec": ("Duration", "sec", "#38BDF8"),
                "f0_mean_hz": ("Fundamental Pitch Mean", "Hz", "#818CF8"),
                "f0_std_hz": ("Pitch Variation (Std)", "Hz", "#C084FC"),
                "f0_jitter": ("Pitch Jitter", "ratio", "#F472B6"),
                "voicing_ratio": ("Voicing Ratio", "%", "#34D399"),
                "spectral_centroid_hz": ("Spectral Centroid", "Hz", "#FBBF24"),
                "spectral_bandwidth_hz": ("Spectral Bandwidth", "Hz", "#FB923C"),
                "spectral_flatness": ("Spectral Flatness", "index", "#F87171"),
                "spectral_rolloff_hz": ("Spectral Rolloff Frequency", "Hz", "#E879F9"),
                "zcr_mean": ("Zero Crossing Rate", "zcr", "#A7F3D0"),
                "rms_energy": ("RMS Energy Intensity", "rms", "#67E8F9"),
            }
            f_cols = st.columns(3)
            for idx, (k, v) in enumerate(res["acoustic_features"].items()):
                fc = f_cols[idx % 3]
                label, unit, color = FEATURE_CONFIG.get(k, (k.replace("_", " ").title(), "", "#38BDF8"))
                val_formatted = f"{v:.4f}" if isinstance(v, float) else str(v)
                if unit == "%" and isinstance(v, float):
                    val_formatted = f"{v * 100:.1f}%"
                elif unit:
                    val_formatted = f"{val_formatted} <span style='font-size:11px; color:#A1A1AA;'>{unit}</span>"
                fc.markdown(f'<div style="background:#0B0E14; border:1px solid #232730; border-left:4px solid {color}; padding:12px 14px; border-radius:10px; margin-bottom:8px;"><div style="font-size:10px; font-weight:700; color:#64748B; text-transform:uppercase;">{label}</div><div style="font-size:17px; font-weight:800; font-family:\'JetBrains Mono\', monospace; color:#FFFFFF; margin-top:2px;">{val_formatted}</div></div>', unsafe_allow_html=True)
        if "last_voice_expl" in st.session_state:
            st.markdown(f'<div class="ai-box"><div style="color:#3B9EFF; font-weight:700; font-size:12px; margin-bottom:4px;">✨ AI Threat Assessment</div><div style="color:#CBD5E1; font-size:12px; line-height:1.6;">{st.session_state["last_voice_expl"]}</div></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# TAB 6: EVENT INSPECTOR
with tabs[5]:
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
        e_col1, e_col2 = st.columns([3, 1])
        with e_col1:
            st.markdown("<div style='font-size:11px; font-family:monospace; color:#A1A1AA; margin-bottom:4px;'>💻 RAW ThreatEvent Payload</div>", unsafe_allow_html=True)
        with e_col2:
            if st.button("✨ Explain Event with AI", key="explain_inspector"):
                with st.spinner("Analyzing Event Schema..."):
                    st.session_state["last_inspector_expl"] = generate_explanation(selected_evt)
        st.json(selected_evt)
        if "last_inspector_expl" in st.session_state:
            st.markdown(f'<div class="ai-box"><div style="color:#3B9EFF; font-weight:700; font-size:12px; margin-bottom:4px;">✨ AI Threat Explanation</div><div style="color:#CBD5E1; font-size:12px; line-height:1.6;">{st.session_state["last_inspector_expl"]}</div></div>', unsafe_allow_html=True)
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

# TAB 7: ALERT WEBHOOKS
with tabs[6]:
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
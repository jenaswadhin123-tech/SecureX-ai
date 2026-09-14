# dashboard/app.py
"""Professional Streamlit dashboard for CYBERGUARD.

Features:
- Live Analytics Overview & Time-series monitoring.
- Interactive URL Reputation Scanner (Google Safe Browsing + Blocklist).
- Interactive Phishing Text Analyzer.
- Account Log Risk Analyzer.
- Detailed Event Inspector with full JSON payload & AI Explanation generator.

The FastAPI service is expected at http://127.0.0.1:8000.
"""

import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta
import json

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_BASE = "http://127.0.0.1:8000/api"
API_HEADERS = {"X-API-Key": "cyberguard-secret-key-2026"}

st.set_page_config(
    page_title="CYBERGUARD – Threat Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CYBERGUARD – Real‑time Threat Event Dashboard")

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def fetch_events(skip: int = 0, limit: int = 100, risk_level: str | None = None) -> pd.DataFrame:
    """Retrieve events from the FastAPI `/events` endpoint and return a DataFrame."""
    limit = min(limit, 100)
    params = {"skip": skip, "limit": limit}
    if risk_level and risk_level != "ALL":
        params["risk_level"] = risk_level
    try:
        resp = requests.get(f"{API_BASE}/events", params=params, headers=API_HEADERS, timeout=5)
        resp.raise_for_status()
        events = resp.json()
        if not events:
            return pd.DataFrame()
        df = pd.DataFrame(events)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        return df
    except Exception as e:
        st.error(f"Failed to fetch events: {e}")
        return pd.DataFrame()

def fetch_total_count() -> int:
    try:
        resp = requests.get(f"{API_BASE}/events", params={"skip": 0, "limit": 1}, headers=API_HEADERS, timeout=5)
        resp.raise_for_status()
        total = resp.headers.get("X-Total-Count")
        if total:
            return int(total)
        return len(resp.json())
    except Exception as e:
        st.error(f"Failed to fetch total count: {e}")
        return 0

def render_risk_badge(level: str, score: int):
    color_map = {
        "SAFE": "🟢 #10B981",
        "LOW": "🔵 #3B82F6",
        "MEDIUM": "🟡 #F59E0B",
        "HIGH": "🟠 #EF4444",
        "CRITICAL": "🔴 #DC2626",
    }
    badge = color_map.get(level.upper(), "⚪ #6B7280")
    st.markdown(f"### Verdict: **{level}** ({score}/100) {badge.split()[0]}")

def generate_explanation(threat_event: dict) -> str:
    try:
        resp = requests.post(f"{API_BASE}/explain", json=threat_event, headers=API_HEADERS, timeout=10)
        resp.raise_for_status()
        return resp.json().get("explanation", "No explanation provided.")
    except Exception as e:
        return f"Failed to generate explanation: {e}"

# ---------------------------------------------------------------------------
# Navigation Tabs
# ---------------------------------------------------------------------------
tab_overview, tab_url, tab_phishing, tab_account, tab_inspector = st.tabs([
    "📊 Overview & Analytics",
    "🔗 URL Scanner",
    "🎣 Phishing Analyzer",
    "👤 Account Log Analyzer",
    "🔍 Event Inspector"
])

# ---------------------------------------------------------------------------
# Tab 1: Overview & Analytics
# ---------------------------------------------------------------------------
with tab_overview:
    col_hdr, col_btn = st.columns([4, 1])
    with col_hdr:
        st.subheader("System Overview")
    with col_btn:
        if st.button("🔄 Refresh Data"):
            st.rerun()

    events_df = fetch_events(limit=100)
    total_events = fetch_total_count()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events Logged", total_events)
    
    if not events_df.empty and "risk_level" in events_df.columns:
        high_critical = len(events_df[events_df["risk_level"].isin(["HIGH", "CRITICAL"])])
        c2.metric("High / Critical Threats", high_critical)
        c3.metric("Latest Threat Category", events_df.iloc[0].get("threat_category", "N/A"))
        c4.metric("Active Sources", events_df["source"].nunique() if "source" in events_df.columns else 1)
    else:
        c2.metric("High / Critical Threats", 0)
        c3.metric("Latest Threat Category", "N/A")
        c4.metric("Active Sources", 0)

    st.markdown("---")
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.write("#### Risk Level Distribution")
        if not events_df.empty and "risk_level" in events_df.columns:
            risk_counts = events_df["risk_level"].value_counts().reindex(
                ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"], fill_value=0
            )
            st.bar_chart(risk_counts)
        else:
            st.info("No threat event data available.")

    with col_chart2:
        st.write("#### Threat Activity (Last 24 Hours)")
        if not events_df.empty and "timestamp" in events_df.columns:
            now = datetime.now(datetime.now().astimezone().tzinfo)
            past_24h = now - timedelta(hours=24)
            recent_24h = events_df[events_df["timestamp"] >= past_24h].copy()
            if not recent_24h.empty:
                recent_24h = recent_24h.set_index("timestamp")
                hourly = recent_24h.resample("h").size().rename("count")
                st.line_chart(hourly)
            else:
                st.info("No threat events in the past 24 hours.")
        else:
            st.info("No time-series data available.")

    st.markdown("---")
    st.write("#### Recent Events (Latest 20)")
    if not events_df.empty:
        display_cols = [c for c in ["id", "timestamp", "threat_category", "risk_score", "risk_level", "source"] if c in events_df.columns]
        recent = events_df[display_cols].head(20).copy()
        if "timestamp" in recent.columns:
            recent["timestamp"] = recent["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        st.dataframe(recent, use_container_width=True, hide_index=True)
    else:
        st.info("No recent events to display.")

# ---------------------------------------------------------------------------
# Tab 2: URL Scanner
# ---------------------------------------------------------------------------
with tab_url:
    st.subheader("🔗 Live URL Reputation Scanner")
    st.caption("Analyzes target URLs against Google Safe Browsing and local threat blocklists.")
    
    with st.form("url_scan_form"):
        url_input = st.text_input("Enter URL to scan:", placeholder="https://phishingsite.com")
        submit_url = st.form_submit_button("Scan URL")
    
    if submit_url and url_input:
        with st.spinner("Analyzing URL reputation..."):
            try:
                resp = requests.post(f"{API_BASE}/analyze/url", json={"url": url_input}, headers=API_HEADERS, timeout=10)
                if resp.status_code == 200:
                    result = resp.json()
                    st.success("Analysis Complete!")
                    
                    render_risk_badge(result.get("risk_level", "SAFE"), result.get("risk_score", 0))
                    
                    st.write("**Threat Category:**", result.get("threat_category"))
                    
                    if result.get("evidence"):
                        st.write("#### Evidence Items:")
                        st.dataframe(pd.DataFrame(result["evidence"]), use_container_width=True)
                    
                    if result.get("recommendations"):
                        st.write("#### Recommendations:")
                        for rec in result["recommendations"]:
                            st.markdown(f"- {rec}")
                            
                    with st.expander("🤖 Generate AI Explanation"):
                        if st.button("Explain Threat", key="explain_url"):
                            explanation = generate_explanation(result)
                            st.info(explanation)
                else:
                    st.error(f"Scan failed: {resp.text}")
            except Exception as e:
                st.error(f"Error connecting to backend: {e}")

# ---------------------------------------------------------------------------
# Tab 3: Phishing Analyzer
# ---------------------------------------------------------------------------
with tab_phishing:
    st.subheader("🎣 Phishing Text & Email Analyzer")
    st.caption("Inspects suspicious emails, SMS messages, or social engineering text for phishing traits.")
    
    with st.form("phishing_scan_form"):
        phishing_text = st.text_area("Paste suspicious text / email content:", height=150,
                                     placeholder="URGENT: Your account has been compromised. Verify your credentials immediately.")
        submit_phishing = st.form_submit_button("Analyze Content")
        
    if submit_phishing and phishing_text:
        with st.spinner("Analyzing content for phishing indicators..."):
            try:
                resp = requests.post(f"{API_BASE}/analyze/phishing", json={"content": phishing_text}, headers=API_HEADERS, timeout=10)
                if resp.status_code == 200:
                    result = resp.json()
                    st.success("Analysis Complete!")
                    
                    render_risk_badge(result.get("risk_level", "SAFE"), result.get("risk_score", 0))
                    
                    if result.get("evidence"):
                        st.write("#### Detected Phishing Indicators:")
                        st.dataframe(pd.DataFrame(result["evidence"]), use_container_width=True)
                        
                    if result.get("recommendations"):
                        st.write("#### Recommendations:")
                        for rec in result["recommendations"]:
                            st.markdown(f"- {rec}")
                            
                    with st.expander("🤖 Generate AI Explanation"):
                        if st.button("Explain Phishing Risk", key="explain_phishing"):
                            explanation = generate_explanation(result)
                            st.info(explanation)
                else:
                    st.error(f"Analysis failed: {resp.text}")
            except Exception as e:
                st.error(f"Error connecting to backend: {e}")

# ---------------------------------------------------------------------------
# Tab 4: Account Log Analyzer
# ---------------------------------------------------------------------------
with tab_account:
    st.subheader("👤 Account Authentication Log Analyzer")
    st.caption("Analyzes authentication logs for brute-force attacks, unusual IP logins, or credential stuffing.")
    
    with st.form("account_scan_form"):
        account_log = st.text_area("Paste authentication log lines:", height=150,
                                   placeholder="Failed login attempt for user admin from IP 192.168.1.105")
        submit_account = st.form_submit_button("Analyze Logs")
        
    if submit_account and account_log:
        with st.spinner("Analyzing authentication log..."):
            try:
                resp = requests.post(f"{API_BASE}/analyze/account", json={"log": account_log}, headers=API_HEADERS, timeout=10)
                if resp.status_code == 200:
                    result = resp.json()
                    st.success("Analysis Complete!")
                    
                    render_risk_badge(result.get("risk_level", "SAFE"), result.get("risk_score", 0))
                    
                    if result.get("evidence"):
                        st.write("#### Suspicious Log Indicators:")
                        st.dataframe(pd.DataFrame(result["evidence"]), use_container_width=True)
                        
                    if result.get("recommendations"):
                        st.write("#### Recommendations:")
                        for rec in result["recommendations"]:
                            st.markdown(f"- {rec}")
                            
                    with st.expander("🤖 Generate AI Explanation"):
                        if st.button("Explain Account Risk", key="explain_account"):
                            explanation = generate_explanation(result)
                            st.info(explanation)
                else:
                    st.error(f"Analysis failed: {resp.text}")
            except Exception as e:
                st.error(f"Error connecting to backend: {e}")

# ---------------------------------------------------------------------------
# Tab 5: Event Inspector
# ---------------------------------------------------------------------------
with tab_inspector:
    st.subheader("🔍 Threat Event Deep Inspector")
    st.caption("Select any logged Threat Event to view full payload, evidence metrics, and AI explanations.")
    
    events_df_insp = fetch_events(limit=50)
    if not events_df_insp.empty and "id" in events_df_insp.columns:
        event_ids = events_df_insp["id"].tolist()
        selected_id = st.selectbox("Select Threat Event ID:", event_ids)
        
        if selected_id:
            event_row = events_df_insp[events_df_insp["id"] == selected_id].iloc[0].to_dict()
            
            c_score, c_level, c_cat = st.columns(3)
            c_score.metric("Risk Score", event_row.get("risk_score", 0))
            c_level.metric("Risk Level", event_row.get("risk_level", "UNKNOWN"))
            c_cat.metric("Category", event_row.get("threat_category", "N/A"))
            
            st.write("#### Raw Event JSON")
            st.json(event_row)
            
            if st.button("🤖 Generate AI Explanation for Event", key="explain_inspector"):
                with st.spinner("Generating AI explanation..."):
                    # Clean out pandas non-serializable elements if any
                    clean_dict = json.loads(json.dumps(event_row, default=str))
                    explanation = generate_explanation(clean_dict)
                    st.info(explanation)
    else:
        st.info("No threat events available to inspect.")

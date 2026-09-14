# backend/services/virustotal_service.py
"""VirusTotal v3 API helper for CyberGuard URL reputation analysis.

Queries VirusTotal v3 API to fetch antivirus engine threat detections
for target URLs. Returns an integer threat score (0-100).
"""

import requests
import base64
from typing import Dict

def _query_virustotal_url(url: str) -> int:
    """Query VirusTotal v3 API for URL threat verdict.

    Returns threat score (0-100). Returns 0 if API key missing or request fails.
    """
    from .. import config
    api_key = config.VIRUSTOTAL_API_KEY
    if not api_key:
        return 0

    try:
        # Base64 encode URL without padding as required by VirusTotal v3 API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": api_key}

        resp = requests.get(endpoint, headers=headers, timeout=5)
        if resp.status_code != 200:
            return 0

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        total_bad = malicious + suspicious
        if total_bad >= 5:
            return 95
        elif total_bad >= 3:
            return 80
        elif total_bad >= 1:
            return 60
        return 0
    except Exception:
        return 0

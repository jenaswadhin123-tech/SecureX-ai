# backend/services/abuseipdb_service.py
"""AbuseIPDB v2 API helper for CyberGuard Account authentication log analysis.

Queries AbuseIPDB check endpoint for IP reputation and abuse confidence score.
"""

import requests
from typing import Dict

def _query_abuseipdb_ip(ip: str) -> int:
    """Query AbuseIPDB v2 check API for an IP address.

    Returns abuseConfidenceScore (0-100). Returns 0 if API key missing or on failure.
    """
    from .. import config
    api_key = config.ABUSEIPDB_API_KEY
    if not api_key:
        return 0

    try:
        endpoint = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        resp = requests.get(endpoint, headers=headers, params=params, timeout=5)
        if resp.status_code != 200:
            return 0

        data = resp.json()
        score = data.get("data", {}).get("abuseConfidenceScore", 0)
        return int(score)
    except Exception:
        return 0

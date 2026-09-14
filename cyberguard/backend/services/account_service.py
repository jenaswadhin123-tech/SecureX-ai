from __future__ import annotations

import math
from datetime import datetime
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple

# Shared utilities
from ..risk_engine import compute_overall_risk
from ..models import ThreatEvent, EvidenceItem

# Very small heuristics – replace with a proper ML model later.
FAILED_LOGIN_KEYWORDS = {"failed", "invalid", "error", "incorrect"}
MAX_FAILED_PER_IP = 5  # threshold for flagging brute‑force

# Sample Geolocation Coordinates for test/demo IP ranges & cities
KNOWN_GEO_COORDS = {
    "nyc": (40.7128, -74.0060),
    "london": (51.5074, -0.1278),
    "tokyo": (35.6762, 139.6503),
    "sydney": (-33.8688, 151.2093),
    "paris": (48.8566, 2.3522),
    "berlin": (52.5200, 13.4050),
    # Known test IPs mapped to coordinates
    "1.1.1.1": (40.7128, -74.0060),      # NYC
    "2.2.2.2": (51.5074, -0.1278),      # London
    "3.3.3.3": (35.6762, 139.6503),     # Tokyo
    "4.4.4.4": (-33.8688, 151.2093),    # Sydney
}

# In-memory geo cache – keyed by IP string, value is (lat, lon) or None
_GEO_CACHE: Dict[str, Optional[Tuple[float, float]]] = {}

def _geolocate_ip(ip: str) -> Optional[Tuple[float, float]]:
    """Resolve an IP address to (lat, lon) using ip-api.com (free, no key required).

    Results are cached in-process so each unique IP is only looked up once per
    server lifetime. Private/reserved addresses return ``None`` immediately.
    """
    import ipaddress
    import requests as _requests

    # Return from cache if we already looked this up
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    # Check our static dict first
    if ip in KNOWN_GEO_COORDS:
        _GEO_CACHE[ip] = KNOWN_GEO_COORDS[ip]
        return KNOWN_GEO_COORDS[ip]

    # Skip private / loopback / link-local addresses — no public geo data
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            _GEO_CACHE[ip] = None
            return None
    except ValueError:
        _GEO_CACHE[ip] = None
        return None

    # Live lookup via ip-api.com (free tier: 45 req/min, no key needed)
    try:
        resp = _requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,lat,lon"},
            timeout=3,
        )
        data = resp.json()
        if data.get("status") == "success":
            result = (float(data["lat"]), float(data["lon"]))
            _GEO_CACHE[ip] = result
            return result
    except Exception:
        pass

    _GEO_CACHE[ip] = None
    return None

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate Great Circle distance between two points in kilometers."""
    R = 6371.0  # Earth radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

def _parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Try parsing timestamp from ISO strings or unix epochs."""
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
    ):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromtimestamp(float(ts_str))
    except ValueError:
        return None

def _parse_log(log: str) -> List[Dict]:
    """Parse raw auth logs into structured entries.
    Supported formats:
    - `<timestamp> <ip> <status>`
    - `<timestamp> <user> <ip> <status>`
    - `<timestamp> <user> <ip> <lat,lon|city> <status>`
    """
    entries = []
    for line in log.splitlines():
        parts = line.strip().split()
        if len(parts) < 3:
            continue

        ts = _parse_timestamp(parts[0])

        if len(parts) == 3:
            # ts ip status
            ip = parts[1]
            entries.append({
                "ts": ts,
                "user": "default_user",
                "ip": ip,
                "geo": _geolocate_ip(ip),
                "status": parts[2].lower()
            })
        elif len(parts) == 4:
            # ts user ip status
            ip = parts[2]
            entries.append({
                "ts": ts,
                "user": parts[1],
                "ip": ip,
                "geo": _geolocate_ip(ip),
                "status": parts[3].lower()
            })
        elif len(parts) >= 5:
            # ts user ip geo status
            ip = parts[2]
            geo_val = None
            if "," in parts[3]:
                try:
                    lat, lon = map(float, parts[3].split(","))
                    geo_val = (lat, lon)
                except ValueError:
                    pass
            elif parts[3].lower() in KNOWN_GEO_COORDS:
                geo_val = KNOWN_GEO_COORDS[parts[3].lower()]
            else:
                # Fall back to live geolocation of the IP
                geo_val = _geolocate_ip(ip)

            entries.append({
                "ts": ts,
                "user": parts[1],
                "ip": ip,
                "geo": geo_val,
                "status": parts[-1].lower()
            })
    return entries


def _score_entries(entries: List[Dict]) -> Dict[str, int]:
    """Score the log based on failed‑login patterns, AbuseIPDB, and Impossible Travel."""
    contributions: Dict[str, int] = {}

    # 1. Count failed attempts per IP (Brute Force)
    failed_counts = Counter(
        e["ip"] for e in entries if any(k in e["status"] for k in FAILED_LOGIN_KEYWORDS)
    )
    for ip, cnt in failed_counts.items():
        if cnt >= MAX_FAILED_PER_IP:
            contributions[f"BRUTE_FORCE_{ip.replace('.', '_')}"] = min(100, cnt * 10)

    # 2. AbuseIPDB Lookup
    from .abuseipdb_service import _query_abuseipdb_ip
    unique_ips = set(e["ip"] for e in entries if e.get("ip"))
    for ip in unique_ips:
        abuse_score = _query_abuseipdb_ip(ip)
        if abuse_score > 0:
            contributions[f"ABUSEIPDB_{ip.replace('.', '_')}"] = abuse_score

    # 3. Impossible Travel Velocity Anomaly Detection per User
    user_logins = defaultdict(list)
    for e in entries:
        if e.get("ts") and e.get("geo"):
            user_logins[e["user"]].append(e)

    for user, logins in user_logins.items():
        # Sort logins by timestamp
        logins.sort(key=lambda x: x["ts"])
        for i in range(len(logins) - 1):
            l1, l2 = logins[i], logins[i + 1]
            time_delta_secs = (l2["ts"] - l1["ts"]).total_seconds()
            if time_delta_secs <= 0:
                continue

            time_hours = time_delta_secs / 3600.0
            dist_km = _haversine_km(l1["geo"][0], l1["geo"][1], l2["geo"][0], l2["geo"][1])
            speed_kmh = dist_km / time_hours

            # Commercial airliner speed limit ~ 800-900 km/h
            if speed_kmh > 800 and dist_km > 300:
                safe_user = user.replace("@", "_").replace(".", "_")
                contributions[f"IMPOSSIBLE_TRAVEL_{safe_user}"] = 50
                break

    return contributions

def analyze_account_log(log: str) -> Dict:
    """Analyze authentication log and return a ``ThreatEvent`` dict."""
    entries = _parse_log(log)
    contributions = _score_entries(entries)
    overall_risk, risk_level = compute_overall_risk(contributions)

    evidence: List[EvidenceItem] = [
        EvidenceItem(name=name, value=val) for name, val in contributions.items()
    ]

    recommendations = [
        "Lock accounts with multiple failed attempts or impossible travel anomalies",
        "Enforce MFA for affected user accounts immediately",
        "Investigate login geographic origin and active session tokens",
        "Consider rate‑limiting login attempts from unknown IP ranges",
    ]

    threat = ThreatEvent(
        threat_category="ACCOUNT_TAKEOVER",
        risk_score=overall_risk,
        risk_level=risk_level,
        evidence=evidence,
        recommendations=recommendations,
        explanation=None,
        source="account_service",
    )
    return threat.model_dump()

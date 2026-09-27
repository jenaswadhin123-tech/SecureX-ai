"""Rule-based detection for structured security telemetry batches."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List

from ..models import EvidenceItem, ThreatEvent
from ..risk_engine import compute_overall_risk

MIB = 1024 * 1024
HIGH_RISK_EGRESS_BYTES = 100 * MIB
SENSITIVE_EGRESS_BYTES = 10 * MIB
SUSPICIOUS_OUTBOUND_PORTS = {1337, 4444, 5555, 9001, 31337}
API_FAILURE_CODES = {401, 403, 429}
INSIDER_ACTIONS = {
    "bulk_download",
    "bulk_export",
    "mass_delete",
    "privilege_escalation",
    "privilege_grant",
    "sensitive_data_export",
}


def _actor(event: Dict[str, Any]) -> str:
    return str(event.get("user") or event.get("source_ip") or "unknown").strip().lower()


def _as_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def analyze_cyber_events(events: List[Dict[str, Any]], window_minutes: int = 15) -> Dict[str, Any]:
    """Score a bounded batch of security events and return a ThreatEvent payload.

    Thresholds are conservative heuristics, not a substitute for environment-specific
    baselines or a trained detection model.
    """
    contributions: Dict[str, int] = {}
    evidence: List[EvidenceItem] = []
    api_requests = Counter()
    api_failures = Counter()
    outbound_bytes = Counter()
    sensitive_outbound_bytes = Counter()
    insider_actions = Counter()
    system_errors = Counter()
    system_critical: List[Dict[str, Any]] = []

    for event in events:
        actor = _actor(event)
        event_type = str(event.get("event_type", "")).strip().lower()
        action = str(event.get("action", "")).strip().lower()
        direction = str(event.get("direction", "")).strip().lower()
        severity = str(event.get("severity", "")).strip().lower()
        status_code = _as_int(event.get("status_code"))
        bytes_out = _as_int(event.get("bytes_out"))
        indicator = str(event.get("threat_indicator", "")).strip()

        if event.get("malware_detected") is True or indicator:
            contributions["MALWARE_INDICATOR"] = max(
                contributions.get("MALWARE_INDICATOR", 0), 55
            )
            evidence.append(EvidenceItem(
                name="MALWARE_INDICATOR",
                value={"actor": actor, "indicator": indicator or "explicit malware alert"},
            ))

        process = str(event.get("process", "")).lower()
        command_line = str(event.get("command_line", "")).lower()
        if process in {"mimikatz", "psexec", "cobaltstrike", "meterpreter"} or (
            "powershell" in process and any(flag in command_line for flag in ("-enc", "-encodedcommand"))
        ):
            contributions["SUSPICIOUS_PROCESS_EXECUTION"] = max(
                contributions.get("SUSPICIOUS_PROCESS_EXECUTION", 0), 35
            )
            evidence.append(EvidenceItem(
                name="SUSPICIOUS_PROCESS_EXECUTION",
                value={"actor": actor, "process": process},
            ))

        if direction in {"outbound", "egress"}:
            outbound_bytes[actor] += bytes_out
            if event.get("sensitive_resource") is True:
                sensitive_outbound_bytes[actor] += bytes_out

        port = _as_int(event.get("destination_port"))
        if direction in {"outbound", "egress"} and port in SUSPICIOUS_OUTBOUND_PORTS:
            contributions["SUSPICIOUS_OUTBOUND_PORT"] = max(
                contributions.get("SUSPICIOUS_OUTBOUND_PORT", 0), 25
            )
            evidence.append(EvidenceItem(
                name="SUSPICIOUS_OUTBOUND_PORT",
                value={"actor": actor, "destination_port": port},
            ))

        if event_type in {"api", "api_request", "http_request"}:
            api_requests[actor] += max(1, _as_int(event.get("request_count", 1)))
            if status_code in API_FAILURE_CODES:
                api_failures[actor] += max(1, _as_int(event.get("request_count", 1)))

        if action in INSIDER_ACTIONS:
            insider_actions[actor] += 1

        if event_type in {"system_log", "application_log", "audit_log"}:
            if severity in {"critical", "fatal"}:
                system_critical.append({"actor": actor, "severity": severity})
            elif severity in {"error", "err"}:
                system_errors[actor] += 1

        if event.get("activity_anomaly") is True:
            contributions["ABNORMAL_USER_ACTIVITY"] = max(
                contributions.get("ABNORMAL_USER_ACTIVITY", 0), 25
            )
            evidence.append(EvidenceItem(
                name="ABNORMAL_USER_ACTIVITY",
                value={"actor": actor, "action": action or event_type or "unspecified"},
            ))

    window_scale = window_minutes / 15
    high_egress_threshold = max(10 * MIB, int(HIGH_RISK_EGRESS_BYTES * window_scale))
    sensitive_egress_threshold = max(1 * MIB, int(SENSITIVE_EGRESS_BYTES * window_scale))
    for actor, byte_count in outbound_bytes.items():
        sensitive_bytes = sensitive_outbound_bytes[actor]
        if byte_count >= high_egress_threshold:
            contributions["POSSIBLE_DATA_EXFILTRATION"] = max(
                contributions.get("POSSIBLE_DATA_EXFILTRATION", 0), 45
            )
            evidence.append(EvidenceItem(
                name="POSSIBLE_DATA_EXFILTRATION",
                value={"actor": actor, "outbound_bytes": byte_count},
            ))
        elif sensitive_bytes >= sensitive_egress_threshold:
            contributions["POSSIBLE_DATA_EXFILTRATION"] = max(
                contributions.get("POSSIBLE_DATA_EXFILTRATION", 0), 40
            )
            evidence.append(EvidenceItem(
                name="POSSIBLE_DATA_EXFILTRATION",
                value={"actor": actor, "sensitive_outbound_bytes": sensitive_bytes},
            ))

    api_request_threshold = max(100, int(1000 * window_scale))
    api_failure_threshold = max(5, int(20 * window_scale))
    for actor, request_count in api_requests.items():
        failures = api_failures[actor]
        if request_count >= api_request_threshold or failures >= api_failure_threshold:
            contributions["API_ABUSE"] = max(contributions.get("API_ABUSE", 0), 35)
            evidence.append(EvidenceItem(
                name="API_ABUSE",
                value={"actor": actor, "requests": request_count, "auth_or_rate_limit_failures": failures},
            ))

    for actor, action_count in insider_actions.items():
        if action_count >= max(2, int(5 * window_scale)) or any(
            _actor(event) == actor
            and str(event.get("action", "")).strip().lower() in {"privilege_escalation", "privilege_grant"}
            for event in events
        ):
            contributions["POTENTIAL_INSIDER_MISUSE"] = max(
                contributions.get("POTENTIAL_INSIDER_MISUSE", 0), 35
            )
            evidence.append(EvidenceItem(
                name="POTENTIAL_INSIDER_MISUSE",
                value={"actor": actor, "sensitive_actions": action_count},
            ))

    for actor, error_count in system_errors.items():
        if error_count >= max(3, int(10 * window_scale)):
            contributions["UNUSUAL_SYSTEM_LOG_ACTIVITY"] = max(
                contributions.get("UNUSUAL_SYSTEM_LOG_ACTIVITY", 0), 25
            )
            evidence.append(EvidenceItem(
                name="UNUSUAL_SYSTEM_LOG_ACTIVITY",
                value={"actor": actor, "error_events": error_count},
            ))
    if system_critical:
        contributions["CRITICAL_SYSTEM_LOG"] = 30
        evidence.extend(
            EvidenceItem(name="CRITICAL_SYSTEM_LOG", value=item)
            for item in system_critical[:10]
        )

    risk_score, risk_level = compute_overall_risk(contributions)
    recommendations = [
        "Validate high-confidence indicators against endpoint, network, and identity telemetry",
        "Contain confirmed malware or suspicious egress and preserve relevant logs for investigation",
        "Review API credentials, request patterns, and access permissions for affected actors",
        "Investigate bulk sensitive-data actions and critical system logs before attributing intent",
    ]
    return ThreatEvent(
        threat_category="INTELLIGENT_CYBER_THREAT",
        risk_score=risk_score,
        risk_level=risk_level,
        evidence=evidence,
        recommendations=recommendations,
        explanation=(
            f"Analyzed {len(events)} security events over a {window_minutes}-minute window "
            "using explainable indicator, volume, and activity rules."
        ),
        source="cyber_threat_service",
    ).model_dump()
# backend/services/webhook_service.py
"""Webhook alerting service for CyberGuard backend.

Formats and dispatches real-time threat notifications to Slack, Discord,
or custom webhook endpoints when HIGH or CRITICAL threats are detected.
"""

import requests
import logging
from typing import Dict, Optional
from ..logging_config import logger

RISK_WEIGHTS = {
    "SAFE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

def format_slack_payload(event: Dict) -> Dict:
    level = event.get("risk_level", "UNKNOWN")
    category = event.get("threat_category", "UNKNOWN")
    score = event.get("risk_score", 0)
    source = event.get("source", "system")
    event_id = event.get("id", "N/A")

    badge = "🚨" if level in ["HIGH", "CRITICAL"] else "⚠️"

    return {
        "text": f"{badge} *CYBERGUARD ALERT*: [{level}] {category} (Score: {score}/100)",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{badge} CyberGuard Security Incident Alert",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Category:*\n{category}"},
                    {"type": "mrkdwn", "text": f"*Risk Level:*\n{level} ({score}/100)"},
                    {"type": "mrkdwn", "text": f"*Source Detector:*\n{source}"},
                    {"type": "mrkdwn", "text": f"*Event ID:*\n`{event_id}`"}
                ]
            }
        ]
    }

def send_threat_alert(event: Dict, target_webhook: Optional[str] = None) -> bool:
    """Send threat notification to configured webhook URL if risk exceeds threshold."""
    from .. import config
    url = target_webhook or config.ALERT_WEBHOOK_URL
    if not url:
        return False

    event_level = (event.get("risk_level") or "SAFE").upper()
    min_level = (config.ALERT_MIN_RISK_LEVEL or "HIGH").upper()

    # Check threshold weight
    if RISK_WEIGHTS.get(event_level, 0) < RISK_WEIGHTS.get(min_level, 3) and not target_webhook:
        return False

    try:
        # Check if URL looks like Slack
        if "hooks.slack.com" in url:
            payload = format_slack_payload(event)
        else:
            payload = {
                "alert": "CYBERGUARD_THREAT_DETECTED",
                "event": event
            }

        resp = requests.post(url, json=payload, timeout=5)
        logger.info(f"[WebhookAlert] Dispatched threat alert for event {event.get('id')} to {url}. Status: {resp.status_code}")
        return resp.status_code in [200, 201, 204]
    except Exception as exc:
        logger.error(f"[WebhookAlert] Failed to dispatch webhook alert: {exc}")
        return False

# backend/config.py
"""Configuration utilities for CYBERGUARD backend.

We keep the config very lightweight – values are read from environment
variables with sensible defaults. This module can be imported anywhere
without causing side‑effects.
"""

import os
from typing import Optional

# MongoDB connection – default to a local instance for development.
MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017/cyberguard")

# Retention interval – how often (in hours) the cleanup task runs.
RETENTION_INTERVAL_HOURS: int = int(os.getenv("RETENTION_INTERVAL_HOURS", "24"))
RETENTION_DAYS: int = int(os.getenv("RETENTION_DAYS", "90"))

# Rate‑limit settings – already used elsewhere, but expose for central config.
RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

# Google Safe Browsing API key – optional, read from env. Empty string means disabled.
SAFE_BROWSING_API_KEY: str = os.getenv("SAFE_BROWSING_API_KEY", "")

# API Security settings
CYBERGUARD_API_KEY: str = os.getenv("CYBERGUARD_API_KEY", "cyberguard-secret-key-2026")
JWT_SECRET: str = os.getenv("JWT_SECRET", "super-secret-jwt-key")

# Webhook Alerting settings
ALERT_WEBHOOK_URL: str = os.getenv("ALERT_WEBHOOK_URL", "")
ALERT_MIN_RISK_LEVEL: str = os.getenv("ALERT_MIN_RISK_LEVEL", "HIGH")

# Threat Intelligence API keys
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")




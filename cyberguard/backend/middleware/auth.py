# backend/middleware/auth.py
"""Authentication dependency for CyberGuard FastAPI backend.

Verifies either:
1. `X-API-Key` header matching `CYBERGUARD_API_KEY`
2. `Authorization: Bearer <token>` header
"""

from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from ..config import CYBERGUARD_API_KEY, JWT_SECRET

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

async def verify_api_key(
    api_key: Optional[str] = Security(api_key_header),
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
):
    # Check X-API-Key header
    if api_key and api_key == CYBERGUARD_API_KEY:
        return api_key

    # Check Authorization: Bearer token
    if credentials and credentials.credentials:
        token = credentials.credentials
        # Check against secret or demo token pattern
        if token == JWT_SECRET or token == f"demo-jwt-token-{CYBERGUARD_API_KEY}":
            return token

    # Fallback: if CYBERGUARD_API_KEY is empty/unset, allow dev mode
    if not CYBERGUARD_API_KEY:
        return "dev-unauthenticated"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Invalid or missing X-API-Key / Authorization Bearer header",
        headers={"WWW-Authenticate": "Bearer, Key"},
    )

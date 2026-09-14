# backend/api/auth.py
"""FastAPI router exposing authentication token issuance.

POST /api/auth/token
    Accepts an API key and returns a Bearer access token.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from ..config import CYBERGUARD_API_KEY, JWT_SECRET

router = APIRouter()

class TokenRequest(BaseModel):
    api_key: str

@router.post("/auth/token", status_code=status.HTTP_200_OK)
async def issue_token(request: TokenRequest):
    if request.api_key == CYBERGUARD_API_KEY:
        return {
            "access_token": f"demo-jwt-token-{CYBERGUARD_API_KEY}",
            "token_type": "bearer",
            "expires_in": 86400
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key provided."
    )

class WebhookTestRequest(BaseModel):
    webhook_url: str

@router.post("/alerts/test", status_code=status.HTTP_200_OK)
async def test_webhook_alert(request: WebhookTestRequest):
    from ..services.webhook_service import send_threat_alert
    test_event = {
        "id": "test_event_id_12345",
        "threat_category": "MALICIOUS_URL",
        "risk_score": 85,
        "risk_level": "HIGH",
        "source": "webhook_test",
        "recommendations": ["Verify target URL in sandbox", "Block domain on firewall"]
    }
    success = send_threat_alert(test_event, target_webhook=request.webhook_url)
    if success:
        return {"status": "success", "message": f"Test alert successfully sent to {request.webhook_url}"}
    return {"status": "failed", "message": f"Failed to deliver alert to {request.webhook_url}. Verify URL."}


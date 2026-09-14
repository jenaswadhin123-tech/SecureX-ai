# backend/api/phishing.py
"""FastAPI router exposing a simple phishing text analysis endpoint.

POST /api/analyze/phishing
    Accepts a JSON payload with a ``content`` field (email or SMS text)
    and returns a ``ThreatEvent`` JSON structure.
"""

from fastapi import APIRouter, HTTPException, status, Depends, BackgroundTasks
from pydantic import BaseModel
from ..middleware.auth import verify_api_key
from ..services.webhook_service import send_threat_alert

from ..services.phishing_service import analyze_phishing_text

router = APIRouter()


class PhishingRequest(BaseModel):
    content: str


@router.post("/analyze/phishing", status_code=status.HTTP_200_OK, dependencies=[Depends(verify_api_key)])
async def analyze_phishing(request: PhishingRequest, background_tasks: BackgroundTasks):
    try:
        # Run analysis
        result_dict = analyze_phishing_text(request.content)
        # Persist the event
        from ..db.threat_event_repository import ThreatEventRepository
        from ..models import ThreatEvent
        repo = ThreatEventRepository()
        threat_obj = ThreatEvent(**result_dict)
        inserted_id = await repo.save(threat_obj)
        result_dict["id"] = inserted_id

        # Trigger real-time webhook alert if HIGH or CRITICAL risk
        if result_dict.get("risk_level") in ["HIGH", "CRITICAL"]:
            background_tasks.add_task(send_threat_alert, result_dict)

        return result_dict
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

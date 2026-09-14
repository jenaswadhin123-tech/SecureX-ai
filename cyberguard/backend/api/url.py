# backend/api/url.py
"""FastAPI router exposing a simple URL analysis endpoint.

POST /api/analyze/url
    Accepts a JSON payload with a ``url`` field and returns a
    ``ThreatEvent`` JSON structure.
"""

from fastapi import APIRouter, HTTPException, status, Depends, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from ..middleware.auth import verify_api_key
from ..services.webhook_service import send_threat_alert

from ..services.url_service import analyze_url

router = APIRouter()


class URLRequest(BaseModel):
    url: HttpUrl


@router.post("/analyze/url", status_code=status.HTTP_200_OK, dependencies=[Depends(verify_api_key)])
async def analyze_url_endpoint(request: URLRequest, background_tasks: BackgroundTasks):
    try:
        # Run analysis
        result_dict = analyze_url(str(request.url))
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

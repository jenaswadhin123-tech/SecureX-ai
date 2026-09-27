"""API for batch analysis of structured cyber-security events."""

from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ..middleware.auth import verify_api_key
from ..services.cyber_threat_service import analyze_cyber_events
from ..services.webhook_service import send_threat_alert

router = APIRouter()


class SecurityEvent(BaseModel):
    event_type: str = ""
    timestamp: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    direction: Optional[str] = None
    destination_port: Optional[int] = Field(None, ge=1, le=65535)
    bytes_out: int = Field(0, ge=0)
    status_code: Optional[int] = Field(None, ge=100, le=599)
    request_count: int = Field(1, ge=0)
    action: Optional[str] = None
    sensitive_resource: bool = False
    activity_anomaly: bool = False
    severity: Optional[str] = None
    process: Optional[str] = None
    command_line: Optional[str] = None
    malware_detected: bool = False
    threat_indicator: Optional[str] = None


class CyberThreatRequest(BaseModel):
    events: List[SecurityEvent] = Field(..., min_length=1, max_length=500)
    window_minutes: int = Field(15, ge=1, le=1440)


@router.post(
    "/analyze/cyber-threat",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_api_key)],
)
async def analyze_cyber_threat(
    request: CyberThreatRequest,
    background_tasks: BackgroundTasks,
):
    try:
        events = [event.model_dump() for event in request.events]
        result = analyze_cyber_events(events, request.window_minutes)

        from ..db.threat_event_repository import ThreatEventRepository
        from ..models import ThreatEvent

        repository = ThreatEventRepository()
        result["id"] = await repository.save(ThreatEvent(**result))

        if result["risk_level"] in {"HIGH", "CRITICAL"}:
            background_tasks.add_task(send_threat_alert, result)
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
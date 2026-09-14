"""FastAPI router that exposes the voice analysis endpoint.

Endpoint
--------
POST /api/analyze/voice
    Accepts a multipart form field named ``file`` containing the audio.
    Returns JSON matching the unified threat‑event schema.
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, status, BackgroundTasks
from ..services.webhook_service import send_threat_alert

from ..services.voice_service import analyze_voice_file

router = APIRouter()

@router.post("/analyze/voice", status_code=status.HTTP_200_OK)
async def analyze_voice(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Receive an audio file, run the voice engine and return results.
    Any exception raised by the service layer is converted into a 400
    response so the client gets a clear error message.
    """
    if not file.filename.lower().endswith(("wav", "mp3", "m4a", "ogg", "flac")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported audio format. Accepted: wav, mp3, m4a, ogg, flac.",
        )
    try:
        # Run analysis through the existing service
        result_dict = analyze_voice_file(file)
        # Persist the event in MongoDB
        from ..db.threat_event_repository import ThreatEventRepository
        from ..models import ThreatEvent
        repo = ThreatEventRepository()
        threat_obj = ThreatEvent(**result_dict)
        inserted_id = await repo.save(threat_obj)
        # Attach the MongoDB document id to the response
        result_dict["id"] = inserted_id

        # Trigger real-time webhook alert if HIGH or CRITICAL risk
        if result_dict.get("risk_level") in ["HIGH", "CRITICAL"]:
            background_tasks.add_task(send_threat_alert, result_dict)

        return result_dict
    except Exception as exc:  # pragma: no cover – unexpected errors are logged
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )

"""FastAPI router for QR-code phishing analysis."""

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, status

from ..middleware.auth import verify_api_key
from ..services.qr_service import analyze_qr_image
from ..services.webhook_service import send_threat_alert

router = APIRouter()


@router.post("/analyze/qr", status_code=status.HTTP_200_OK, dependencies=[Depends(verify_api_key)])
async def analyze_qr(background_tasks: BackgroundTasks, image: UploadFile = File(...)):
    try:
        image_bytes = await image.read()
        result_dict = analyze_qr_image(image_bytes, image.filename or "qr-image")
        from ..db.threat_event_repository import ThreatEventRepository
        from ..models import ThreatEvent

        repo = ThreatEventRepository()
        inserted_id = await repo.save(ThreatEvent(**result_dict))
        result_dict["id"] = inserted_id
        if result_dict.get("risk_level") in ["HIGH", "CRITICAL"]:
            background_tasks.add_task(send_threat_alert, result_dict)
        return result_dict
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

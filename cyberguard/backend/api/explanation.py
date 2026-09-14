# backend/api/explanation.py
"""FastAPI router for generating human‑readable explanations.

Endpoint
--------
POST /api/explain
    Accepts a full ``ThreatEvent`` payload (as produced by any detector)
    and returns a JSON object ``{"explanation": "..."}``.
"""

from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from ..middleware.auth import verify_api_key

from ..services.explanation_service import generate_explanation

router = APIRouter()


class ExplainRequest(BaseModel):
    # Accept any fields – we just need a dict, so we allow arbitrary extra data.
    class Config:
        extra = "allow"

    # No explicit fields – the whole payload is passed through.
    # Pydantic will store any extra keys in ``__dict__``.
    pass


@router.post("/explain", status_code=status.HTTP_200_OK, dependencies=[Depends(verify_api_key)])
async def explain(request: ExplainRequest):
    try:
        # ``request`` is a BaseModel; convert to dict preserving all keys.
        payload = request.model_dump()
        explanation = generate_explanation(payload)
        return {"explanation": explanation}
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

# backend/api/events.py
"""FastAPI router for accessing persisted ThreatEvent documents.

Provides:
- GET /api/events           → paginated list (skip/limit) with optional risk_level filter
- GET /api/events/{event_id} → single event by MongoDB ObjectId
"""

import io
import csv
from fastapi import APIRouter, HTTPException, Query, status, Depends, Response
from typing import List, Optional
from ..middleware.auth import verify_api_key

from ..db.threat_event_repository import ThreatEventRepository
from ..models import ThreatEvent

router = APIRouter()

repo = ThreatEventRepository()

@router.get("/events", status_code=status.HTTP_200_OK, dependencies=[Depends(verify_api_key)])
async def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    risk_level: Optional[str] = Query(None, description="Filter by risk level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)"),
    response: Response = None,
):
    """Return a page of persisted ThreatEvent documents.
    The response is a list of JSON objects; each contains an ``id`` field (MongoDB ObjectId)
    in addition to the ThreatEvent fields. The ``X-Total-Count`` response header contains
    the total number of matching documents (un-paged).
    """
    collection = repo._collection  # type: ignore  # internal use
    query = {}
    if risk_level:
        query["risk_level"] = risk_level

    # Count total matching docs for pagination metadata
    total = await collection.count_documents(query)

    cursor = collection.find(query).sort("timestamp", -1).skip(skip).limit(limit)
    result = []
    async for doc in cursor:
        doc_id = str(doc.get("_id"))
        doc.pop("_id", None)
        result.append({"id": doc_id, **doc})

    if response is not None:
        response.headers["X-Total-Count"] = str(total)
        response.headers["Access-Control-Expose-Headers"] = "X-Total-Count"

    return result


@router.get("/events/export", status_code=status.HTTP_200_OK)
async def export_events(
    risk_level: Optional[str] = Query(None, description="Filter export by risk level"),
):
    """Export threat events as downloadable CSV."""
    collection = repo._collection  # type: ignore
    query = {}
    if risk_level:
        query["risk_level"] = risk_level

    cursor = collection.find(query).sort("timestamp", -1).limit(1000)

    output = io.StringIO()
    writer = csv.writer(output)
    # Write CSV Header
    writer.writerow(["ID", "Timestamp", "Category", "Risk Level", "Risk Score", "Source", "Evidence Count"])

    async for doc in cursor:
        doc_id = str(doc.get("_id", ""))
        ts = str(doc.get("timestamp", ""))
        cat = doc.get("threat_category", "")
        level = doc.get("risk_level", "")
        score = doc.get("risk_score", 0)
        source = doc.get("source", "")
        ev_count = len(doc.get("evidence", []))
        writer.writerow([doc_id, ts, cat, level, score, source, ev_count])

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cyberguard_events_report.csv"}
    )

@router.get("/events/{event_id}", status_code=status.HTTP_200_OK)
async def get_event(event_id: str):
    """Retrieve a single ThreatEvent by its MongoDB ObjectId."""
    event = await repo.get_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="ThreatEvent not found")
    # The repository strips ``_id``; we re‑attach it.
    return {"id": event_id, **event.model_dump()}

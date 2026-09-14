# backend/api/health.py
"""Health‑check endpoint for the CYBERGUARD backend.

- ``GET /health`` returns a JSON payload indicating the service status.
- Performs a quick ping to MongoDB to ensure the database connection is alive.
- Uses the central ``logger`` for structured logging.
"""

from fastapi import APIRouter, HTTPException, status
from ..db.mongo_client import get_client
from ..logging_config import logger

router = APIRouter()

@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """Return basic health information.

    The response includes:
    * ``status`` – always ``"ok"`` if the endpoint is reachable.
    * ``db`` – ``"connected"`` if a MongoDB ping succeeds, otherwise ``"unavailable"``.
    """
    try:
        client = get_client()
        # ``admin.command('ping')`` is the canonical way to check connectivity.
        await client.admin.command("ping")
        db_status = "connected"
    except Exception as exc:
        logger.error("MongoDB health check failed: %s", exc)
        db_status = "unavailable"
        # We still return 200 for the HTTP endpoint but indicate DB problem in payload.
    return {"status": "ok", "db": db_status}

"""FastAPI entry point for CYBERGUARD backend.

Provides the main application instance and includes routers.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .middleware.rate_limit import RateLimitMiddleware
import asyncio
from .config import RETENTION_DAYS, RETENTION_INTERVAL_HOURS
app = FastAPI()
# Allow all origins for now (adjust in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
# Register rate‑limit middleware
app.add_middleware(RateLimitMiddleware)

from .api import voice, phishing, url, qr, account, explanation, events, health, auth
from .logging_config import logger

@app.on_event("startup")
async def start_retention_cleanup():
    async def purge_task():
        from .db.threat_event_repository import ThreatEventRepository
        repo = ThreatEventRepository()
        deleted = await repo.purge_expired(RETENTION_DAYS)
        logger.info(f"[Retention] Deleted {deleted} old ThreatEvent documents")

    async def scheduler():
        while True:
            await purge_task()
            await asyncio.sleep(RETENTION_INTERVAL_HOURS * 60 * 60)

    # Kick off the background scheduler (fire‑and‑forget)
    asyncio.create_task(scheduler())

# Include routers
app.include_router(auth.router, prefix="/api")
app.include_router(voice.router, prefix="/api")
app.include_router(phishing.router, prefix="/api")
app.include_router(url.router, prefix="/api")
app.include_router(qr.router, prefix="/api")
app.include_router(account.router, prefix="/api")
app.include_router(explanation.router, prefix="/api")
app.include_router(events.router, prefix="/api")
app.include_router(health.router, prefix="/api")


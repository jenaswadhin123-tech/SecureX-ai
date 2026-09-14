# backend/db/threat_event_repository.py
"""Repository for persisting ThreatEvent documents in MongoDB.

The implementation uses Motor (async MongoDB driver) and works with the
Pydantic ``ThreatEvent`` model defined in ``backend.models.threat_event``.
All CRUD operations are async so they can be awaited directly from the
FastAPI service layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Optional

from bson import ObjectId

from ..models import ThreatEvent
from .mongo_client import get_collection


class ThreatEventRepository:
    """Simple async repository for ``ThreatEvent`` documents.

    The repository abstracts the Motor collection handling and provides
    convenient methods for the rest of the codebase.
    """

    def __init__(self, collection_name: str = "threat_events") -> None:
        self._collection = get_collection(collection_name)

    # ---------------------------------------------------------------------
    # Create
    # ---------------------------------------------------------------------
    async def save(self, event: ThreatEvent) -> str:
        """Insert a ``ThreatEvent`` document.

        Args:
            event: The Pydantic model instance to persist.
        Returns:
            The inserted document's ObjectId as a string.

        Note: Webhook alerting is handled exclusively by FastAPI BackgroundTasks
        in the individual API routers — do NOT call send_threat_alert here to
        avoid duplicate alerts.
        """
        data = event.model_dump()
        # Ensure timestamp exists for sorting / retention policies
        if not data.get("timestamp"):
            data["timestamp"] = datetime.utcnow().isoformat()
        result = await self._collection.insert_one(data)
        return str(result.inserted_id)

    # ---------------------------------------------------------------------
    # Read – single document by id
    # ---------------------------------------------------------------------
    async def get_by_id(self, id_: str) -> Optional[ThreatEvent]:
        """Retrieve a ``ThreatEvent`` by its MongoDB ObjectId.

        Returns ``None`` if the document does not exist.
        """
        try:
            oid = ObjectId(id_)
        except Exception:
            return None
        doc = await self._collection.find_one({"_id": oid})
        if doc:
            doc.pop("_id", None)
            return ThreatEvent(**doc)
        return None

    # ---------------------------------------------------------------------
    # List with optional pagination / filtering
    # ---------------------------------------------------------------------
    async def list(
        self,
        skip: int = 0,
        limit: int = 20,
        risk_level: Optional[str] = None,
    ) -> List[ThreatEvent]:
        """Return a page of events.

        Args:
            skip: Number of documents to skip (for paging).
            limit: Maximum number of documents to return.
            risk_level: Optional filter to only include events of a given risk level.
        """
        query: dict = {}
        if risk_level:
            query["risk_level"] = risk_level
        cursor = (
            self._collection.find(query)
            .sort("timestamp", -1)
            .skip(skip)
            .limit(limit)
        )
        results: List[ThreatEvent] = []
        async for doc in cursor:
            doc.pop("_id", None)
            results.append(ThreatEvent(**doc))
        return results

    # ---------------------------------------------------------------------
    # Delete older documents (retention policy)
    # ---------------------------------------------------------------------
    async def purge_expired(self, older_than_days: int) -> int:
        """Delete events older than ``older_than_days`` days.

        Returns the number of documents removed.
        """
        cutoff = datetime.utcnow() - timedelta(days=older_than_days)
        result = await self._collection.delete_many({"timestamp": {"$lt": cutoff.isoformat()}})
        return result.deleted_count

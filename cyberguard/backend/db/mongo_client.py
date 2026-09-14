# MongoDB async client singleton using Motor

from motor.motor_asyncio import AsyncIOMotorClient
from typing import Optional
import os

# Default URI – can be overridden via environment variable MONGODB_URI
_MONGO_URI: Optional[str] = os.getenv("MONGODB_URI", "mongodb://localhost:27017/cyberguard")

_client: Optional[AsyncIOMotorClient] = None

def get_client() -> AsyncIOMotorClient:
    """Return a singleton Motor client.

    The client is created lazily on first use. The function is safe to call from
    async FastAPI routes because Motor's client creation is inexpensive.
    """
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(_MONGO_URI)
    return _client

def get_collection(name: str):
    """Shortcut to retrieve a collection from the default database.

    Args:
        name: Collection name, e.g. "threat_events".
    Returns:
        AsyncIOMotorCollection instance.
    """
    client = get_client()
    # Safely obtain the default database name without triggering a bool conversion error
    default_db = client.get_default_database()
    db_name = default_db.name if default_db is not None else "cyberguard"
    return client[db_name][name]

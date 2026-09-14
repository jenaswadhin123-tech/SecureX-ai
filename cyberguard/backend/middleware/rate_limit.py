# backend/middleware/rate_limit.py
"""Simple in‑memory rate‑limiting middleware.

The logic mirrors the original implementation but reads limits from
`backend.config` so they are configurable via environment variables.

- RATE_LIMIT_REQUESTS: maximum requests per window per client IP.
- RATE_LIMIT_WINDOW_SECONDS: window duration in seconds.

If the limit is exceeded a ``HTTPException`` with status 429 is raised.
"""

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from collections import defaultdict
import time

from .. import config  # Import central config module

# In‑memory store: {ip: (count, window_start)}
_rate_store = defaultdict(lambda: {"count": 0, "window_start": 0.0})


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "anonymous"
        now = time.time()
        entry = _rate_store[client_ip]

        # Reset window if needed
        if now - entry["window_start"] > config.RATE_LIMIT_WINDOW_SECONDS:
            entry["count"] = 0
            entry["window_start"] = now

        entry["count"] += 1
        if entry["count"] > config.RATE_LIMIT_REQUESTS:
            raise HTTPException(
                status_code=429,
                detail="Too Many Requests – rate limit exceeded",
                headers={"Retry-After": str(config.RATE_LIMIT_WINDOW_SECONDS)},
            )

        response: Response = await call_next(request)
        return response

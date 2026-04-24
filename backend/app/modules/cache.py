"""In-memory TTL cache for scan results and API responses.

Avoids re-running expensive OSINT lookups during demo sessions. Thread-safe
via asyncio (single event loop). Items expire after `ttl` seconds.
"""
from __future__ import annotations

import time
from typing import Any

_store: dict[str, tuple[float, Any]] = {}

DEFAULT_TTL = 300  # 5 minutes


def get(key: str) -> Any | None:
    entry = _store.get(key)
    if entry is None:
        return None
    expires_at, value = entry
    if time.monotonic() > expires_at:
        _store.pop(key, None)
        return None
    return value


def put(key: str, value: Any, ttl: int = DEFAULT_TTL) -> None:
    _store[key] = (time.monotonic() + ttl, value)


def invalidate(key: str) -> None:
    _store.pop(key, None)


def clear() -> None:
    _store.clear()


def stats() -> dict:
    now = time.monotonic()
    alive = sum(1 for _, (exp, _) in _store.items() if exp > now)
    return {"total_entries": len(_store), "alive": alive, "expired": len(_store) - alive}

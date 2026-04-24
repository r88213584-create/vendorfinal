"""Stateless signed URL helpers for sharing audit bundles.

HMAC-SHA256 over `vendor|expires_at` with a secret derived from
`VG_SIGNING_SECRET` (falls back to a deterministic value in DEMO mode so the
hackathon judges can hit the same URL on a fresh boot). The public audit URL
is safe to mail to an auditor — it carries no credentials, expires in 24h by
default, and is read-only (only the audit ZIP is shared, not the admin UI).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from typing import Optional

# Deterministic secret when explicitly in demo mode — makes the QR on the
# final slide survive a server restart. Override in prod by setting the env
# var to anything non-empty.
_SECRET = os.environ.get("VG_SIGNING_SECRET", "vendorguard-demo-signing-key-do-not-use-in-prod")
_TTL_SECONDS = int(os.environ.get("VG_AUDIT_TTL_SECONDS", str(24 * 60 * 60)))


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sign(vendor: str, ttl: Optional[int] = None) -> tuple[str, int]:
    """Return (token, expires_at) where `expires_at` is epoch seconds."""
    expires = int(time.time()) + int(ttl if ttl is not None else _TTL_SECONDS)
    payload = f"{vendor}|{expires}".encode()
    mac = hmac.new(_SECRET.encode(), payload, hashlib.sha256).digest()
    token = f"{_b64(payload)}.{_b64(mac)}"
    return token, expires


def verify(token: str) -> Optional[str]:
    """Return the vendor name if the token is valid and unexpired, else None."""
    try:
        payload_b64, mac_b64 = token.split(".", 1)
        payload = _unb64(payload_b64)
        mac = _unb64(mac_b64)
    except Exception:  # noqa: BLE001
        return None
    expected = hmac.new(_SECRET.encode(), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        vendor, expires_str = payload.decode().split("|", 1)
        if int(expires_str) < int(time.time()):
            return None
        return vendor
    except Exception:  # noqa: BLE001
        return None


def ttl_seconds() -> int:
    return _TTL_SECONDS

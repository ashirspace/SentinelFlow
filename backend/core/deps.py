"""Shared dependencies and audit helpers for SentinelFlow."""
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request

from auth import get_current_user
from core.config import PUBLIC_INGEST_URL
from core.database import db
import ingest_v1 as _v1


async def current_user(request: Request) -> dict:
    """FastAPI dependency to extract and validate the authenticated user from JWT cookie/header."""
    return await get_current_user(request, db)


async def require_admin(user: dict = Depends(current_user)) -> dict:
    """FastAPI dependency to ensure the user has the 'admin' role."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


async def audit(actor_email: str, action: str, target: str = "", meta: Optional[dict] = None):
    """Write an immutable entry to the audit_logs collection."""
    await db.audit_logs.insert_one({
        "id": str(uuid.uuid4()),
        "actor": actor_email,
        "action": action,
        "target": target,
        "meta": meta or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


def public_ingest_base() -> str:
    """Return the configured public base URL for ingestion endpoints."""
    return PUBLIC_INGEST_URL


def url_for(path: str) -> str:
    """Build a fully-qualified public URL if a base is configured, otherwise return path."""
    base = public_ingest_base()
    return f"{base}{path}" if base else path


async def auth_source_from_ingest_key(request: Request) -> dict:
    """Authenticate and rate-limit a push ingestion source using its scoped API key."""
    key = _v1.extract_key(request.headers, request.query_params)
    if not key or not key.startswith(_v1.KEY_PREFIX):
        raise HTTPException(status_code=401, detail="Missing or malformed ingest key")
    key_hash = _v1.hash_key(key)
    source = await db.log_sources.find_one({"ingest_api_key_hash": key_hash})
    if not source:
        raise HTTPException(status_code=401, detail="Invalid ingest key")
    if source.get("paused"):
        raise HTTPException(status_code=423, detail="Source is paused")
    allowed, remaining, reset = _v1.check_rate(key_hash)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({_v1.RATE_LIMIT_PER_MIN}/min). Retry in {reset}s",
            headers={"Retry-After": str(reset)},
        )
    source["_rate_remaining"] = remaining
    source["_rate_reset"] = reset
    return source

"""Push-only, key-authenticated ingestion path.

- Keys are stored only as sha256 hashes (plaintext returned once on
  create/rotate). Prefix `sfk_` for grep-ability.
- Rate limit: 60 requests/min AND 1000 events/req AND 1 MB body per key.
- Push-only: this key does not grant access to any other endpoint.
"""
import hashlib
import secrets
import time
from collections import deque
from typing import Any, Deque, Dict, Optional, Tuple

MAX_BODY_BYTES = 1_000_000       # 1 MB
MAX_EVENTS_PER_REQ = 1000
RATE_LIMIT_PER_MIN = 60
KEY_PREFIX = "sfk_"

# in-memory sliding-window rate limiter keyed by key_hash
_RATE: Dict[str, Deque[float]] = {}


def generate_key() -> Tuple[str, str]:
    """Return (plaintext, sha256_hash)."""
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, hash_key(raw)


def hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def extract_key(headers) -> Optional[str]:
    auth = headers.get("authorization") or headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip() or None
    return headers.get("x-ingest-key") or headers.get("X-Ingest-Key") or None


def check_rate(key_hash: str) -> Tuple[bool, int, int]:
    """Return (allowed, remaining, reset_seconds)."""
    now = time.monotonic()
    window = 60.0
    q = _RATE.setdefault(key_hash, deque())
    while q and (now - q[0]) > window:
        q.popleft()
    remaining = RATE_LIMIT_PER_MIN - len(q)
    if remaining <= 0:
        reset = int(window - (now - q[0])) + 1
        return False, 0, reset
    q.append(now)
    return True, remaining - 1, int(window)


def reset_rate(key_hash: str) -> None:
    _RATE.pop(key_hash, None)


def validate_batch(payload: Any) -> list:
    """Return a list of event dicts or raise ValueError."""
    if isinstance(payload, dict):
        if "events" in payload and isinstance(payload["events"], list):
            events = payload["events"]
        else:
            events = [payload]
    elif isinstance(payload, list):
        events = payload
    else:
        raise ValueError("body must be a JSON object or array")
    if len(events) == 0:
        raise ValueError("no events in payload")
    if len(events) > MAX_EVENTS_PER_REQ:
        raise ValueError(f"too many events (max {MAX_EVENTS_PER_REQ})")
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            raise ValueError(f"event #{i} must be a JSON object")
    return events

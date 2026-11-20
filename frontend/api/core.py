"""Shared API plumbing: Supabase client, API keys, rate limits, client IP."""
from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import HTTPException, Request

DAILY_KEY_LIMIT = int(os.getenv("DAILY_KEY_LIMIT", "100"))
GUEST_PER_MINUTE = int(os.getenv("GUEST_PER_MINUTE", "10"))
GUEST_PER_DAY = int(os.getenv("GUEST_PER_DAY", "100"))

_client = None
_client_lock = threading.Lock()


def supabase():
    """Supabase client, or None when SUPABASE_URL / SUPABASE_KEY are not set."""
    global _client
    if _client is not None:
        return _client
    url, key = os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY")
    if not url or not key:
        return None
    with _client_lock:
        if _client is None:
            from supabase import create_client
            _client = create_client(url, key)
    return _client


def require_db():
    db = supabase()
    if db is None:
        raise HTTPException(status_code=503, detail="Accounts are not available right now.")
    return db


def today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def lookup_key(api_key: str) -> dict:
    if not api_key or not api_key.startswith("pg_") or len(api_key) > 100:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    db = require_db()
    try:
        res = db.table("api_keys").select("*").eq("api_key", api_key).limit(1).execute()
    except Exception as e:
        print(f"[core] key lookup failed: {e}")
        raise HTTPException(status_code=503, detail="Could not verify the API key. Try again shortly.")
    if not res.data:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    return res.data[0]


def requests_today(api_key: str) -> int:
    """Checks made with this key since 00:00 UTC (from the analytics log)."""
    db = supabase()
    if db is None:
        return 0
    try:
        res = (
            db.table("analytics").select("api_key", count="exact")
            .eq("api_key", api_key).gte("created_at", today_utc()).limit(1).execute()
        )
        return res.count or 0
    except Exception as e:
        print(f"[core] usage count failed: {e}")
        return 0


# ── In-memory limiter for guests (per serverless instance, best effort) ──

_hits: dict[str, list[float]] = defaultdict(list)
_hits_lock = threading.Lock()


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")


def guest_limit(request: Request) -> None:
    ip_key = hashlib.sha256(client_ip(request).encode()).hexdigest()[:16]
    now = time.time()
    with _hits_lock:
        if len(_hits) > 5000:
            _hits.clear()
        hits = [t for t in _hits[ip_key] if now - t < 86400]
        per_min = sum(1 for t in hits if now - t < 60)
        if per_min >= GUEST_PER_MINUTE:
            raise HTTPException(status_code=429, detail="Too many checks in a minute. Wait a moment, or use a free API key.",
                                headers={"Retry-After": "60"})
        if len(hits) >= GUEST_PER_DAY:
            raise HTTPException(status_code=429, detail="Daily limit for guest checks reached. Get a free API key for more.")
        hits.append(now)
        _hits[ip_key] = hits

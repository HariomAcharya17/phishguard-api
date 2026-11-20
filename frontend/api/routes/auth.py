from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr

from core import guest_limit, lookup_key, require_db, requests_today, DAILY_KEY_LIMIT

router = APIRouter()


class SignupRequest(BaseModel):
    email: EmailStr


def generate_api_key() -> str:
    return "pg_" + secrets.token_hex(24)


@router.post("/signup")
async def signup(body: SignupRequest, request: Request):
    guest_limit(request)  # slows down bulk key creation
    db = require_db()
    email = body.email.lower()
    try:
        existing = db.table("api_keys").select("id").eq("email", email).limit(1).execute()
    except Exception as e:
        print(f"[auth] lookup failed: {e}")
        raise HTTPException(status_code=503, detail="Could not create a key right now. Try again shortly.")

    if existing.data:
        # Never return an existing key: anyone who knew the email could take it.
        raise HTTPException(
            status_code=409,
            detail="A key was already issued for this email. Use the key you saved, or contact support to reset it.",
        )

    api_key = generate_api_key()
    try:
        db.table("api_keys").insert({"email": email, "api_key": api_key, "requests": 0}).execute()
    except Exception as e:
        print(f"[auth] insert failed: {e}")
        raise HTTPException(status_code=503, detail="Could not create a key right now. Try again shortly.")

    return {
        "message": "API key created. Copy it now; it will not be shown again.",
        "api_key": api_key,
        "email": email,
        "daily_limit": DAILY_KEY_LIMIT,
    }


@router.get("/validate")
async def validate(api_key: str):
    user = lookup_key(api_key)
    used = requests_today(api_key)
    return {
        "valid": True,
        "email": user["email"],
        "requests_today": used,
        "daily_limit": DAILY_KEY_LIMIT,
        "remaining_today": max(0, DAILY_KEY_LIMIT - used),
    }

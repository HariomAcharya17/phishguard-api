from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from core import DAILY_KEY_LIMIT, guest_limit, lookup_key, requests_today, supabase
from detectors import scorer
from detectors.urlparts import InvalidURL

router = APIRouter()


class CheckURLRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


@router.post("/check-url")
async def check_url(body: CheckURLRequest, request: Request, x_api_key: Optional[str] = Header(None)):
    if x_api_key:
        lookup_key(x_api_key)
        used = requests_today(x_api_key)
        if used >= DAILY_KEY_LIMIT:
            raise HTTPException(status_code=429, detail=f"Daily limit of {DAILY_KEY_LIMIT} checks reached. It resets at 00:00 UTC.")
    else:
        guest_limit(request)

    try:
        result = await run_in_threadpool(scorer.analyze, body.url)
    except InvalidURL as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"[check] analysis failed for {body.url!r}: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="Analysis failed. Try again.")

    db = supabase()
    if db is not None:
        try:
            db.table("analytics").insert({
                "api_key": x_api_key,
                "url": result["url"],
                "risk_score": result["risk_score"],
                "is_safe": result["is_safe"],
            }).execute()
        except Exception as e:
            print(f"[check] analytics insert failed: {e}")

    return {**result, "cached": False}

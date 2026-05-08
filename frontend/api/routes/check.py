from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
import os
from typing import Optional
from supabase import create_client
from dotenv import load_dotenv
load_dotenv()
from detectors import scorer

router = APIRouter()

supabase = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_KEY")
)


class CheckURLRequest(BaseModel):
    url: str


async def validate_api_key(api_key: str) -> dict:
    try:
        result = supabase.table("api_keys")\
            .select("*")\
            .eq("api_key", api_key)\
            .execute()

        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=401, detail="Invalid API key")

        return result.data[0]

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/check-url")
async def check_url(
    request: CheckURLRequest,
    x_api_key: Optional[str] = Header(None)
):
    # Validate API key or use Guest mode
    if x_api_key:
        user = await validate_api_key(x_api_key)
        # Check rate limit (100 requests/day for users)
        if user["requests"] >= 100:
            raise HTTPException(
                status_code=429,
                detail="Daily request limit reached. Upgrade for more requests."
            )
    else:
        # Simple Guest Mode
        user = {"id": "guest", "email": "guest@phishguard.io"}
        # You can add a global guest rate limit here later

    url = request.url.strip()

    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        # Run full analysis dynamically (Cache disabled by user request)
        result = scorer.analyze(url)

        # Update request count (only for logged in users)
        if x_api_key:
            try:
                supabase.table("api_keys")\
                    .update({"requests": user.get("requests", 0) + 1})\
                    .eq("api_key", x_api_key)\
                    .execute()
            except:
                pass

        # Log analytics
        try:
            supabase.table("analytics").insert({
                "api_key": x_api_key, # Can be null for guests
                "url": url,
                "risk_score": result.get("risk_score", 0),
                "is_safe": result.get("is_safe", True)
            }).execute()
        except:
            pass

        return {**result, "cached": False}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
import os
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
    x_api_key: str = Header(...)
):
    # Validate API key
    user = await validate_api_key(x_api_key)

    # Check rate limit (100 requests/day free tier)
    if user["requests"] >= 100:
        raise HTTPException(
            status_code=429,
            detail="Daily request limit reached. Upgrade for more requests."
        )

    url = request.url.strip()

    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        # Run full analysis dynamically (Cache disabled by user request)
        result = scorer.analyze(url)

        # Update request count
        supabase.table("api_keys")\
            .update({"requests": user["requests"] + 1})\
            .eq("api_key", x_api_key)\
            .execute()

        # Log analytics
        supabase.table("analytics").insert({
            "api_key": x_api_key,
            "url": url,
            "risk_score": result["risk_score"],
            "is_safe": result["is_safe"]
        }).execute()

        return {**result, "cached": False}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
from fastapi import APIRouter, HTTPException, Header
import os
from dotenv import load_dotenv
load_dotenv()
from supabase import create_client

router = APIRouter()

supabase = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_KEY")
)


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


@router.get("/analytics")
async def get_analytics(x_api_key: str = Header(...)):

    # Validate API key
    user = await validate_api_key(x_api_key)

    try:
        # Get all requests for this API key
        result = supabase.table("analytics")\
            .select("*")\
            .eq("api_key", x_api_key)\
            .execute()

        data = result.data if result.data else []

        total_requests = len(data)
        threats_detected = len([r for r in data if not r["is_safe"]])
        safe_urls = len([r for r in data if r["is_safe"]])

        # Requests today
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        requests_today = len([
            r for r in data
            if r.get("created_at", "").startswith(today)
        ])

        # Average risk score
        avg_risk = round(
            sum(r["risk_score"] for r in data) / total_requests, 4
        ) if total_requests > 0 else 0.0

        # Recent 10 requests
        recent = sorted(
            data,
            key=lambda x: x.get("created_at", ""),
            reverse=True
        )[:10]

        return {
            "email": user["email"],
            "total_requests": total_requests,
            "threats_detected": threats_detected,
            "safe_urls": safe_urls,
            "requests_today": requests_today,
            "daily_limit": 100,
            "remaining_today": 100 - user["requests"],
            "average_risk_score": avg_risk,
            "recent_checks": recent
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
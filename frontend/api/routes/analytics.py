from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException

from core import DAILY_KEY_LIMIT, lookup_key, require_db, today_utc

router = APIRouter()


@router.get("/analytics")
async def get_analytics(x_api_key: str = Header(...)):
    user = lookup_key(x_api_key)
    db = require_db()
    try:
        res = (
            db.table("analytics").select("url,risk_score,is_safe,created_at")
            .eq("api_key", x_api_key).order("created_at", desc=True).limit(1000).execute()
        )
    except Exception as e:
        print(f"[analytics] query failed: {e}")
        raise HTTPException(status_code=503, detail="Could not load usage right now.")

    rows = res.data or []
    total = len(rows)
    today = today_utc()
    used_today = sum(1 for r in rows if (r.get("created_at") or "").startswith(today))
    threats = sum(1 for r in rows if not r.get("is_safe"))

    return {
        "email": user["email"],
        "total_requests": total,
        "threats_detected": threats,
        "safe_urls": total - threats,
        "requests_today": used_today,
        "daily_limit": DAILY_KEY_LIMIT,
        "remaining_today": max(0, DAILY_KEY_LIMIT - used_today),
        "average_risk_score": round(sum(r.get("risk_score") or 0 for r in rows) / total, 4) if total else 0.0,
        "recent_checks": rows[:10],
    }

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
import uuid
import os
from dotenv import load_dotenv
load_dotenv()
from supabase import create_client

router = APIRouter()

supabase = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_KEY")
)


class SignupRequest(BaseModel):
    email: EmailStr


def generate_api_key() -> str:
    return f"pg_{uuid.uuid4().hex}"


@router.post("/signup")
async def signup(request: SignupRequest):
    try:
        # Check if email already exists
        existing = supabase.table("api_keys")\
            .select("*")\
            .eq("email", request.email)\
            .execute()

        if existing.data and len(existing.data) > 0:
            return {
                "message": "Email already registered",
                "api_key": existing.data[0]["api_key"],
                "email": request.email
            }

        # Generate new API key
        api_key = generate_api_key()

        # Save to Supabase
        supabase.table("api_keys").insert({
            "email": request.email,
            "api_key": api_key,
            "requests": 0
        }).execute()

        return {
            "message": "API key generated successfully",
            "api_key": api_key,
            "email": request.email
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/validate")
async def validate(api_key: str):
    try:
        result = supabase.table("api_keys")\
            .select("*")\
            .eq("api_key", api_key)\
            .execute()

        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=401, detail="Invalid API key")

        return {
            "valid": True,
            "email": result.data[0]["email"],
            "requests": result.data[0]["requests"]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
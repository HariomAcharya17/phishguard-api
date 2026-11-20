import os
import sys

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Let "routes", "detectors" and "core" import as top-level packages on Vercel.
sys.path.insert(0, os.path.dirname(__file__))

# Local development only; Vercel provides environment variables directly.
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env.local"))

from routes import analytics, auth, check  # noqa: E402
from detectors import ml_model  # noqa: E402

app = FastAPI(
    title="PhishGuard API",
    description="Checks links for phishing using reputation feeds, URL analysis, domain intelligence and a hostname classifier.",
    version="2.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,
)

# Public API: any site may call it. No cookies are used, so credentials stay off.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
    max_age=86400,
)


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    first = exc.errors()[0] if exc.errors() else {}
    field = ".".join(str(x) for x in first.get("loc", [])[1:]) or "request"
    return JSONResponse(status_code=422, content={"detail": f"Invalid {field}: {first.get('msg', 'bad value')}"})


@app.exception_handler(404)
async def not_found(request: Request, _exc):
    return JSONResponse(status_code=404, content={"detail": "Not found.", "path": request.url.path})


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    print(f"[api] unhandled {type(exc).__name__}: {exc}")
    return JSONResponse(status_code=500, content={"detail": "Something went wrong. Try again."})


app.include_router(check.router, prefix="/api")
app.include_router(auth.router, prefix="/api/auth")
app.include_router(analytics.router, prefix="/api")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": app.version,
        "model_loaded": ml_model.MODEL_LOADED,
        "sources": {
            "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            "safe_browsing": bool(os.getenv("GOOGLE_SAFE_BROWSING_KEY")),
            "whois": bool(os.getenv("WHOIS_API_KEY")),
            "openphish": os.getenv("OPENPHISH_DISABLED") != "1",
            "accounts": bool(os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_KEY")),
        },
    }

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

# Load .env explicitly before anything else
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

from routes import check, auth, analytics

app = FastAPI(
    title="PhishGuard API",
    description="Phishing URL Detection API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(check.router, prefix="/api")
app.include_router(auth.router, prefix="/api/auth")
app.include_router(analytics.router, prefix="/api")

@app.get("/")
def root():
    return {"message": "PhishGuard API is running 🛡️"}
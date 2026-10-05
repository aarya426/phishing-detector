import os
import sys
import time
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

# Ensure app directory is importable
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.ml.model import engine

APP_VERSION = "v1.2.0-calibrated-rf"

# In-memory sliding-window rate limiter (e.g., 30 requests / 60 seconds per IP)
RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW_SECONDS = 60
client_request_history: Dict[str, List[float]] = {}

def check_rate_limit(client_ip: str):
    """Simple in-memory rate limiter per IP address."""
    now = time.time()
    history = client_request_history.setdefault(client_ip, [])
    # Filter out entries older than window
    client_request_history[client_ip] = [t for t in history if now - t < RATE_LIMIT_WINDOW_SECONDS]
    if len(client_request_history[client_ip]) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded ({RATE_LIMIT_REQUESTS} requests/minute). Please wait before scanning again."
        )
    client_request_history[client_ip].append(now)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load ML models once at server startup."""
    print(f"[+] Initializing PhishGuard AI models ({APP_VERSION})...")
    engine._ensure_models_loaded()
    print("[+] Models successfully loaded into memory.")
    yield
    print("[-] Shutting down PhishGuard AI server.")

app = FastAPI(
    title="PhishGuard AI — Phishing Detection API",
    description="Calibrated Machine Learning API for detecting phishing URLs and social engineering messages",
    version=APP_VERSION,
    lifespan=lifespan
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files directory
STATIC_DIR = BASE_DIR / "app" / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Request Models with validation
class URLScanRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze", max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url_content(cls, v: str) -> str:
        cleaned = v.strip()
        if len(cleaned) < 3:
            raise ValueError("URL is too short to be valid.")
        # Reject dangerous URI schemes
        lowered = cleaned.lower()
        if lowered.startswith(("javascript:", "data:", "file:", "vbscript:")):
            raise ValueError("Disallowed URI scheme detected. Only HTTP/HTTPS destinations are permitted.")
        return cleaned

class TextScanRequest(BaseModel):
    text: str = Field(..., description="The email or message text to analyze", max_length=15000)

    @field_validator("text")
    @classmethod
    def validate_text_content(cls, v: str) -> str:
        cleaned = v.strip()
        if len(cleaned) < 5:
            raise ValueError("Text must be at least 5 characters long.")
        return cleaned

@app.get("/")
def serve_index():
    """Serve the cyber dashboard frontend."""
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Index HTML not found")
    return FileResponse(str(index_path))

@app.post("/api/scan-url")
def scan_url(payload: URLScanRequest, request: Request) -> Dict[str, Any]:
    """
    Analyze a given URL with safe redirect expansion, feature extraction, and calibrated ML inference.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_rate_limit(client_ip)

    try:
        result = engine.analyze_url(payload.url, check_network=True, resolve_shorteners=True)
        return {
            "success": True,
            "version": APP_VERSION,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/scan-text")
def scan_text(payload: TextScanRequest, request: Request) -> Dict[str, Any]:
    """
    Analyze message or email content for social engineering cues AND scan all embedded URLs.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_rate_limit(client_ip)

    try:
        result = engine.analyze_text(payload.text)
        return {
            "success": True,
            "version": APP_VERSION,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Text analysis failed: {str(e)}")

@app.get("/api/model-stats")
def model_stats() -> Dict[str, Any]:
    """Return verified model metrics, confusion matrix, ROC-AUC, and feature rankings."""
    try:
        stats = engine.get_stats()
        return {
            "success": True,
            "version": APP_VERSION,
            "data": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch model stats: {str(e)}")

@app.get("/api/sample-urls")
def sample_urls() -> Dict[str, Any]:
    """Return diverse preset sample URLs for testing."""
    return {
        "success": True,
        "samples": [
            {
                "label": "Legitimate (Google - Tranco Top 1k)",
                "url": "https://www.google.com",
                "expected": "Verified Safe (Allowlisted)",
                "category": "safe"
            },
            {
                "label": "Legitimate (GitHub Linux Repo)",
                "url": "https://github.com/torvalds/linux",
                "expected": "Verified Safe",
                "category": "safe"
            },
            {
                "label": "Typosquatting Lookalike (paypa1-security.com)",
                "url": "https://paypa1-security-center.com/webscr/login",
                "expected": "Dangerous Phishing (Brand Typosquat)",
                "category": "danger"
            },
            {
                "label": "Phishing (Deceptive PayPal Domain .xyz)",
                "url": "http://paypal-account-verification-security.xyz/login.php",
                "expected": "Dangerous Phishing",
                "category": "danger"
            },
            {
                "label": "Phishing (Direct IP Hostname + Bank)",
                "url": "http://192.168.1.100/chase-online/auth/login.html",
                "expected": "Dangerous Phishing",
                "category": "danger"
            },
            {
                "label": "Suspicious (URL Shortener)",
                "url": "http://tinyurl.com/bank-urgent-fix",
                "expected": "Suspicious / Redirect Resolved",
                "category": "warning"
            }
        ]
    }

@app.get("/api/health")
def health() -> Dict[str, str]:
    return {
        "status": "ok",
        "app": "PhishGuard AI Detection System",
        "version": APP_VERSION
    }

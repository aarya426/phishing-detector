import os
import sys
from pathlib import Path
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Ensure app directory is importable
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.ml.model import engine

app = FastAPI(
    title="Phishing Detection API",
    description="Machine Learning API for identifying phishing URLs and social engineering messages",
    version="1.0.0"
)

# Enable CORS for all origins for local flexibility
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

# Request Models
class URLScanRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze", min_length=3)

class TextScanRequest(BaseModel):
    text: str = Field(..., description="The email or message text to analyze", min_length=5)

@app.get("/")
def serve_index():
    """Serve the cyber dashboard frontend."""
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Index HTML not found")
    return FileResponse(str(index_path))

@app.post("/api/scan-url")
def scan_url(payload: URLScanRequest) -> Dict[str, Any]:
    """
    Analyze a given URL with feature extraction and ML inference.
    """
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    try:
        result = engine.analyze_url(url)
        return {
            "success": True,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/scan-text")
def scan_text(payload: TextScanRequest) -> Dict[str, Any]:
    """
    Analyze message or email content for social engineering / phishing cues.
    """
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    try:
        result = engine.analyze_text(text)
        return {
            "success": True,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Text analysis failed: {str(e)}")

@app.get("/api/model-stats")
def model_stats() -> Dict[str, Any]:
    """Return model metrics and feature importance statistics."""
    try:
        stats = engine.get_stats()
        return {
            "success": True,
            "data": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch model stats: {str(e)}")

@app.get("/api/sample-urls")
def sample_urls() -> Dict[str, Any]:
    """Return diverse preset sample URLs for quick testing in UI."""
    return {
        "success": True,
        "samples": [
            {
                "label": "Legitimate (Google)",
                "url": "https://www.google.com",
                "expected": "Safe",
                "category": "safe"
            },
            {
                "label": "Legitimate (GitHub Linux Repo)",
                "url": "https://github.com/torvalds/linux",
                "expected": "Safe",
                "category": "safe"
            },
            {
                "label": "Phishing (Deceptive PayPal Domain)",
                "url": "http://paypal-account-verification-security.xyz/login.php",
                "expected": "Dangerous Phishing",
                "category": "danger"
            },
            {
                "label": "Phishing (IP Hostname + Bank)",
                "url": "http://192.168.1.100/chase-online/auth/login.html",
                "expected": "Dangerous Phishing",
                "category": "danger"
            },
            {
                "label": "Phishing (Suspicious Subdomain + TLD)",
                "url": "http://wellsfargo.com.security-alert-user-auth.ga/login.asp",
                "expected": "Dangerous Phishing",
                "category": "danger"
            },
            {
                "label": "Suspicious (URL Shortener)",
                "url": "http://tinyurl.com/bank-urgent-fix",
                "expected": "Suspicious",
                "category": "warning"
            }
        ]
    }

@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "app": "Phishing Detection System", "version": "1.0.0"}

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_sample_urls_endpoint():
    response = client.get("/api/sample-urls")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["samples"]) > 0

def test_model_stats_endpoint():
    response = client.get("/api/model-stats")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "url_metrics" in data["data"]
    assert "top_features" in data["data"]

def test_scan_url_legitimate():
    response = client.post("/api/scan-url", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    res = response.json()
    assert res["success"] is True
    data = res["data"]
    assert data["verdict"] == "SAFE"
    assert data["risk_score"] < 35.0

def test_scan_url_phishing():
    response = client.post("/api/scan-url", json={"url": "http://paypal-account-verification-security.xyz/login.php"})
    assert response.status_code == 200
    res = response.json()
    assert res["success"] is True
    data = res["data"]
    assert "PHISHING" in data["verdict"] or data["risk_score"] >= 70.0
    assert len(data["diagnostics"]) > 0

def test_scan_text_urgent_phishing():
    scam_text = "URGENT: Your bank account has been suspended due to suspicious activity. Click here to verify your identity immediately: http://chase-security-fix.xyz"
    response = client.post("/api/scan-text", json={"text": scam_text})
    assert response.status_code == 200
    res = response.json()
    assert res["success"] is True
    data = res["data"]
    assert data["risk_score"] >= 70.0
    assert data["indicators"]["urgency_score"] > 0

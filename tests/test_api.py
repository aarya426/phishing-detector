import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "v1.2.0" in data["version"]

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
    metrics = data["data"]["url_metrics"]
    assert "accuracy" in metrics
    assert "roc_auc" in metrics
    assert "confusion_matrix" in metrics
    assert "tn" in metrics["confusion_matrix"]
    assert "tp" in metrics["confusion_matrix"]
    assert len(data["data"]["top_features"]) > 0

def test_scan_url_allowlisted():
    response = client.post("/api/scan-url", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    res = response.json()
    assert res["success"] is True
    data = res["data"]
    assert data["is_allowlisted"] is True
    assert data["risk_score"] <= 15.0

def test_scan_url_brand_typosquatting():
    response = client.post("/api/scan-url", json={"url": "https://paypa1-security-center.com/webscr/login"})
    assert response.status_code == 200
    res = response.json()
    assert res["success"] is True
    data = res["data"]
    assert data["risk_score"] >= 70.0
    assert any("typosquatting" in d.lower() for d in data["diagnostics"])
    assert len(data["feature_contributions"]) > 0

def test_scan_url_validation_rejection():
    # Dangerous URI scheme
    response = client.post("/api/scan-url", json={"url": "javascript:alert(1)"})
    assert response.status_code == 422  # Pydantic validation error

def test_scan_text_extracts_embedded_urls():
    text_with_link = "URGENT: Your account has been locked. Verify immediately at http://paypal-account-verification-security.xyz/login.php"
    response = client.post("/api/scan-text", json={"text": text_with_link})
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["risk_score"] >= 70.0
    assert len(data["embedded_url_scans"]) >= 1
    embedded = data["embedded_url_scans"][0]
    assert "paypal" in embedded["url"]
    assert embedded["risk_score"] >= 70.0

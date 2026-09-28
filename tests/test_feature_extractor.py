import pytest
from app.ml.feature_extractor import (
    extract_url_features, 
    calculate_entropy, 
    is_ip_address,
    FEATURE_NAMES
)

def test_entropy_calculation():
    # Identical characters have zero entropy
    assert calculate_entropy("aaaa") == 0.0
    # High randomness has higher entropy
    entropy_random = calculate_entropy("q7w8e9r0ty1ui2op3")
    entropy_word = calculate_entropy("google")
    assert entropy_random > entropy_word

def test_ip_address_detection():
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("10.0.0.1:8080") is True
    assert is_ip_address("google.com") is False
    assert is_ip_address("192.168.1.300") is False  # Invalid octet > 255

def test_extract_features_legitimate_url():
    url = "https://www.google.com/search?q=machine+learning"
    vector, features, diagnostics = extract_url_features(url)
    
    assert len(vector) == len(FEATURE_NAMES)
    assert features["is_https"] == 1
    assert features["has_ip_address"] == 0
    assert features["has_punycode"] == 0
    assert features["hostname"] == "www.google.com"

def test_extract_features_phishing_ip_url():
    url = "http://192.168.1.100/chase-online/auth/login.html"
    vector, features, diagnostics = extract_url_features(url)
    
    assert features["has_ip_address"] == 1
    assert features["is_https"] == 0
    assert features["has_suspicious_keyword"] == 1
    assert "login" in features["keywords_found"]
    # Check diagnostics
    assert any("Direct IP address" in d for d in diagnostics)

def test_extract_features_punycode():
    url = "http://xn--googl-rsa.com/login"
    vector, features, diagnostics = extract_url_features(url)
    
    assert features["has_punycode"] == 1
    assert any("Punycode" in d for d in diagnostics)

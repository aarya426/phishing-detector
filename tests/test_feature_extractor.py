import pytest
from app.ml.feature_extractor import (
    extract_url_features, 
    calculate_entropy, 
    is_ip_address,
    is_safe_public_ip,
    extract_root_domain,
    check_brand_typosquatting,
    FEATURE_NAMES
)

def test_entropy_calculation():
    assert calculate_entropy("aaaa") == 0.0
    entropy_random = calculate_entropy("q7w8e9r0ty1ui2op3")
    entropy_word = calculate_entropy("google")
    assert entropy_random > entropy_word

def test_ip_address_detection():
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("10.0.0.1:8080") is True
    assert is_ip_address("google.com") is False

def test_ssrf_safety_check():
    # Private / Loopback IPs must be flagged as unsafe
    assert is_safe_public_ip("127.0.0.1") is False
    assert is_safe_public_ip("10.0.0.1") is False
    assert is_safe_public_ip("192.168.1.1") is False
    assert is_safe_public_ip("172.16.0.1") is False
    assert is_safe_public_ip("169.254.169.254") is False
    assert is_safe_public_ip("::1") is False
    # Valid public IPs
    assert is_safe_public_ip("8.8.8.8") is True
    assert is_safe_public_ip("1.1.1.1") is True

def test_root_domain_extraction():
    assert extract_root_domain("www.google.com") == "google.com"
    assert extract_root_domain("login.secure.paypal.com") == "paypal.com"
    assert extract_root_domain("subdomain.service.co.uk") == "service.co.uk"
    assert extract_root_domain("192.168.1.1") == "192.168.1.1"

def test_brand_typosquatting_detection():
    # Edit distance 1 to "paypal"
    is_typo, in_sub, brand = check_brand_typosquatting("paypa1.com")
    assert is_typo is True
    assert brand == "paypal"

    # Edit distance 1 to "google"
    is_typo, in_sub, brand = check_brand_typosquatting("g00gle.com")
    assert is_typo is True
    assert brand == "google"

    # Brand in subdomain
    is_typo, in_sub, brand = check_brand_typosquatting("paypal.com.user-auth-portal.xyz")
    assert in_sub is True
    assert brand == "paypal"

    # Legitimate root domain is NOT flagged as typosquat
    is_typo, in_sub, brand = check_brand_typosquatting("paypal.com")
    assert is_typo is False
    assert in_sub is False

def test_extract_features_tranco_top():
    url = "https://www.google.com/search?q=machine+learning"
    vector, features, diagnostics = extract_url_features(url)
    
    assert len(vector) == len(FEATURE_NAMES)
    assert features["is_tranco_top"] == 1
    assert features["is_brand_typosquat"] == 0
    assert features["has_ip_address"] == 0
    assert any("Tranco Top 1k" in d for d in diagnostics)

def test_extract_features_phishing_typosquat():
    url = "https://paypa1-security-center.com/webscr/login"
    vector, features, diagnostics = extract_url_features(url)
    
    assert features["is_brand_typosquat"] == 1
    assert features["matched_brand"] == "paypal"
    assert any("Brand typosquatting" in d for d in diagnostics)

import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple

# Suspicious keywords frequently used in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", 
    "account", "update", "banking", "secure", "security", "confirm", 
    "password", "auth", "credential", "recover", "wallet", "support", 
    "service", "billing", "invoice", "payment", "authenticate", "validation",
    "paypal", "apple", "netflix", "microsoft", "amazon", "google", "chase", "wellsfargo"
]

# Suspicious or high-abuse TLDs often used in disposable phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "fit", "live", "cf", "ga", "gq", "ml", "tk",
    "icu", "cam", "bid", "loan", "men", "work", "date", "racing", "kim",
    "country", "click", "rest", "stream", "download", "review", "party"
}

# Known URL shorteners
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "goo.gl", "tiny.cc", "rebrand.ly", "rb.gy", "v.gd"
}

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_at_symbols",
    "num_slashes",
    "num_question_marks",
    "num_equal_signs",
    "num_percent_signs",
    "num_digits",
    "digit_ratio",
    "has_ip_address",
    "is_https",
    "subdomain_count",
    "has_suspicious_tld",
    "has_suspicious_keyword",
    "suspicious_keyword_count",
    "domain_entropy",
    "has_shortener",
    "has_punycode",
    "num_redirections_markers"
]

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)

def is_ip_address(hostname: str) -> bool:
    """Check if the hostname is an IPv4 or IPv6 address."""
    # IPv4 regex check
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
    if re.match(ipv4_pattern, hostname):
        parts = hostname.split(":")[0].split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    # Basic IPv6 check
    if ":" in hostname and not re.search(r"[a-z]", hostname.lower()):
        return True
    return False

def normalize_url(url: str) -> str:
    """Ensure URL has scheme for parsing."""
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    return url

def extract_url_features(url: str) -> Tuple[List[float], Dict[str, Any], List[str]]:
    """
    Extract numerical features, feature dictionary, and human-readable threat indicators.
    Returns:
        (feature_vector, feature_dict, diagnostic_reasons)
    """
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_url_lower = normalized.lower()

    # Domain parts & TLD
    domain_parts = [p for p in hostname.split(".") if p]
    tld = domain_parts[-1] if domain_parts else ""
    subdomain_count = max(0, len(domain_parts) - 2) if not is_ip_address(hostname) else 0

    # Numerical metrics
    url_len = len(normalized)
    domain_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    num_dots = normalized.count(".")
    num_hyphens = normalized.count("-")
    num_at = normalized.count("@")
    num_slashes = normalized.count("/")
    num_question = normalized.count("?")
    num_equal = normalized.count("=")
    num_percent = normalized.count("%")
    num_digits = sum(c.isdigit() for c in normalized)
    digit_ratio = round(num_digits / max(1, url_len), 4)

    has_ip = 1 if is_ip_address(hostname) else 0
    is_https = 1 if parsed.scheme.lower() == "https" else 0
    has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Keyword check
    keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url_lower]
    has_suspicious_keyword = 1 if len(keywords_found) > 0 else 0
    suspicious_keyword_count = len(keywords_found)

    domain_entropy = calculate_entropy(hostname)
    has_shortener = 1 if hostname in SHORTENERS else 0
    has_punycode = 1 if "xn--" in hostname else 0
    num_redirections = 1 if "//" in path else 0

    features_dict: Dict[str, Any] = {
        "url_length": url_len,
        "domain_length": domain_len,
        "path_length": path_len,
        "query_length": query_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_at_symbols": num_at,
        "num_slashes": num_slashes,
        "num_question_marks": num_question,
        "num_equal_signs": num_equal,
        "num_percent_signs": num_percent,
        "num_digits": num_digits,
        "digit_ratio": digit_ratio,
        "has_ip_address": has_ip,
        "is_https": is_https,
        "subdomain_count": subdomain_count,
        "has_suspicious_tld": has_suspicious_tld,
        "has_suspicious_keyword": has_suspicious_keyword,
        "suspicious_keyword_count": suspicious_keyword_count,
        "domain_entropy": domain_entropy,
        "has_shortener": has_shortener,
        "has_punycode": has_punycode,
        "num_redirections_markers": num_redirections,
        # Auxiliary info for UI
        "hostname": hostname,
        "tld": tld,
        "keywords_found": keywords_found
    }

    feature_vector = [float(features_dict[name]) for name in FEATURE_NAMES]

    # Diagnostic indicators for Explainable AI
    diagnostics: List[str] = []
    if has_ip:
        diagnostics.append("Direct IP address used as hostname instead of a legitimate domain.")
    if num_at > 0:
        diagnostics.append("Contains '@' symbol, often used to bypass visual inspection and redirect users.")
    if has_punycode:
        diagnostics.append("Uses Punycode ('xn--') homograph characters resembling legitimate letters.")
    if has_suspicious_tld:
        diagnostics.append(f"Uses top-level domain '.{tld}', which is frequently associated with disposable phishing campaigns.")
    if has_shortener:
        diagnostics.append("Uses a known URL shortening service to conceal the final destination.")
    if subdomain_count >= 3:
        diagnostics.append(f"Excessive nested subdomains ({subdomain_count} levels) masquerading as legitimate portals.")
    if keywords_found:
        top_kws = ", ".join(f"'{k}'" for k in keywords_found[:4])
        diagnostics.append(f"Contains credential or security-sensitive keywords: {top_kws}.")
    if not is_https:
        diagnostics.append("Unencrypted connection (HTTP instead of HTTPS).")
    if domain_entropy > 3.8 and not has_ip:
        diagnostics.append(f"High domain character randomness (entropy {domain_entropy}), indicating potential automated generation (DGA).")
    if num_dots >= 4:
        diagnostics.append(f"Abnormally high dot count ({num_dots} dots) in URL structure.")
    if url_len > 100:
        diagnostics.append(f"Abnormally long URL ({url_len} chars), typical of token harvesting or obfuscated payloads.")
    if num_redirections > 0:
        diagnostics.append("Contains secondary '//' redirection markers within the path.")

    return feature_vector, features_dict, diagnostics

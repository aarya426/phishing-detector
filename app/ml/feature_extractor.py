import math
import re
import socket
import ipaddress
import urllib.parse
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple, Set

# Suspicious keywords frequently used in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", 
    "account", "update", "banking", "secure", "security", "confirm", 
    "password", "auth", "credential", "recover", "wallet", "support", 
    "service", "billing", "invoice", "payment", "authenticate", "validation",
    "webscr", "myaccount", "ebayisapi", "securelogin"
]

# High-value brands often targeted by phishing / typosquatting
TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "chase", "bankofamerica", "wellsfargo", "binance", "coinbase",
    "facebook", "instagram", "dropbox", "adobe", "linkedin", "twitter",
    "ebay", "steam", "citibank", "whatsapp"
]

# High-abuse TLDs often used in disposable phishing campaigns
SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "buzz", "fit", "live", "cf", "ga", "gq", "ml", "tk",
    "icu", "cam", "bid", "loan", "men", "work", "date", "racing", "kim",
    "country", "click", "rest", "stream", "download", "review", "party"
}

# Known URL shorteners
SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "goo.gl", "tiny.cc", "rebrand.ly", "rb.gy", "v.gd"
}

# Curated Tranco Top 1k / Alexa Top Domains (Allowlist Tier)
TRANCO_TOP_DOMAINS: Set[str] = {
    "google.com", "youtube.com", "github.com", "wikipedia.org", "amazon.com",
    "microsoft.com", "apple.com", "twitter.com", "x.com", "facebook.com",
    "instagram.com", "linkedin.com", "reddit.com", "netflix.com", "paypal.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "stackoverflow.com",
    "medium.com", "yahoo.com", "cloudflare.com", "wordpress.org", "adobe.com",
    "spotify.com", "dropbox.com", "zoom.us", "ebay.com", "salesforce.com",
    "steampowered.com", "bing.com", "duckduckgo.com", "weather.com", "cnn.com",
    "bbc.com", "nytimes.com", "wsj.com", "forbes.com", "nih.gov", "who.int",
    "mit.edu", "stanford.edu", "harvard.edu", "pypi.org", "kaggle.com",
    "fastapi.tiangolo.com", "tailwindcss.com", "arxiv.org", "mozilla.org",
    "coinbase.com", "binance.com", "twitch.tv", "vimeo.com", "whatsapp.com"
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
    "num_redirections_markers",
    "is_tranco_top",
    "is_brand_typosquat",
    "brand_in_subdomain",
    "dns_resolves"
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

def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def is_ip_address(hostname: str) -> bool:
    """Check if the hostname is an IPv4 or IPv6 address."""
    clean_host = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False

def is_safe_public_ip(ip_str: str) -> bool:
    """
    SSRF Protection: Ensure IP is a safe public routable address.
    Rejects private (RFC 1918), loopback, link-local, multicast, and reserved ranges.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
        return ip.is_global and not (
            ip.is_private or ip.is_loopback or ip.is_link_local or 
            ip.is_multicast or ip.is_reserved or ip.is_unspecified
        )
    except ValueError:
        return False

def extract_root_domain(hostname: str) -> str:
    """
    Extract the root domain (second-level domain + TLD) from a hostname.
    Handles common two-part TLDs (e.g. .co.uk, .com.au) and standard single TLDs.
    """
    if is_ip_address(hostname) or not hostname:
        return hostname

    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return hostname.lower()

    two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.jp", "com.br", "co.in"}
    last_two = ".".join(parts[-2:])
    if last_two in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    
    return ".".join(parts[-2:])

def check_brand_typosquatting(hostname: str) -> Tuple[bool, bool, str]:
    """
    Inspect domain and subdomains for brand impersonation and typosquatting.
    Returns: (is_typosquat, brand_in_subdomain, matched_brand)
    """
    root_domain = extract_root_domain(hostname)
    domain_label = root_domain.split(".")[0] if "." in root_domain else root_domain
    
    # Check 1: Brand name placed in subdomain while root domain is different
    for brand in TARGET_BRANDS:
        if brand in hostname and brand != domain_label and not hostname.endswith(f".{brand}.com"):
            return False, True, brand

    # Check 2: Edit distance on root domain label and tokenized components
    tokens = re.split(r"[-_.]", domain_label)
    if domain_label not in tokens:
        tokens.append(domain_label)

    for token in tokens:
        if not token:
            continue
        for brand in TARGET_BRANDS:
            if token == brand:
                continue
            dist = levenshtein_distance(token, brand)
            if dist in (1, 2) and abs(len(token) - len(brand)) <= 2:
                return True, False, brand

    return False, False, ""

def check_dns_resolves(hostname: str, timeout: float = 1.5) -> bool:
    """Check if the hostname resolves via DNS to an active IP address."""
    if not hostname or is_ip_address(hostname):
        return True
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(hostname, None)
        return True
    except (socket.gaierror, socket.timeout, Exception):
        return False

def normalize_url(url: str) -> str:
    """Ensure URL has scheme and clean whitespace."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url

def safe_resolve_redirects(url: str, max_hops: int = 3, timeout: float = 2.0) -> Tuple[str, List[str], bool]:
    """
    Safely follow redirects for URL shorteners with strict SSRF protection.
    Returns: (final_url, redirect_chain, was_blocked_by_ssrf)
    """
    import http.client
    
    current_url = normalize_url(url)
    chain = [current_url]
    
    for _ in range(max_hops):
        try:
            parsed = urlparse(current_url)
            hostname = parsed.hostname or ""
            if not hostname:
                break
                
            # SSRF Guard: resolve host to IP and ensure it is safe public IP
            try:
                addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
                ip = addr_info[0][4][0]
                if not is_safe_public_ip(ip):
                    return current_url, chain, True  # Blocked by SSRF
            except Exception:
                break  # DNS failed, abort redirect resolution
                
            # Perform HEAD or GET with short timeout
            is_ssl = (parsed.scheme == "https")
            conn_class = http.client.HTTPSConnection if is_ssl else http.client.HTTPConnection
            port = parsed.port or (443 if is_ssl else 80)
            
            conn = conn_class(hostname, port, timeout=timeout)
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
                
            conn.request("HEAD", path, headers={"User-Agent": "PhishGuard-Bot/1.2"})
            res = conn.getresponse()
            
            if res.status in (301, 302, 303, 307, 308):
                location = res.getheader("Location")
                if not location:
                    break
                # Handle relative redirect
                current_url = urllib.parse.urljoin(current_url, location)
                chain.append(current_url)
            else:
                break
        except Exception:
            break

    return current_url, chain, False

def extract_url_features(url: str, check_network: bool = False) -> Tuple[List[float], Dict[str, Any], List[str]]:
    """
    Extract 27 numerical features, feature dictionary, and diagnostic reasons.
    """
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_url_lower = normalized.lower()

    # Root domain & TLD extraction
    root_domain = extract_root_domain(hostname)
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

    # Advanced verification features
    is_tranco_top = 1 if root_domain in TRANCO_TOP_DOMAINS else 0
    is_brand_typosquat, brand_in_subdomain, matched_brand = check_brand_typosquatting(hostname)
    
    dns_resolves = 1
    if check_network:
        dns_resolves = 1 if check_dns_resolves(hostname) else 0

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
        "is_tranco_top": is_tranco_top,
        "is_brand_typosquat": 1 if is_brand_typosquat else 0,
        "brand_in_subdomain": 1 if brand_in_subdomain else 0,
        "dns_resolves": dns_resolves,
        # Metadata
        "hostname": hostname,
        "root_domain": root_domain,
        "tld": tld,
        "matched_brand": matched_brand,
        "keywords_found": keywords_found
    }

    feature_vector = [float(features_dict[name]) for name in FEATURE_NAMES]

    # Diagnostic indicators
    diagnostics: List[str] = []
    if is_brand_typosquat:
        diagnostics.append(f"Brand typosquatting detected: domain mimics '{matched_brand}' using visual lookalike spelling.")
    if brand_in_subdomain:
        diagnostics.append(f"Deceptive subdomain masquerading: '{matched_brand}' appears in subdomain while root domain is '{root_domain}'.")
    if is_tranco_top:
        diagnostics.append(f"Verified authoritative domain: root domain '{root_domain}' is indexed in the Tranco Top 1k Allowlist.")
    if has_ip:
        diagnostics.append("Direct IP address used as hostname instead of a registered domain.")
    if num_at > 0:
        diagnostics.append("Contains '@' symbol, which causes browsers to ignore preceding credentials and redirect destinations.")
    if has_punycode:
        diagnostics.append("Uses Punycode ('xn--') homograph characters resembling legitimate letters.")
    if has_suspicious_tld:
        diagnostics.append(f"Uses top-level domain '.{tld}', which is statistically overrepresented in disposable phishing campaigns.")
    if has_shortener:
        diagnostics.append("Uses a URL shortening service to mask the real destination.")
    if subdomain_count >= 3:
        diagnostics.append(f"Excessive nested subdomains ({subdomain_count} levels) obscuring true destination.")
    if keywords_found:
        top_kws = ", ".join(f"'{k}'" for k in keywords_found[:4])
        diagnostics.append(f"Contains security-sensitive or credential harvesting keywords: {top_kws}.")
    if not is_https:
        diagnostics.append("Unencrypted connection (HTTP instead of HTTPS).")
    if domain_entropy > 3.8 and not has_ip:
        diagnostics.append(f"High domain character randomness (entropy {domain_entropy}), indicating potential Domain Generation Algorithm (DGA).")
    if num_dots >= 4:
        diagnostics.append(f"Abnormally high dot count ({num_dots} dots) in URL structure.")
    if url_len > 100:
        diagnostics.append(f"Abnormally long URL ({url_len} chars), typical of token harvesting or obfuscated payloads.")
    if num_redirections > 0:
        diagnostics.append("Contains secondary '//' redirection markers within the path.")
    if check_network and dns_resolves == 0:
        diagnostics.append("Domain has no active DNS A/AAAA records (dormant or non-existent domain).")

    return feature_vector, features_dict, diagnostics

def compute_feature_contributions(features: Dict[str, Any], risk_score: float) -> List[Dict[str, Any]]:
    """
    Explainable AI: Compute local feature contributions (drivers towards phishing or safety).
    """
    contributions = []

    if features.get("is_tranco_top") == 1:
        contributions.append({
            "feature": "Tranco Top 1k Domain",
            "impact": "safeguard",
            "weight": -45.0,
            "description": "Verified high-reputation global domain"
        })
    if features.get("is_brand_typosquat") == 1:
        contributions.append({
            "feature": "Brand Typosquatting",
            "impact": "threat",
            "weight": +40.0,
            "description": f"Near-match to legitimate brand '{features.get('matched_brand')}'"
        })
    if features.get("brand_in_subdomain") == 1:
        contributions.append({
            "feature": "Brand in Subdomain",
            "impact": "threat",
            "weight": +35.0,
            "description": f"Deceptive use of '{features.get('matched_brand')}' before '{features.get('root_domain')}'"
        })
    if features.get("has_ip_address") == 1:
        contributions.append({
            "feature": "Raw IP Hostname",
            "impact": "threat",
            "weight": +35.0,
            "description": "Bypasses standard DNS registration"
        })
    if features.get("has_suspicious_tld") == 1:
        contributions.append({
            "feature": "High-Abuse TLD",
            "impact": "threat",
            "weight": +25.0,
            "description": f"Domain ends in disposable '.{features.get('tld')}'"
        })
    if features.get("has_punycode") == 1:
        contributions.append({
            "feature": "Punycode Homograph",
            "impact": "threat",
            "weight": +30.0,
            "description": "Internationalized character spoofing"
        })
    if features.get("has_suspicious_keyword") == 1:
        kws = ", ".join(features.get("keywords_found", [])[:2])
        contributions.append({
            "feature": "Credential Keywords",
            "impact": "threat",
            "weight": +15.0,
            "description": f"Found tokens: {kws}"
        })
    if features.get("domain_entropy", 0.0) > 3.8:
        contributions.append({
            "feature": "High Character Entropy",
            "impact": "threat",
            "weight": +15.0,
            "description": f"Entropy {features.get('domain_entropy')} indicates automated generation"
        })
    if features.get("is_https") == 1 and features.get("is_tranco_top") == 1:
        contributions.append({
            "feature": "Valid HTTPS + Tranco",
            "impact": "safeguard",
            "weight": -15.0,
            "description": "Standard encrypted transport on verified domain"
        })

    return contributions

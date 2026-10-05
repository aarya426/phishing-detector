import re
from typing import Dict, Any, List, Tuple

URGENCY_KEYWORDS = [
    "urgent", "immediately", "within 24 hours", "suspended", "termination",
    "deactivated", "action required", "unauthorized", "locked", "expire",
    "final notice", "critical alert", "compromised", "restrict", "within 2 hours",
    "deadline", "attention required", "freeze transaction"
]

FINANCIAL_KEYWORDS = [
    "bank", "wire", "transfer", "bitcoin", "crypto", "refund", "invoice",
    "billing", "payment", "credit card", "payroll", "tax refund", "prize",
    "lottery", "claim", "reward", "inheritance", "million", "direct deposit",
    "customs fee", "dispute charge"
]

CREDENTIAL_KEYWORDS = [
    "password", "verify account", "confirm identity", "login credentials",
    "security question", "pin code", "ssn", "social security", "auth token",
    "click here to login", "reset password", "seed phrase", "one-time password",
    "two-factor", "2fa code", "mnemonic"
]

SPOOFING_PATTERNS = [
    r"from:\s*.*<.*>",
    r"official\s+(support|security|alert|notice)",
    r"account\s+administrator",
    r"system\s+notification"
]

URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))""",
    re.VERBOSE
)

def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract all embedded URLs and link mentions from raw email/message text.
    """
    matches = URL_REGEX.findall(text)
    urls = []
    seen = set()
    for m in matches:
        url = m[0].strip()
        # Clean trailing punctuation
        url = re.sub(r"[.,;!?\)\'\"]+$", "", url)
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls

def preprocess_text(text: str) -> str:
    """Normalize text for TF-IDF / NLP analysis."""
    text = text.lower()
    text = re.sub(r"https?://\S+|www\.\S+", " httpurl ", text)
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", " emailaddr ", text)
    text = re.sub(r"\d+", " number ", text)
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def extract_text_indicators(text: str) -> Tuple[Dict[str, Any], List[str]]:
    """
    Extract psychological triggers, urgency cues, and embedded links.
    Returns: (indicators_dict, diagnostics_list)
    """
    text_lower = text.lower()
    
    urgency_matches = [w for w in URGENCY_KEYWORDS if w in text_lower]
    financial_matches = [w for w in FINANCIAL_KEYWORDS if w in text_lower]
    credential_matches = [w for w in CREDENTIAL_KEYWORDS if w in text_lower]
    
    extracted_urls = extract_urls_from_text(text)
    has_links = len(extracted_urls) > 0 or bool(re.search(r"click here|follow the link|verify now", text_lower))
    has_caps = bool(re.search(r"\b[A-Z]{4,}\b", text))
    
    spoofing_cues = []
    for pat in SPOOFING_PATTERNS:
        if re.search(pat, text_lower):
            spoofing_cues.append(pat)

    indicators = {
        "urgency_matches": urgency_matches,
        "financial_matches": financial_matches,
        "credential_matches": credential_matches,
        "urgency_score": len(urgency_matches),
        "financial_score": len(financial_matches),
        "credential_score": len(credential_matches),
        "has_links": has_links,
        "embedded_urls": extracted_urls,
        "excessive_caps": has_caps,
        "has_spoofing_cues": len(spoofing_cues) > 0
    }
    
    diagnostics = []
    if urgency_matches:
        diagnostics.append(f"High urgency psychological pressure detected: {', '.join(urgency_matches[:3])}.")
    if credential_matches:
        diagnostics.append(f"Credential or identity verification solicitation detected: {', '.join(credential_matches[:3])}.")
    if financial_matches:
        diagnostics.append(f"Financial or monetary urgency cues detected: {', '.join(financial_matches[:3])}.")
    if extracted_urls:
        diagnostics.append(f"Detected {len(extracted_urls)} embedded link(s) in message body.")
    if has_links and (urgency_matches or credential_matches):
        diagnostics.append("Direct call-to-action link combined with urgent demand (hallmark of credential phishing).")
        
    return indicators, diagnostics

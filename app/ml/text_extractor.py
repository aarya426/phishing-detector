import re
from typing import Dict, Any, List, Tuple

URGENCY_KEYWORDS = [
    "urgent", "immediately", "within 24 hours", "suspended", "termination",
    "deactivated", "action required", "unauthorized", "locked", "expire",
    "final notice", "critical alert", "compromised", "restrict"
]

FINANCIAL_KEYWORDS = [
    "bank", "wire", "transfer", "bitcoin", "crypto", "refund", "invoice",
    "billing", "payment", "credit card", "payroll", "tax refund", "prize",
    "lottery", "claim", "reward", "inheritance", "million"
]

CREDENTIAL_KEYWORDS = [
    "password", "verify account", "confirm identity", "login credentials",
    "security question", "pin code", "ssn", "social security", "auth token",
    "click here to login", "reset password"
]

def preprocess_text(text: str) -> str:
    """Normalize text for analysis."""
    text = text.lower()
    text = re.sub(r"https?://\S+|www\.\S+", " httpurl ", text)
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", " emailaddr ", text)
    text = re.sub(r"\d+", " number ", text)
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def extract_text_indicators(text: str) -> Tuple[Dict[str, Any], List[str]]:
    """
    Extract heuristic indicators from message/email body.
    Returns (indicator_dict, diagnostic_reasons)
    """
    text_lower = text.lower()
    
    urgency_matches = [w for w in URGENCY_KEYWORDS if w in text_lower]
    financial_matches = [w for w in FINANCIAL_KEYWORDS if w in text_lower]
    credential_matches = [w for w in CREDENTIAL_KEYWORDS if w in text_lower]
    
    has_links = bool(re.search(r"https?://|www\.|click here|follow the link", text_lower))
    has_caps = bool(re.search(r"\b[A-Z]{4,}\b", text))
    
    indicators = {
        "urgency_matches": urgency_matches,
        "financial_matches": financial_matches,
        "credential_matches": credential_matches,
        "urgency_score": len(urgency_matches),
        "financial_score": len(financial_matches),
        "credential_score": len(credential_matches),
        "has_links": has_links,
        "excessive_caps": has_caps
    }
    
    diagnostics = []
    if urgency_matches:
        diagnostics.append(f"High urgency psychological triggers detected: {', '.join(urgency_matches[:3])}.")
    if credential_matches:
        diagnostics.append(f"Credential or sensitive identity solicitation detected: {', '.join(credential_matches[:3])}.")
    if financial_matches:
        diagnostics.append(f"Financial or monetary pressure cues detected: {', '.join(financial_matches[:3])}.")
    if has_links and (urgency_matches or credential_matches):
        diagnostics.append("Direct call-to-action link combined with high-urgency language (classic phishing tactic).")
        
    return indicators, diagnostics

import os
import sys
from pathlib import Path
from typing import Dict, Any, List
import joblib
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.ml.feature_extractor import (
    extract_url_features,
    safe_resolve_redirects,
    compute_feature_contributions,
    FEATURE_NAMES
)
from app.ml.text_extractor import extract_text_indicators, preprocess_text, extract_urls_from_text

MODELS_DIR = BASE_DIR / "models"
URL_MODEL_PATH = MODELS_DIR / "url_phishing_model.joblib"
TEXT_MODEL_PATH = MODELS_DIR / "text_phishing_model.joblib"

class PhishingDetectionEngine:
    def __init__(self):
        self.url_model_pkg = None
        self.text_model_pkg = None
        self._ensure_models_loaded()

    def _ensure_models_loaded(self):
        """Ensure models exist and load them; train if missing."""
        if not URL_MODEL_PATH.exists() or not TEXT_MODEL_PATH.exists():
            print("Models not found. Training models now...")
            from app.ml.train import train_url_model, train_text_model
            self.url_model_pkg = train_url_model()
            self.text_model_pkg = train_text_model()
        else:
            if self.url_model_pkg is None:
                self.url_model_pkg = joblib.load(URL_MODEL_PATH)
            if self.text_model_pkg is None:
                self.text_model_pkg = joblib.load(TEXT_MODEL_PATH)

    def analyze_url(self, url: str, check_network: bool = True, resolve_shorteners: bool = True) -> Dict[str, Any]:
        """
        Analyze a URL for phishing characteristics with safe redirect expansion,
        brand typosquatting checks, Tranco allowlist verification, and calibrated ML scoring.
        """
        self._ensure_models_loaded()
        
        target_url = url.strip()
        redirect_chain = [target_url]
        was_redirected = False
        ssrf_blocked = False

        # Step 1: Safe Redirect Resolution for shorteners / suspicious links
        if resolve_shorteners:
            final_url, chain, ssrf_flag = safe_resolve_redirects(target_url, max_hops=3, timeout=2.0)
            if ssrf_flag:
                ssrf_blocked = True
            elif final_url != target_url:
                target_url = final_url
                redirect_chain = chain
                was_redirected = True

        # If blocked by SSRF
        if ssrf_blocked:
            return {
                "url": url,
                "normalized_url": target_url,
                "risk_score": 100.0,
                "verdict": "BLOCKED / SSRF THREAT",
                "status_level": "high",
                "badge_color": "rose",
                "is_allowlisted": False,
                "summary": "Target resolves to a restricted private or loopback IP range (SSRF exploit attempt). Connection blocked.",
                "diagnostics": ["Host resolves to an internal RFC 1918 / loopback address.", "Potential Server-Side Request Forgery attempt."],
                "recommendations": ["Do not follow or interact with internal redirection schemes."],
                "feature_contributions": [{
                    "feature": "SSRF Violation",
                    "impact": "threat",
                    "weight": 100.0,
                    "description": "Private / non-routable destination address"
                }],
                "redirect_chain": redirect_chain,
                "features": {"hostname": "localhost", "root_domain": "localhost"}
            }

        # Step 2: Feature extraction
        feature_vector, features_dict, diagnostics = extract_url_features(target_url, check_network=check_network)
        
        clf = self.url_model_pkg["model"]
        X = np.array([feature_vector])
        
        # Predict probability from calibrated model
        proba = clf.predict_proba(X)[0]
        phish_proba = float(proba[1])

        # Base calibrated risk score
        calibrated_score = phish_proba * 100.0

        # Step 3: Allowlist vs Guardrail Heuristics
        is_allowlisted = bool(features_dict.get("is_tranco_top") == 1 and 
                              features_dict.get("is_brand_typosquat") == 0 and 
                              features_dict.get("brand_in_subdomain") == 0)

        # Brand typosquatting / deception override
        if features_dict.get("is_brand_typosquat") == 1:
            calibrated_score = max(calibrated_score, 88.0)
        if features_dict.get("brand_in_subdomain") == 1:
            calibrated_score = max(calibrated_score, 85.0)
        if features_dict.get("has_ip_address") == 1:
            calibrated_score = max(calibrated_score, 88.0)
        if features_dict.get("has_punycode") == 1:
            calibrated_score = max(calibrated_score, 85.0)
        if features_dict.get("has_suspicious_tld") == 1 and features_dict.get("has_suspicious_keyword") == 1:
            calibrated_score = max(calibrated_score, 82.0)

        # If verified allowlisted domain with zero anomalies, keep score minimal
        if is_allowlisted and features_dict.get("has_suspicious_keyword") == 0:
            calibrated_score = min(calibrated_score, 5.0)

        risk_score = round(min(100.0, max(0.0, calibrated_score)), 1)

        # Verdict classification
        if is_allowlisted and risk_score < 30.0:
            verdict = "VERIFIED SAFE (ALLOWLISTED)"
            status_level = "low"
            badge_color = "emerald"
            summary = f"Root domain '{features_dict.get('root_domain')}' is verified in the Tranco Top 1k Allowlist and presents no deceptive signals."
        elif risk_score < 35.0:
            verdict = "SAFE"
            status_level = "low"
            badge_color = "emerald"
            summary = "This URL exhibits standard legitimate structure with no significant threat indicators."
        elif risk_score < 70.0:
            verdict = "SUSPICIOUS"
            status_level = "medium"
            badge_color = "amber"
            summary = "This URL exhibits characteristics often found in deceptive or unverified websites. Exercise caution."
        else:
            verdict = "PHISHING / DANGEROUS"
            status_level = "high"
            badge_color = "rose"
            summary = "Warning: High likelihood of phishing or credential harvesting attack. Do not enter personal credentials."

        if was_redirected:
            diagnostics.insert(0, f"Resolved through redirect chain: expanded to '{target_url}'.")

        # Explainable AI: Feature contributions
        contributions = compute_feature_contributions(features_dict, risk_score)

        # Contextual recommendations
        recommendations = []
        if risk_score >= 70:
            recommendations.append("Do not click links or enter passwords or payment details on this site.")
            recommendations.append("If this arrived via email or SMS, report the message as phishing.")
            recommendations.append("Verify the official website by typing the known legitimate address directly in your browser.")
        elif risk_score >= 35:
            recommendations.append("Check the SSL/TLS certificate and verify the exact domain spelling.")
            recommendations.append("Beware of unexpected login prompts or demands for urgent action.")
        else:
            recommendations.append("The URL appears safe based on structural and lexical ML checks.")
            recommendations.append("Always verify the browser address bar for padlock icon and valid SSL certificate.")

        return {
            "url": url,
            "normalized_url": target_url,
            "risk_score": risk_score,
            "verdict": verdict,
            "status_level": status_level,
            "badge_color": badge_color,
            "is_allowlisted": is_allowlisted,
            "summary": summary,
            "diagnostics": diagnostics,
            "feature_contributions": contributions,
            "recommendations": recommendations,
            "redirect_chain": redirect_chain,
            "was_redirected": was_redirected,
            "features": features_dict
        }

    def analyze_text(self, text: str) -> Dict[str, Any]:
        """
        Analyze email or message text for social engineering cues AND scan all embedded URLs.
        """
        self._ensure_models_loaded()
        cleaned_text = preprocess_text(text)
        indicators, diagnostics = extract_text_indicators(text)
        
        pipeline = self.text_model_pkg["pipeline"]
        proba = pipeline.predict_proba([cleaned_text])[0]
        text_phish_proba = float(proba[1])

        text_score = text_phish_proba * 100.0

        if indicators["urgency_score"] > 0 and indicators["credential_score"] > 0:
            text_score = max(text_score, 78.0)
        if indicators["urgency_score"] > 0 and indicators["financial_score"] > 0:
            text_score = max(text_score, 75.0)

        # Step 2: Scan all embedded URLs found in message body
        embedded_urls = indicators.get("embedded_urls", [])
        url_scans = []
        highest_url_risk = 0.0

        for embedded_url in embedded_urls[:5]:  # limit to 5 URLs to prevent abuse
            scan_res = self.analyze_url(embedded_url, check_network=False, resolve_shorteners=True)
            url_scans.append({
                "url": embedded_url,
                "risk_score": scan_res["risk_score"],
                "verdict": scan_res["verdict"],
                "badge_color": scan_res["badge_color"],
                "diagnostics": scan_res["diagnostics"][:2]
            })
            highest_url_risk = max(highest_url_risk, scan_res["risk_score"])

        # Composite risk score: max of text urgency score and highest embedded URL threat
        composite_score = max(text_score, highest_url_risk)
        risk_score = round(min(100.0, max(0.0, composite_score)), 1)

        if risk_score < 35.0:
            verdict = "SAFE / BENIGN"
            status_level = "low"
            badge_color = "emerald"
            summary = "The message appears to be standard communication without coercive phishing cues."
        elif risk_score < 70.0:
            verdict = "SUSPICIOUS"
            status_level = "medium"
            badge_color = "amber"
            summary = "Contains urgency or monetary references commonly used in unsolicited outreach."
        else:
            verdict = "PHISHING DETECTED"
            status_level = "high"
            badge_color = "rose"
            summary = "High probability of social engineering or credential harvesting attempt."

        recommendations = []
        if risk_score >= 70:
            recommendations.append("Never reply with passwords, one-time pins (OTP), or sensitive banking information.")
            recommendations.append("Do not click any embedded links or open unexpected email attachments.")
            recommendations.append("Contact the alleged sender through a verified, separate communication channel.")
        else:
            recommendations.append("Standard message content detected.")

        return {
            "risk_score": risk_score,
            "verdict": verdict,
            "status_level": status_level,
            "badge_color": badge_color,
            "summary": summary,
            "diagnostics": diagnostics,
            "recommendations": recommendations,
            "indicators": indicators,
            "embedded_url_scans": url_scans
        }

    def get_stats(self) -> Dict[str, Any]:
        """Return model metadata, confusion matrix, ROC-AUC, and feature rankings."""
        self._ensure_models_loaded()
        return {
            "version": self.url_model_pkg.get("version", "v1.2.0-calibrated-rf"),
            "url_metrics": self.url_model_pkg.get("metrics", {}),
            "top_features": self.url_model_pkg.get("feature_ranking", [])[:10],
            "text_metrics": {
                "accuracy": self.text_model_pkg.get("accuracy", 0.0),
                "total_samples": self.text_model_pkg.get("total_samples", 0),
                "version": self.text_model_pkg.get("version", "v1.2.0")
            }
        }

engine = PhishingDetectionEngine()

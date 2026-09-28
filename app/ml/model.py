import os
import sys
from pathlib import Path
from typing import Dict, Any, List
import joblib
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.ml.feature_extractor import extract_url_features, FEATURE_NAMES
from app.ml.text_extractor import extract_text_indicators, preprocess_text

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

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for phishing characteristics using feature extraction and ML inference.
        """
        self._ensure_models_loaded()
        feature_vector, features_dict, diagnostics = extract_url_features(url)
        
        clf = self.url_model_pkg["model"]
        X = np.array([feature_vector])
        
        # Predict probability: [prob_legit, prob_phish]
        proba = clf.predict_proba(X)[0]
        phish_proba = float(proba[1])

        # Heuristic calibration: direct IP or high abuse TLD with security keywords
        calibrated_score = phish_proba * 100
        
        if features_dict.get("has_ip_address") == 1:
            calibrated_score = max(calibrated_score, 88.0)
        if features_dict.get("has_punycode") == 1:
            calibrated_score = max(calibrated_score, 85.0)
        if features_dict.get("has_suspicious_tld") == 1 and features_dict.get("has_suspicious_keyword") == 1:
            calibrated_score = max(calibrated_score, 82.0)
        if features_dict.get("num_at_symbols", 0) > 0:
            calibrated_score = max(calibrated_score, 80.0)

        # Cap between 0 and 100
        risk_score = round(min(100.0, max(0.0, calibrated_score)), 1)

        # Determine verdict and status
        if risk_score < 35.0:
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

        # Recommendations
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
            "normalized_url": features_dict.get("hostname", ""),
            "risk_score": risk_score,
            "verdict": verdict,
            "status_level": status_level,
            "badge_color": badge_color,
            "summary": summary,
            "diagnostics": diagnostics,
            "recommendations": recommendations,
            "features": features_dict
        }

    def analyze_text(self, text: str) -> Dict[str, Any]:
        """
        Analyze email or message text for social engineering / phishing cues.
        """
        self._ensure_models_loaded()
        cleaned_text = preprocess_text(text)
        indicators, diagnostics = extract_text_indicators(text)
        
        pipeline = self.text_model_pkg["pipeline"]
        proba = pipeline.predict_proba([cleaned_text])[0]
        phish_proba = float(proba[1])

        # Heuristic calibration based on psychological triggers
        score = phish_proba * 100
        if indicators["urgency_score"] > 0 and indicators["credential_score"] > 0:
            score = max(score, 78.0)
        if indicators["urgency_score"] > 0 and indicators["financial_score"] > 0:
            score = max(score, 75.0)

        risk_score = round(min(100.0, max(0.0, score)), 1)

        if risk_score < 35.0:
            verdict = "SAFE / BENIGN"
            status_level = "low"
            badge_color = "emerald"
            summary = "The message appears to be normal communication without coercive phishing patterns."
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
            "indicators": indicators
        }

    def get_stats(self) -> Dict[str, Any]:
        """Return model metadata and top feature importance."""
        self._ensure_models_loaded()
        return {
            "url_metrics": self.url_model_pkg.get("metrics", {}),
            "top_features": self.url_model_pkg.get("feature_ranking", [])[:10],
            "text_metrics": {
                "accuracy": self.text_model_pkg.get("accuracy", 0.0),
                "total_samples": self.text_model_pkg.get("total_samples", 0)
            }
        }

# Global singleton instance
engine = PhishingDetectionEngine()

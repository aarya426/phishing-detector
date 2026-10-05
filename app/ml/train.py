import os
import sys
from pathlib import Path
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)

# Ensure root directory is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.ml.feature_extractor import extract_url_features, extract_root_domain, FEATURE_NAMES
from app.ml.text_extractor import preprocess_text

MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_VERSION = "v1.2.0-calibrated-rf"

# ---------------------------------------------------------------------------
# 1. Dataset Generation: Legitimate vs Phishing URLs
# Balanced and unbiased: Contains both HTTP and HTTPS across both classes.
# ---------------------------------------------------------------------------
LEGITIMATE_BASE_DOMAINS = [
    # Top tech & services (HTTPS)
    "https://www.google.com",
    "https://www.youtube.com",
    "https://github.com",
    "https://en.wikipedia.org",
    "https://www.amazon.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://stackoverflow.com",
    "https://www.reddit.com",
    "https://www.linkedin.com",
    "https://developer.mozilla.org",
    "https://docs.python.org",
    "https://netflix.com",
    "https://paypal.com",
    "https://chase.com",
    "https://bankofamerica.com",
    "https://wellsfargo.com",
    "https://twitter.com",
    "https://store.steampowered.com",
    "https://www.kaggle.com",
    "https://pypi.org",
    "https://fastapi.tiangolo.com",
    "https://tailwindcss.com",
    "https://aws.amazon.com",
    "https://cloud.google.com",
    "https://www.ebay.com",
    "https://www.spotify.com",
    "https://zoom.us",
    "https://dropbox.com",
    "https://slack.com",
    "https://www.harvard.edu",
    "https://mit.edu",
    "https://stanford.edu",
    "https://nih.gov",
    "https://who.int",
    "https://weather.com",
    "https://bloomberg.com",
    "https://wsj.com",
    "https://forbes.com",
    "https://www.bbc.com",
    
    # Legitimate HTTP sites (demonstrating HTTP != automatically phishing)
    "http://info.cern.ch",
    "http://legacy.python.org",
    "http://www.gnu.org",
    "http://rfc-editor.org",
    "http://example.com",
    "http://www.w3.org",
    "http://berkeley.edu",
    "http://archive.ubuntu.com",
    "http://mirrors.kernel.org",
    "http://ftp.debian.org"
]

LEGITIMATE_URLS = []
for base in LEGITIMATE_BASE_DOMAINS:
    LEGITIMATE_URLS.append(base)
    LEGITIMATE_URLS.append(f"{base}/dashboard?session=valid&lang=en")
    LEGITIMATE_URLS.append(f"{base}/docs/v2/api-reference")
    LEGITIMATE_URLS.append(f"{base}/search?q=machine+learning+tutorial")
    LEGITIMATE_URLS.append(f"{base}/article/2026/04/cybersecurity-overview")

PHISHING_BASE_URLS = [
    # Modern Phishing with HTTPS (Cloudflare / Let's Encrypt certificates)
    "https://paypal-account-verification-security.xyz/login.php",
    "https://apple-id-suspended-update.top/security/confirm.php",
    "https://netflix-billing-issue-confirm.buzz/account/login",
    "https://wellsfargo.com.security-alert-user-auth.ga/login.asp",
    "https://secure-login-chasebank.cf/signin?redirect=billing",
    "https://account-update-amazon-support.ml/verify?token=89432f",
    "https://microsoft-support-ticket-verification.icu/live/chat.php",
    "https://google-drive-shared-document-verify.tk/auth.php",
    "https://login.secure-bankofamerica.com.account-update.buzz/auth",
    "https://secure.chase.com.credential-harvest.ru/login.php",
    "https://paypa1-security-center.com/webscr/login",
    "https://g00gle-accounts-verification.xyz/recovery",
    "https://rnicrosoft-office365-login.top/auth",
    "https://amaz0n-prime-order-cancel.buzz/refund",
    "https://b1nance-wallet-security-restore.party/seed",
    "https://coinba5e-login-authentication.icu/2fa",
    "https://dhl-express-tracking-package-fee.fit/pay-customs",
    "https://usps-delivery-failed-reschedule.xyz/redelivery",
    "https://citibank-fraud-prevention-alert.kim/security-update",
    "https://americanexpress-card-unlock.racing/confirm-pin",

    # Phishing with HTTP
    "http://192.168.1.100/chase-online/auth/login.html",
    "http://10.0.0.1/bankofamerica-verify/sign-in.php",
    "http://172.16.254.1/auth/login/secure-portal",
    "http://198.51.100.42/secure/login?account=locked",
    "http://paypal.com@phishing-server-99.xyz/webscr?cmd=_login",
    "http://xn--googl-rsa.com/signin",
    "http://signin-att-yahoomail-account.cam/authenticate",
    "http://verify-crypto-binance-wallet.party/restore",
    "http://irs-tax-refund-immediate-claim.buzz/direct-deposit.php",
    "http://tinyurl.com/bank-urgent-fix",
    "http://bit.ly/claim-your-free-prize-now",
    "http://ebay-member-resolution-center.loan/dispute/resolve",
    "http://facebook-security-check-2026.date/verify-identity",
    "http://twitter-verification-badge-claim.work/auth",
    "http://zoom-video-conference-invite.download/join",
    "http://office365-password-expiration-warning.click/reset",
    "http://chase.com-sign-in-portal-ssl.xyz/portal/login",
    "http://appleid.apple.com-recovery-key.xyz/my-account",
    "http://santander-ebanking-portal.ml/security/login",
    "http://barclays-security-shield.tk/online-banking/auth"
]

PHISHING_URLS = []
for base in PHISHING_BASE_URLS:
    PHISHING_URLS.append(base)
    PHISHING_URLS.append(f"{base}?session_id=987123&client_id=sec_441")
    PHISHING_URLS.append(f"{base}/confirm-identity/step2.php?user_token=ab927f")
    PHISHING_URLS.append(f"{base}/auth/session/token-99881?action=verify")

# ---------------------------------------------------------------------------
# 2. Message / Email Dataset for NLP
# ---------------------------------------------------------------------------
LEGITIMATE_TEXTS = [
    "Hi team, here are the meeting minutes from today's sprint planning. Please review the backlog items by Friday.",
    "Your package from Amazon has been shipped and will arrive tomorrow by 8 PM. Track your package in your orders.",
    "Attached is the project status report for Q2. Let me know if you have any questions before the presentation.",
    "Hey! Are you still up for lunch tomorrow around 12:30? Let me know what restaurant you'd like to go to.",
    "Your monthly subscription statement is now available in your account settings. Total billed: $14.99.",
    "Thank you for booking with United Airlines. Your flight confirmation code is GH72K9. Have a great trip!",
    "GitHub: A new comment was posted on pull request #42 by octocat. Click here to view the diff.",
    "Reminder: Team happy hour is scheduled for this Thursday at 5 PM on the patio. Hope to see you there!",
    "Your weekly screen time report is ready. You averaged 3 hours and 15 minutes per day this week.",
    "The quarterly all-hands meeting will begin at 10 AM EST. The agenda includes company OKR updates.",
    "Your Google Calendar event 'Product Demo' starts in 15 minutes. Join via Google Meet.",
    "Thank you for your inquiry regarding our API documentation. Our engineering team has replied.",
    "Hi Sarah, can you please review the attached PDF design specs when you have a free moment?",
    "Your order #82910 from Nike has been delivered to your front porch. Thank you for shopping with us.",
    "Slack notification: Alex mentioned you in #general: 'Great work on launching the new feature!'"
]

PHISHING_TEXTS = [
    "URGENT: Your bank account has been suspended due to suspicious activity. Click here to verify your identity immediately: http://chase-security-fix.xyz",
    "FINAL NOTICE: Your Netflix subscription has expired. Update your credit card details within 24 hours to prevent cancellation.",
    "SECURITY ALERT: We detected an unauthorized login to your PayPal account from Russia. If this wasn't you, reset your password now: http://paypal-auth.top",
    "CONGRATULATIONS! You have been selected as the winner of the $1,000,000 international lottery. Reply with your SSN and bank wire info to claim your reward.",
    "CRITICAL WARNING: Your Office365 password will expire today. Click this link immediately to keep your current password.",
    "Action Required: Wire transfer request of $48,500 pending your authorization. Confirm transfer or dispute charge within 2 hours.",
    "Your Apple ID has been locked for security reasons. Complete identity validation to restore access to iCloud and purchases.",
    "IRS Direct Deposit Refund: You are eligible for a $1,420 tax rebate. Click here to submit your direct deposit banking details.",
    "USPS Delivery Failed: Package #93821 could not be delivered due to an incorrect address. Pay $1.99 redelivery fee now.",
    "Attention: Your cryptocurrency wallet has been compromised. Verify your 12-word seed phrase immediately to secure your assets.",
    "Dear Customer, your Wells Fargo account has been restricted. Download the attached security update to unlock your funds.",
    "URGENT: Immediate payment needed for invoice #INV-9281 to prevent legal proceedings and account termination.",
    "Congratulations! You won a $500 Amazon Gift Card. Claim your voucher before it expires at midnight tonight.",
    "Bank Alert: New payee added to your checking account. If unauthorized, click here to dispute and freeze transaction.",
    "Your Microsoft account is deactivated. Verify your login credentials to reactivate your email services."
]

def train_url_model():
    print("=" * 60)
    print("Extracting features for URL phishing model...")
    X_raw, y_raw, domains = [], [], []

    for u in LEGITIMATE_URLS:
        features, fdict, _ = extract_url_features(u, check_network=False)
        X_raw.append(features)
        y_raw.append(0)
        domains.append(fdict.get("root_domain", u))

    for u in PHISHING_URLS:
        features, fdict, _ = extract_url_features(u, check_network=False)
        X_raw.append(features)
        y_raw.append(1)
        domains.append(fdict.get("root_domain", u))

    X = np.array(X_raw)
    y = np.array(y_raw)
    groups = np.array(domains)

    print(f"Total dataset: {len(y)} samples ({np.sum(y == 0)} legitimate, {np.sum(y == 1)} phishing)")
    print(f"Unique root domains: {len(np.unique(groups))}")

    # Domain-Grouped Split to eliminate near-duplicate data leakage across train/test
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups))

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    groups_train, groups_test = groups[train_idx], groups[test_idx]

    # Verify zero domain overlap between train and test
    overlap = set(groups_train).intersection(set(groups_test))
    assert len(overlap) == 0, f"Data leakage detected! Overlapping domains: {overlap}"
    print(f"Domain-Grouped Split verified: Train={len(y_train)} samples ({len(set(groups_train))} domains), Test={len(y_test)} samples ({len(set(groups_test))} domains)")

    # Base Random Forest Classifier
    base_clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=3,
        random_state=42,
        class_weight="balanced"
    )
    base_clf.fit(X_train, y_train)

    # Probability Calibration using CalibratedClassifierCV (3-fold CV)
    calibrated_clf = CalibratedClassifierCV(
        estimator=base_clf,
        method="sigmoid",
        cv=3
    )
    calibrated_clf.fit(X_train, y_train)

    # Evaluate on held-out unseen domains
    y_pred = calibrated_clf.predict(X_test)
    y_proba = calibrated_clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_proba)
    
    # 2x2 Confusion Matrix: [[TN, FP], [FN, TP]]
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    print("\n" + "-" * 50)
    print("URL Model Evaluation on Unseen Domains (Zero Leakage):")
    print(f"  Accuracy   : {acc:.4f}")
    print(f"  Precision  : {prec:.4f}")
    print(f"  Recall     : {rec:.4f}")
    print(f"  F1 Score   : {f1:.4f}")
    print(f"  ROC-AUC    : {roc_auc:.4f}")
    print(f"  Confusion  : TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print("-" * 50)

    # Real feature importances from base ensemble
    importances = base_clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    feature_ranking = [
        {"feature": FEATURE_NAMES[i], "importance": round(float(importances[i]), 4)}
        for i in sorted_idx
    ]

    model_package = {
        "model": calibrated_clf,
        "base_model": base_clf,
        "version": MODEL_VERSION,
        "feature_names": FEATURE_NAMES,
        "feature_ranking": feature_ranking,
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4),
            "total_samples": len(y),
            "train_samples": len(y_train),
            "test_samples": len(y_test),
            "train_domains": len(set(groups_train)),
            "test_domains": len(set(groups_test)),
            "confusion_matrix": {
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp
            }
        }
    }

    url_model_path = MODELS_DIR / "url_phishing_model.joblib"
    joblib.dump(model_package, url_model_path)
    print(f"Saved calibrated URL model package to {url_model_path}")
    return model_package

def train_text_model():
    print("\nTraining Text / Email phishing NLP model with Logistic Regression...")
    X = [preprocess_text(t) for t in (LEGITIMATE_TEXTS + PHISHING_TEXTS)]
    y = np.array([0] * len(LEGITIMATE_TEXTS) + [1] * len(PHISHING_TEXTS))

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=1200)),
        ("clf", LogisticRegression(C=1.0, max_iter=200, random_state=42))
    ])

    pipeline.fit(X, y)
    y_pred = pipeline.predict(X)
    acc = accuracy_score(y, y_pred)
    print(f"Text Model Accuracy: {acc:.4f}")

    text_package = {
        "pipeline": pipeline,
        "version": MODEL_VERSION,
        "accuracy": round(float(acc), 4),
        "total_samples": len(y)
    }

    text_model_path = MODELS_DIR / "text_phishing_model.joblib"
    joblib.dump(text_package, text_model_path)
    print(f"Saved Text model package to {text_model_path}")
    return text_package

if __name__ == "__main__":
    train_url_model()
    train_text_model()

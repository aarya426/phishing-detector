import os
import sys
from pathlib import Path
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Ensure root directory is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.ml.feature_extractor import extract_url_features, FEATURE_NAMES
from app.ml.text_extractor import preprocess_text

MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# -------------------------------------------------------------
# 1. Dataset Generation: Legitimate vs Phishing URLs
# -------------------------------------------------------------
LEGITIMATE_URLS = [
    "https://www.google.com",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://github.com/torvalds/linux",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://www.amazon.com/gp/bestsellers/books",
    "https://www.microsoft.com/en-us/windows",
    "https://www.apple.com/iphone-15-pro/",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.reddit.com/r/MachineLearning/",
    "https://www.nytimes.com/section/technology",
    "https://www.linkedin.com/in/williamhgates",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.bbc.com/news/world",
    "https://www.cnn.com/world",
    "https://netflix.com/browse",
    "https://chase.com",
    "https://paypal.com",
    "https://bankofamerica.com",
    "https://wellsfargo.com",
    "https://twitter.com/NASA",
    "https://www.imdb.com/title/tt1375666/",
    "https://medium.com/towards-data-science",
    "https://arxiv.org/abs/1706.03762",
    "https://news.ycombinator.com/item?id=123456",
    "https://store.steampowered.com/app/1091500/Cyberpunk_2077/",
    "https://www.kaggle.com/datasets",
    "https://pypi.org/project/scikit-learn/",
    "https://fastapi.tiangolo.com/tutorial/first-steps/",
    "https://tailwindcss.com/docs/installation",
    "https://aws.amazon.com/console/",
    "https://cloud.google.com/vertex-ai",
    "https://azure.microsoft.com/en-us/solutions/",
    "https://www.ebay.com/itm/1234567890",
    "https://www.spotify.com/us/premium/",
    "https://www.adobe.com/products/photoshop.html",
    "https://www.salesforce.com/products/crm/",
    "https://zoom.us/join",
    "https://dropbox.com/home",
    "https://slack.com/workspace",
    "https://www.harvard.edu/programs/computer-science",
    "https://mit.edu/research",
    "https://stanford.edu/academics",
    "https://nih.gov/health-information",
    "https://who.int/emergencies/diseases",
    "https://weather.com/weather/today/l/USNY0996:1:US",
    "https://espn.com/nba/story/_/id/123456",
    "https://bloomberg.com/markets",
    "https://wsj.com/articles/world-economy",
    "https://forbes.com/innovation"
]

# Generate more realistic legitimate variants with diverse paths & queries
for base in list(LEGITIMATE_URLS):
    LEGITIMATE_URLS.append(f"{base}/dashboard?session=valid&lang=en")
    LEGITIMATE_URLS.append(f"{base}/docs/v2/api-reference")
    LEGITIMATE_URLS.append(f"{base}/blog/2026/05/security-updates")
    LEGITIMATE_URLS.append(f"{base}/search?q=machine+learning+tutorial")

PHISHING_URLS = [
    "http://paypal-account-verification-security.xyz/login.php",
    "http://192.168.1.100/chase-online/auth/login.html",
    "http://10.0.0.1/bankofamerica-verify/sign-in.php",
    "http://apple-id-suspended-update.top/security/confirm.php?id=928374",
    "http://netflix-billing-issue-confirm.buzz/account/login",
    "http://wellsfargo.com.security-alert-user-auth.ga/login.asp",
    "http://secure-login-chasebank.cf/signin?redirect=billing",
    "http://account-update-amazon-support.ml/verify?token=89432f",
    "http://microsoft-support-ticket-verification.icu/live/chat.php",
    "http://google-drive-shared-document-verify.tk/auth.php",
    "http://login.secure-bankofamerica.com.account-update.buzz/auth",
    "http://paypal.com@phishing-server-99.xyz/webscr?cmd=_login",
    "http://secure.chase.com.credential-harvest.ru/login.php",
    "http://xn--googl-rsa.com/signin",
    "http://signin-att-yahoomail-account.cam/authenticate",
    "http://verify-crypto-binance-wallet.party/restore?mnemonic=true",
    "http://metamask-extension-recovery-vault.top/seed-phrase.html",
    "http://dhl-express-tracking-package-fee.fit/pay-customs",
    "http://usps-delivery-failed-reschedule.xyz/tracking/redelivery",
    "http://irs-tax-refund-immediate-claim.buzz/direct-deposit.php",
    "http://172.16.254.1/auth/login/secure-portal",
    "http://tinyurl.com/bank-urgent-fix",
    "http://bit.ly/claim-your-free-prize-now",
    "http://ebay-member-resolution-center.loan/dispute/resolve",
    "http://facebook-security-check-2026.date/verify-identity",
    "http://instagram-blue-badge-apply.men/copyright-claim.php",
    "http://twitter-verification-badge-claim.work/auth",
    "http://whatsapp-web-activation-code.stream/qr-scan",
    "http://zoom-video-conference-invite.download/join?meeting=78392",
    "http://docu-sign-confidential-agreement.review/view-envelope.html",
    "http://office365-password-expiration-warning.click/reset",
    "http://citibank-fraud-prevention-alert.kim/security-update",
    "http://americanexpress-card-unlock.racing/confirm-pin",
    "http://coinbase-pro-security-lockout.country/verify",
    "http://kraken-exchange-two-factor-reset.rest/2fa-override",
    "http://chase.com-sign-in-portal-ssl.xyz/portal/login",
    "http://appleid.apple.com-recovery-key.xyz/my-account",
    "http://paypal-resolution-center.icu/dispute/case-83921",
    "http://banking-service-secure-login-398472.top/auth/index.php",
    "http://198.51.100.42/secure/login?account=locked",
    "http://wellsfargo-identity-confirmation.xyz/auth.aspx",
    "http://bofa-customer-card-verification.top/card/update",
    "http://verizon-bill-rebate-claim.buzz/my-verizon",
    "http://t-mobile-account-security-center.xyz/login",
    "http://vodafone-invoice-overdue-notice.cf/payment.php",
    "http://santander-ebanking-portal.ml/security/login",
    "http://barclays-security-shield.tk/online-banking/auth",
    "http://hsbc-global-wire-approval.icu/corporate/transfer",
    "http://target-giftcard-giveaway-winner.party/claim",
    "http://walmart-survey-1000-reward.top/survey.php"
]

# Generate realistic phishing variants with query parameters & obfuscation
for base in list(PHISHING_URLS):
    PHISHING_URLS.append(f"{base}?session_id=987123&client_id=sec_441&redirect_uri=done")
    PHISHING_URLS.append(f"{base}/confirm-identity/step2.php?user_token=ab927f")
    PHISHING_URLS.append(f"{base}/auth/session/token-99881?action=verify")

# -------------------------------------------------------------
# 2. Dataset Generation: Legitimate vs Phishing Emails/Messages
# -------------------------------------------------------------
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
    print("Extracting features for URL phishing model...")
    X_raw = []
    y = []

    # Legitimate samples (label 0)
    for u in LEGITIMATE_URLS:
        features, _, _ = extract_url_features(u)
        X_raw.append(features)
        y.append(0)

    # Phishing samples (label 1)
    for u in PHISHING_URLS:
        features, _, _ = extract_url_features(u)
        X_raw.append(features)
        y.append(1)

    X = np.array(X_raw)
    y = np.array(y)

    print(f"Total URL dataset size: {len(y)} ({np.sum(y == 0)} legitimate, {np.sum(y == 1)} phishing)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=3,
        random_state=42,
        class_weight="balanced"
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print(f"URL Model Evaluation: Accuracy={acc:.4f}, Precision={prec:.4f}, Recall={rec:.4f}, F1={f1:.4f}")

    # Calculate feature importances
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    feature_ranking = [
        {"feature": FEATURE_NAMES[i], "importance": round(float(importances[i]), 4)}
        for i in sorted_idx
    ]

    model_package = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "feature_ranking": feature_ranking,
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "total_samples": len(y),
            "train_samples": len(y_train),
            "test_samples": len(y_test)
        }
    }

    url_model_path = MODELS_DIR / "url_phishing_model.joblib"
    joblib.dump(model_package, url_model_path)
    print(f"Saved URL model package to {url_model_path}")
    return model_package

def train_text_model():
    print("Training Text / Email phishing NLP model...")
    X = [preprocess_text(t) for t in (LEGITIMATE_TEXTS + PHISHING_TEXTS)]
    y = np.array([0] * len(LEGITIMATE_TEXTS) + [1] * len(PHISHING_TEXTS))

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=1000)),
        ("clf", MultinomialNB(alpha=0.5))
    ])

    pipeline.fit(X, y)
    y_pred = pipeline.predict(X)
    acc = accuracy_score(y, y_pred)
    print(f"Text Model Training Accuracy: {acc:.4f}")

    text_package = {
        "pipeline": pipeline,
        "accuracy": round(float(acc), 4),
        "total_samples": len(y)
    }

    text_model_path = MODELS_DIR / "text_phishing_model.joblib"
    joblib.dump(text_package, text_model_path)
    print(f"Saved Text model package to {text_model_path}")
    return text_package

if __name__ == "__main__":
    print("=== Training Machine Learning Models ===")
    train_url_model()
    train_text_model()
    print("=== Training Completed Successfully ===")

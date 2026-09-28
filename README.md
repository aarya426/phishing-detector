# 🛡️ PhishGuard AI — Phishing Detection Website using Machine Learning

PhishGuard AI is an intelligent cybersecurity web application designed to detect phishing URLs and social engineering text messages in real time using machine learning classifiers and explainable AI diagnostics.

---

## 🌟 Key Features

- **🌐 Dual Detection Engine**:
  - **URL Random Forest Classifier**: Extracts 23 structural and lexical features per URL (Shannon character entropy, nested subdomains, direct IP hostnames, Punycode homoglyphs, high-abuse TLDs, and credential harvesting keywords).
  - **Message & Email NLP Scanner**: Analyzes text messages and emails using TF-IDF n-grams and Naive Bayes to spot coercive urgency cues, fake account suspensions, and financial scam prompts.
- **📊 Explainable AI & Threat Diagnostics**:
  - Calibrated Risk Score Gauge (0% – 100%) categorized into `SAFE`, `SUSPICIOUS`, or `PHISHING / DANGEROUS`.
  - Detailed diagnostic reports outlining *why* a URL or message was flagged.
  - Context-aware recommendations for end users to avoid falling victim to attacks.
- **⚡ Modern Cybersecurity Dashboard**:
  - Dark-mode interface built with Tailwind CSS, Lucide Icons, and Chart.js.
  - Interactive feature inspection table breaking down all 23 extracted signals.
  - One-click testing presets (Google, GitHub, Fake PayPal, IP-based Bank Scam, Subdomain Spoof, Shortened Link).
  - Live model insights tab displaying test accuracy and feature importance rankings.
  - Session history tracker with instant re-scan capabilities.

---

## 🏗️ Architecture

```
                                  +-------------------------------------+
                                  |         Modern Web Dashboard        |
                                  |     (Tailwind CSS + Chart.js)       |
                                  +------------------+------------------+
                                                     | HTTP REST API
                                                     v
                                  +-------------------------------------+
                                  |           FastAPI Backend           |
                                  |    (Endpoints: /api/scan-url, ...)  |
                                  +---------+--------------------+------+
                                            |                    |
                     +----------------------+                    +----------------------+
                     |                                                                  |
                     v                                                                  v
      +-------------------------------+                                  +-------------------------------+
      |       URL ML Pipeline         |                                  |    Text / Email NLP Engine    |
      +-------------------------------+                                  +-------------------------------+
      | 1. URL Normalization          |                                  | 1. Text Preprocessing         |
      | 2. Feature Extraction (23x)   |                                  | 2. TF-IDF N-gram Vectorizer   |
      | 3. Random Forest (100 Trees)  |                                  | 3. Multinomial Naive Bayes    |
      | 4. Heuristic Safeguard Rules  |                                  | 4. Psychological Threat Cues  |
      | 5. Explainable Risk Score     |                                  +-------------------------------+
      +-------------------------------+
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
Ensure you have **Python 3.10+** and **Git** installed on your system.

### 2. Clone the Repository
```bash
git clone https://github.com/<your-username>/phishing-detector.git
cd phishing-detector
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python run.py
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser to access the live dashboard.

---

## 🧪 Running Automated Tests

To run the complete test suite:
```bash
pytest tests/ -v
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web dashboard user interface |
| `POST` | `/api/scan-url` | Analyzes a URL and returns risk score, verdict, diagnostics & features |
| `POST` | `/api/scan-text` | Analyzes message text for phishing/urgency triggers |
| `GET` | `/api/model-stats` | Returns model accuracy, metrics, and feature importance rankings |
| `GET` | `/api/sample-urls` | Returns curated legitimate and phishing sample URLs for testing |
| `GET` | `/api/health` | API health check endpoint |

---

## 🛠️ Tech Stack

- **Backend**: FastAPI, Uvicorn, Pydantic
- **Machine Learning**: Scikit-Learn (Random Forest, MultinomialNB), NumPy, Joblib
- **Frontend**: HTML5, Tailwind CSS, Lucide Icons, Chart.js
- **Testing**: Pytest, HTTPX

---


import os
import sys
import uvicorn
from pathlib import Path

# Ensure root is on python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def main():
    print("=" * 65)
    print("      [+] PHISHGUARD AI - MACHINE LEARNING DETECTION SERVER      ")
    print("=" * 65)
    print(f"Base Directory : {BASE_DIR}")
    print("Initializing Machine Learning Models...")
    
    # Pre-train or load models
    from app.ml.model import engine
    stats = engine.get_stats()
    url_acc = stats.get("url_metrics", {}).get("accuracy", 0.0)
    print(f"URL Random Forest Model loaded (Validation Accuracy: {url_acc * 100:.1f}%)")
    print(f"NLP Message Classifier loaded (Accuracy: {stats.get('text_metrics', {}).get('accuracy', 0.0) * 100:.1f}%)")
    print("-" * 65)
    print("[*] Starting Web Server at: http://127.0.0.1:8000")
    print("[*] API Documentation at:   http://127.0.0.1:8000/docs")
    print("Press CTRL+C to stop the server.")
    print("=" * 65)

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False, log_level="info")

if __name__ == "__main__":
    main()

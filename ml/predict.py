import os
import sys
import numpy as np
import joblib

# Import feature extractor module
from feature_extractor import extract_features

def predict_url(url: str):
    """
    Loads trained Random Forest model, extracts URL features, calculates phishing probability,
    and displays the prediction result.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "model", "phishing_model.pkl")

    if not os.path.exists(model_path):
        print(f"\n[ERROR] Model file not found at: {model_path}")
        print("Please train the model first by running:")
        print("  python train_model.py")
        sys.exit(1)

    # Load model payload
    try:
        payload = joblib.load(model_path)
        if isinstance(payload, dict) and "model" in payload:
            clf = payload["model"]
        else:
            clf = payload
    except Exception as e:
        print(f"[ERROR] Failed to load model file: {e}")
        sys.exit(1)

    # Extract features for target URL
    features = extract_features(url)
    X = np.array([features])

    # Predict class (0 = Legitimate, 1 = Phishing)
    prediction = clf.predict(X)[0]

    # Predict class probability
    if hasattr(clf, "predict_proba"):
        probabilities = clf.predict_proba(X)[0]
        # Probability of class 1 (Phishing)
        phishing_prob = probabilities[1] if len(probabilities) > 1 else (1.0 if prediction == 1 else 0.0)
    else:
        phishing_prob = 1.0 if prediction == 1 else 0.0

    # Calculate ML Risk Score (0 - 100)
    risk_score = phishing_prob * 100.0
    label_text = "PHISHING" if prediction == 1 else "LEGITIMATE"

    # Display results
    print("=" * 60)
    print("Craxis - ML Predictor (Level 5)")
    print("=" * 60)
    print(f"URL:                  {url}")
    print(f"Prediction:           {label_text}")
    print(f"Phishing Probability: {phishing_prob * 100:.2f}%")
    print(f"ML RISK SCORE:        {risk_score:.2f} / 100")
    print("=" * 60)

def main():
    if len(sys.argv) > 1:
        target_url = sys.argv[1].strip()
    else:
        target_url = input("Enter URL to analyze: ").strip()

    if not target_url:
        print("[ERROR] No URL provided.")
        sys.exit(1)

    predict_url(target_url)

if __name__ == "__main__":
    main()

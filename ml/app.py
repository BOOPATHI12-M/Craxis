"""Craxis local REST API.

Endpoints
---------
GET  /                       service info
GET  /health                 liveness check used by the extension
GET  /model-info             model metadata and top features
GET  /api/model-evaluation   held-out evaluation results
POST /predict                {"url": "...", "intel": false} -> phishing probability
GET  /test-pages/...         local safe test pages

Environment
-----------
AIPHISH_HOST          bind address (default 127.0.0.1)
AIPHISH_PORT          port (default 5000)
AIPHISH_ENABLE_INTEL  set to 1 to allow optional domain age / certificate lookups
"""
import json
import os
import sys
from urllib.parse import urlparse

import joblib
import numpy as np
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

import domain_intel
from feature_extractor import FEATURE_NAMES, extract_features

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
TEST_PAGES_DIR = os.path.join(PROJECT_ROOT, "test-pages")
MODEL_PATH = os.environ.get("AIPHISH_MODEL_PATH", os.path.join(SCRIPT_DIR, "model", "phishing_model.pkl"))

app = Flask(__name__)
# The extension service worker is not subject to CORS. Browser pages may only
# call the API from the API's own origin, so arbitrary websites cannot probe it.
CORS(app, origins=[r"chrome-extension://.*", r"http://127\.0\.0\.1(:\d+)?", r"http://localhost(:\d+)?"])


def load_model(path: str):
    """Load the model package and verify that its feature list matches the extractor."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model file not found at {path}. Run: python ml/train_model.py")
    payload = joblib.load(path)
    if isinstance(payload, dict):
        model = payload.get("model")
        info = {
            "version": payload.get("version", "unknown"),
            "algorithm": payload.get("algorithm", "Random Forest"),
            "metrics": payload.get("metrics", {}),
            "top_features": payload.get("top_features", []),
        }
        stored = payload.get("feature_names")
        if stored is not None and list(stored) != list(FEATURE_NAMES):
            raise ValueError(
                "Model feature list does not match feature_extractor.py. Retrain with: python ml/train_model.py"
            )
    else:
        model = payload
        info = {"version": "legacy", "algorithm": "Random Forest", "metrics": {}, "top_features": []}
    expected = getattr(model, "n_features_in_", len(FEATURE_NAMES))
    if expected != len(FEATURE_NAMES):
        raise ValueError(
            f"Model expects {expected} features but the extractor produces {len(FEATURE_NAMES)}. "
            "Retrain with: python ml/train_model.py"
        )
    return model, info


try:
    model_obj, model_info_data = load_model(MODEL_PATH)
    model_version = model_info_data["version"]
    model_algorithm = model_info_data["algorithm"]
    print(f"[OK] Loaded {model_algorithm} (version {model_version}) from {MODEL_PATH}")
except Exception as exc:  # fail fast with a clear message
    print("=" * 60)
    print(f"[ERROR] {exc}")
    print("=" * 60)
    if __name__ == "__main__":
        sys.exit(1)
    raise


def top_feature_pairs(limit: int = 6) -> list:
    importances = getattr(model_obj, "feature_importances_", None)
    if importances is not None:
        pairs = [
            {"name": str(n), "importance": round(float(i), 4)} for n, i in zip(FEATURE_NAMES, importances)
        ]
        pairs.sort(key=lambda p: p["importance"], reverse=True)
        return pairs[:limit]
    return list(model_info_data["top_features"])[:limit]


@app.route("/", methods=["GET"])
def root():
    return jsonify(
        {
            "status": "Craxis REST API is running",
            "version": model_version,
            "feature_count": len(FEATURE_NAMES),
        }
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "version": model_version,
            "feature_count": len(FEATURE_NAMES),
            "intel_enabled": domain_intel.intel_enabled(),
        }
    )


@app.route("/model-info", methods=["GET"])
def model_info():
    return (
        jsonify(
            {
                "model": model_algorithm,
                "version": model_version,
                "feature_count": len(FEATURE_NAMES),
                "top_features": top_feature_pairs(6),
                "metrics": model_info_data["metrics"],
            }
        ),
        200,
    )


@app.route("/api/model-evaluation", methods=["GET"])
def api_model_evaluation():
    json_path = os.path.join(SCRIPT_DIR, "evaluation_results.json")
    if not os.path.exists(json_path):
        return jsonify({"error": "Evaluation results not found. Run: python ml/evaluate_model.py"}), 404
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            return jsonify(json.load(fh)), 200
    except Exception as exc:
        return jsonify({"error": f"Failed to read evaluation results: {exc}"}), 500


@app.route("/test-pages/", methods=["GET"])
@app.route("/test-pages/index.html", methods=["GET"])
def serve_test_center():
    if os.path.exists(os.path.join(TEST_PAGES_DIR, "index.html")):
        return send_from_directory(TEST_PAGES_DIR, "index.html")
    return jsonify({"error": "Test center index.html not found"}), 404


@app.route("/test-pages/<path:filename>", methods=["GET"])
def serve_test_pages(filename):
    # send_from_directory rejects path traversal; the explicit check keeps the intent obvious.
    safe_name = os.path.normpath(filename)
    if safe_name.startswith("..") or os.path.isabs(safe_name):
        return jsonify({"error": "Access denied"}), 403
    target = os.path.join(TEST_PAGES_DIR, safe_name)
    if not os.path.isfile(target):
        return jsonify({"error": f"Test page '{safe_name}' not found"}), 404
    return send_from_directory(TEST_PAGES_DIR, safe_name)


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    if not data or not isinstance(data.get("url"), str) or not data["url"].strip():
        return jsonify({"error": "URL is required"}), 400

    target_url = data["url"].strip()
    if len(target_url) > 4096:
        return jsonify({"error": "URL is too long"}), 400

    try:
        features = extract_features(target_url)
        X = np.array([features], dtype=float)

        prediction_class = int(model_obj.predict(X)[0])
        if hasattr(model_obj, "predict_proba"):
            probs = model_obj.predict_proba(X)[0]
            phishing_prob = float(probs[1]) if len(probs) > 1 else float(prediction_class)
            legitimate_prob = float(probs[0]) if len(probs) > 1 else 1.0 - float(prediction_class)
        else:
            phishing_prob = float(prediction_class)
            legitimate_prob = 1.0 - phishing_prob

        response = {
            "url": target_url,
            "prediction": "PHISHING" if prediction_class == 1 else "LEGITIMATE",
            "phishing_probability": round(phishing_prob, 4),
            "legitimate_probability": round(legitimate_prob, 4),
            "ai_risk_score": round(phishing_prob * 100.0, 2),
            "model": f"{model_algorithm} (Version {model_version})",
            "feature_count": len(FEATURE_NAMES),
            "top_features": top_feature_pairs(5),
        }

        if data.get("intel") is True and domain_intel.intel_enabled():
            host = (urlparse(target_url).hostname or "").lower()
            intel = domain_intel.lookup(host, use_tls=target_url.lower().startswith("https://"))
            if intel:
                response["intel"] = intel

        return jsonify(response), 200
    except Exception as exc:
        print(f"[ERROR] Failed to analyze URL '{target_url[:200]}': {exc}")
        return jsonify({"error": "Failed to analyze URL"}), 500


if __name__ == "__main__":
    host = os.environ.get("AIPHISH_HOST", "127.0.0.1")
    port = int(os.environ.get("AIPHISH_PORT", "5000"))
    print("=" * 60)
    print("Craxis REST API")
    print(f"Model: {model_algorithm} (version {model_version})")
    print(f"Domain intelligence: {'ENABLED' if domain_intel.intel_enabled() else 'disabled'}")
    print(f"Serving on http://{host}:{port}  (test pages: /test-pages/index.html)")
    print("=" * 60)
    app.run(host=host, port=port, debug=False)

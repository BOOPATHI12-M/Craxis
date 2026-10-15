"""Evaluate the saved model on the held-out, domain-grouped test split.

Writes ml/evaluation_results.json (served by Flask and used by the test-pages
evaluation dashboard) and ml/MODEL-EVALUATION-REPORT.md.

Usage:
    python ml/evaluate_model.py [--dataset path/to/file.csv]
"""
import argparse
import datetime
import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from dataset_utils import group_split, load_dataset, resolve_dataset_path
from feature_extractor import FEATURE_NAMES, extract_features

ML_DIR = Path(__file__).resolve().parent
MODEL_PATH = ML_DIR / "model" / "phishing_model.pkl"
LEGACY_PATH = ML_DIR / "model" / "phishing_model_v2_legacy.pkl"
JSON_PATH = ML_DIR / "evaluation_results.json"
REPORT_PATH = ML_DIR / "MODEL-EVALUATION-REPORT.md"


def score_model(model, X_test, y_test) -> dict:
    pred = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]
    tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
    try:
        auc = round(float(roc_auc_score(y_test, proba)), 4)
        fpr, tpr, _ = roc_curve(y_test, proba)
        mask = fpr <= 0.01
        recall_at_1pct_fpr = round(float(tpr[mask].max()), 4) if mask.any() else 0.0
    except ValueError:
        auc, recall_at_1pct_fpr = None, None
    return {
        "metrics": {
            "accuracy": round(float(accuracy_score(y_test, pred)), 4),
            "precision": round(float(precision_score(y_test, pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, pred, zero_division=0)), 4),
            "roc_auc": auc,
            "false_positive_rate": round(float(fp / (fp + tn)), 4) if (fp + tn) else 0.0,
            "recall_at_1pct_fpr": recall_at_1pct_fpr,
        },
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }


def legacy_comparison(X_test, y_test):
    """Score the previous (20-feature) model on the same held-out set, if present."""
    if not LEGACY_PATH.exists():
        return None
    try:
        payload = joblib.load(LEGACY_PATH)
        legacy = payload["model"] if isinstance(payload, dict) else payload
        cols = getattr(legacy, "n_features_in_", 20)
        scored = score_model(legacy, X_test[:, :cols], y_test)
        return {"model": "Previous Random Forest (20 features)", **scored}
    except Exception as exc:  # pragma: no cover - best effort
        print(f"  (legacy comparison skipped: {exc})")
        return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", help="Path to a url,label CSV.")
    args = parser.parse_args(argv)

    if not MODEL_PATH.exists():
        print("Model not found. Run: python ml/train_model.py", file=sys.stderr)
        return 1

    print("=" * 64)
    print("Craxis - model evaluation")
    print("=" * 64)

    payload = joblib.load(MODEL_PATH)
    model = payload["model"] if isinstance(payload, dict) else payload
    version = payload.get("version", "unknown") if isinstance(payload, dict) else "unknown"
    algorithm = payload.get("algorithm", "Random Forest") if isinstance(payload, dict) else "Random Forest"
    stored_features = payload.get("feature_names") if isinstance(payload, dict) else None
    if stored_features and list(stored_features) != list(FEATURE_NAMES):
        print("Model feature list does not match feature_extractor.py. Retrain the model.", file=sys.stderr)
        return 1

    dataset_path = resolve_dataset_path(args.dataset)
    df = load_dataset(dataset_path)
    X = np.array([extract_features(u) for u in df["url"]], dtype=float)
    y = df["label"].to_numpy()
    train_idx, test_idx = group_split(df)
    X_test, y_test = X[test_idx], y[test_idx]

    scored = score_model(model, X_test, y_test)
    m = scored["metrics"]
    cm = scored["confusion_matrix"]
    print(f"Dataset {dataset_path.name}: {len(df)} rows, test={len(test_idx)}")
    print(f"Accuracy {m['accuracy']:.4f}  Precision {m['precision']:.4f}  Recall {m['recall']:.4f}  "
          f"F1 {m['f1_score']:.4f}  AUC {m['roc_auc']}  FPR {m['false_positive_rate']:.4f}")

    top_features = payload.get("top_features", []) if isinstance(payload, dict) else []
    legacy = legacy_comparison(X_test, y_test)

    total_legit = int((y == 0).sum())
    total_phish = int((y == 1).sum())
    test_legit = int((y_test == 0).sum())
    test_phish = int((y_test == 1).sum())

    result = {
        "model": algorithm,
        "version": version,
        "dataset": dataset_path.name,
        "total_samples": int(len(df)),
        "training_samples": int(len(train_idx)),
        "testing_samples": int(len(test_idx)),
        "dataset_distribution": {"legitimate": total_legit, "phishing": total_phish},
        "testing_distribution": {"legitimate": test_legit, "phishing": test_phish},
        "evaluation_method": "80/20 split grouped by domain (no site appears in both sets)",
        "metrics": m,
        "confusion_matrix": cm,
        "feature_count": len(FEATURE_NAMES),
        "top_features": top_features[:8],
        "cross_validation": payload.get("cv_scores", {}) if isinstance(payload, dict) else {},
        "previous_model": legacy,
        "generated_at": datetime.date.today().isoformat(),
    }
    JSON_PATH.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Wrote {JSON_PATH}")

    lines = [
        "# Craxis: Model Evaluation Report",
        "",
        "## Summary",
        "",
        f"- **Algorithm:** {algorithm}",
        f"- **Model version:** {version}",
        f"- **Dataset:** `{dataset_path.name}` ({len(df)} unique URLs)",
        f"- **Method:** 80/20 split grouped by domain, so no site is in both sets",
        f"- **Generated:** {result['generated_at']}",
        "",
        "## Held-out metrics",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| Accuracy | {m['accuracy']:.4f} |",
        f"| Precision | {m['precision']:.4f} |",
        f"| Recall | {m['recall']:.4f} |",
        f"| F1 score | {m['f1_score']:.4f} |",
        f"| ROC-AUC | {m['roc_auc']} |",
        f"| False-positive rate | {m['false_positive_rate']:.4f} |",
        f"| Recall at 1% false-positive rate | {m['recall_at_1pct_fpr']} |",
        "",
        "## Confusion matrix",
        "",
        "| | Predicted legitimate | Predicted phishing |",
        "| :--- | ---: | ---: |",
        f"| **Actual legitimate** | {cm['true_negative']} | {cm['false_positive']} |",
        f"| **Actual phishing** | {cm['false_negative']} | {cm['true_positive']} |",
        "",
        "## Samples",
        "",
        "| Class | Whole dataset | Test split |",
        "| :--- | ---: | ---: |",
        f"| Legitimate | {total_legit} | {test_legit} |",
        f"| Phishing | {total_phish} | {test_phish} |",
        "",
    ]
    if result["cross_validation"]:
        lines += ["## Model comparison (5-fold grouped cross-validation)", "", "| Model | Mean ROC-AUC | Std |", "| :--- | ---: | ---: |"]
        for name, s in result["cross_validation"].items():
            lines.append(f"| {name} | {s['mean_auc']:.4f} | {s['std_auc']:.4f} |")
        lines.append("")
    if legacy:
        lm = legacy["metrics"]
        lines += [
            "## Comparison with the previous model",
            "",
            "| Metric | Previous (20 features) | Current |",
            "| :--- | ---: | ---: |",
            f"| Accuracy | {lm['accuracy']:.4f} | {m['accuracy']:.4f} |",
            f"| Recall | {lm['recall']:.4f} | {m['recall']:.4f} |",
            f"| ROC-AUC | {lm['roc_auc']} | {m['roc_auc']} |",
            f"| False-positive rate | {lm['false_positive_rate']:.4f} | {m['false_positive_rate']:.4f} |",
            "",
        ]
    lines += ["## Top features", ""]
    for rank, feat in enumerate(top_features[:8], 1):
        lines.append(f"{rank}. `{feat['name']}`: {feat['importance'] * 100:.1f}%")
    lines += [
        "",
        "## Limitations",
        "",
        "1. Phishing URLs come from one public feed (PhishTank). Other feeds may behave differently.",
        "2. Legitimate URLs use real Tranco domains with synthetic paths, so real-world deep links may score differently.",
        "3. Phishing patterns change quickly. Retrain on fresh data regularly.",
        "4. The model sees only URL features. Page content is scored separately by the extension.",
        "",
    ]
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

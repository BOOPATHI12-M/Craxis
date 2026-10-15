"""Train the phishing URL classifier.

Steps
-----
1. Load and clean the dataset (ml/dataset/phishing_urls_full.csv if present,
   otherwise the tiny sample CSV).
2. Extract features and split by domain, so the same site is never in both the
   training and the test set.
3. Compare Random Forest and Histogram Gradient Boosting with 5-fold grouped
   cross-validation (ROC-AUC) and keep the better one.
4. Fit on the training split, report held-out metrics, and save the model
   together with its feature list.
5. Regenerate evaluation_results.json.

Usage:
    python ml/train_model.py [--dataset path/to/file.csv]
"""
import argparse
import datetime
import shutil
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold, cross_val_score

from dataset_utils import group_split, load_dataset, resolve_dataset_path
from feature_extractor import FEATURE_NAMES, extract_features

MODEL_VERSION = "3.0"
MODEL_DIR = Path(__file__).resolve().parent / "model"
MODEL_PATH = MODEL_DIR / "phishing_model.pkl"
LEGACY_PATH = MODEL_DIR / "phishing_model_v2_legacy.pkl"


def build_candidates() -> dict:
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=150,
            min_samples_leaf=2,
            max_features="sqrt",
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        ),
        "Histogram Gradient Boosting": HistGradientBoostingClassifier(
            max_iter=200, learning_rate=0.1, random_state=42
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", help="Path to a url,label CSV.")
    args = parser.parse_args()

    print("=" * 64)
    print(f"Craxis - model training (version {MODEL_VERSION})")
    print(f"Features: {len(FEATURE_NAMES)}")
    print("=" * 64)

    dataset_path = resolve_dataset_path(args.dataset)
    print(f"\n[1/5] Loading dataset: {dataset_path}")
    df = load_dataset(dataset_path)
    n_legit = int((df["label"] == 0).sum())
    n_phish = int((df["label"] == 1).sum())
    print(f"  rows={len(df)}  legitimate={n_legit}  phishing={n_phish}  groups={df['group'].nunique()}")
    if n_legit == 0 or n_phish == 0:
        print("Dataset needs both classes.", file=sys.stderr)
        return 1
    if len(df) < 1000:
        print("  WARNING: very small dataset. Metrics will not be reliable.")
        print("  Run `python ml/build_dataset.py` to build a real dataset.")

    print(f"\n[2/5] Extracting {len(FEATURE_NAMES)} features and splitting by domain ...")
    X = np.array([extract_features(u) for u in df["url"]], dtype=float)
    y = df["label"].to_numpy()
    groups = df["group"].to_numpy()
    train_idx, test_idx = group_split(df)
    X_train, y_train, g_train = X[train_idx], y[train_idx], groups[train_idx]
    X_test, y_test = X[test_idx], y[test_idx]
    print(f"  train={len(train_idx)}  test={len(test_idx)}")

    print("\n[3/5] Comparing models with grouped cross-validation (ROC-AUC) ...")
    candidates = build_candidates()
    cv_scores = {}
    n_groups = len(set(g_train))
    if n_groups >= 5 and len(train_idx) >= 200:
        cv = GroupKFold(n_splits=5)
        for name, model in candidates.items():
            scores = cross_val_score(model, X_train, y_train, groups=g_train, cv=cv, scoring="roc_auc")
            cv_scores[name] = {"mean_auc": float(scores.mean()), "std_auc": float(scores.std())}
            print(f"  {name:<30} AUC {scores.mean():.4f} +/- {scores.std():.4f}")
        best_name = max(cv_scores, key=lambda k: cv_scores[k]["mean_auc"])
    else:
        best_name = "Random Forest"
        print("  Too little data for cross-validation. Using Random Forest.")
    print(f"  Selected: {best_name}")

    print("\n[4/5] Fitting the selected model and evaluating on the held-out set ...")
    model = build_candidates()[best_name]
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]
    tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
    try:
        auc = float(roc_auc_score(y_test, proba))
    except ValueError:
        auc = None
    metrics = {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1": float(f1_score(y_test, pred, zero_division=0)),
        "roc_auc": auc,
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
    }
    for key, value in metrics.items():
        if value is not None:
            print(f"  {key:<22} {value:.4f}")
    print(f"  confusion matrix: TN={tn} FP={fp} FN={fn} TP={tp}")

    if hasattr(model, "feature_importances_"):
        importances = np.asarray(model.feature_importances_, dtype=float)
    else:
        sample = min(len(test_idx), 3000)
        result = permutation_importance(
            model, X_test[:sample], y_test[:sample], n_repeats=3, random_state=42, scoring="roc_auc"
        )
        importances = np.clip(result.importances_mean, 0, None)
        total = importances.sum()
        importances = importances / total if total > 0 else importances
    order = np.argsort(importances)[::-1]
    top_features = [
        {"name": FEATURE_NAMES[i], "importance": round(float(importances[i]), 4)} for i in order
    ]
    for rank, item in enumerate(top_features[:8], 1):
        print(f"  {rank}. {item['name']:<28} {item['importance']:.4f}")

    print("\n[5/5] Saving model package ...")
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    if MODEL_PATH.exists() and not LEGACY_PATH.exists():
        shutil.copy2(MODEL_PATH, LEGACY_PATH)
        print(f"  Kept previous model as {LEGACY_PATH.name} for comparison.")

    payload = {
        "model": model,
        "version": MODEL_VERSION,
        "algorithm": best_name,
        "feature_names": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "training_date": datetime.date.today().isoformat(),
        "dataset": dataset_path.name,
        "dataset_rows": int(len(df)),
        "metrics": metrics,
        "cv_scores": cv_scores,
        "top_features": top_features,
    }
    joblib.dump(payload, MODEL_PATH, compress=3)
    print(f"  Saved {MODEL_PATH} ({MODEL_PATH.stat().st_size / 1_000_000:.1f} MB)")

    import evaluate_model

    evaluate_model.main(["--dataset", str(dataset_path)])
    print("\nTraining finished.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

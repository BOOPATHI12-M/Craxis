"""Train CANDIDATE models on the experimental PhreshPhish dataset.

The active model (ml/model/phishing_model.pkl) is never read for writing.
Candidates are saved under new names in the same package format the Flask
backend already loads, so they can be tried with:

    AIPHISH_MODEL_PATH=ml/model/candidate_phresh_balanced.pkl python ml/app.py

Same algorithm, hyperparameters and 32-feature extractor as version 3.0, so the
only difference between v3 and a candidate is the training data.

Usage:
    python ml/train_candidate.py
"""
import datetime
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score

from feature_extractor import FEATURE_NAMES, extract_features

ML_DIR = Path(__file__).resolve().parent
DATA = ML_DIR / "dataset" / "experimental_phreshphish.csv"
MODEL_DIR = ML_DIR / "model"
CACHE = Path(__import__("os").environ.get("TEMP", ".")) / "phresh_features.npz"


def features_for(urls) -> np.ndarray:
    return np.array([extract_features(u) for u in urls], dtype=float)


def load_features(df: pd.DataFrame) -> np.ndarray:
    """Extract features once and cache them outside the project."""
    if CACHE.exists():
        cached = np.load(CACHE, allow_pickle=True)
        if int(cached["n"]) == len(df) and list(cached["names"]) == list(FEATURE_NAMES):
            print(f"Using cached features: {CACHE}")
            return cached["X"]
    t = time.time()
    X = features_for(df["url"])
    np.savez(CACHE, X=X, n=len(df), names=np.array(FEATURE_NAMES))
    print(f"Extracted {X.shape} features in {time.time() - t:.0f}s")
    return X


def main() -> int:
    if not DATA.exists():
        print("Run ml/prepare_phreshphish.py first.", file=sys.stderr)
        return 1
    df = pd.read_csv(DATA)
    X = load_features(df)
    y = df["label"].to_numpy()

    variants = {
        "candidate_phresh_all": (df["split"] == "train"),
        "candidate_phresh_balanced": (df["split"] == "train") & (df["balanced"] == 1),
    }
    for name, mask in variants.items():
        idx = np.flatnonzero(mask.to_numpy())
        t = time.time()
        model = RandomForestClassifier(
            n_estimators=150, min_samples_leaf=2, max_features="sqrt",
            class_weight="balanced", n_jobs=-1, random_state=42,
        ).fit(X[idx], y[idx])
        secs = time.time() - t

        ev = np.flatnonzero((df["split"] == "eval").to_numpy())
        auc = float(roc_auc_score(y[ev], model.predict_proba(X[ev])[:, 1]))
        order = np.argsort(model.feature_importances_)[::-1]
        payload = {
            "model": model,
            "version": f"3.1-{name}",
            "algorithm": "Random Forest (candidate, not active)",
            "feature_names": list(FEATURE_NAMES),
            "feature_count": len(FEATURE_NAMES),
            "training_date": datetime.date.today().isoformat(),
            "dataset": DATA.name,
            "dataset_rows": int(len(idx)),
            "metrics": {"roc_auc_eval_sites": round(auc, 4)},
            "top_features": [
                {"name": FEATURE_NAMES[i], "importance": round(float(model.feature_importances_[i]), 4)}
                for i in order
            ],
        }
        out = MODEL_DIR / f"{name}.pkl"
        if out.exists():
            print(f"{out.name} already exists; refusing to overwrite.", file=sys.stderr)
            return 1
        joblib.dump(payload, out, compress=3)
        print(f"{name}: trained on {len(idx)} rows in {secs:.0f}s, eval-site ROC-AUC {auc:.4f}, "
              f"saved {out.name} ({out.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

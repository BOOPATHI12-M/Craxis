"""Train COMBINED candidate models: original dataset plus PhreshPhish.

Training data
-------------
 original  : the TRAINING split of ml/dataset/phishing_urls_full.csv, the same
             rows v3 was trained on (PhishTank phishing, Tranco domains with
             synthetic paths)
 phresh    : the TRAINING split of ml/dataset/experimental_phreshphish.csv

Sites in the original TEST split and the PhreshPhish EVAL split are never used,
so every evaluation set stays unseen.

Variants
--------
 combined_concat    all rows of both sources
 combined_weighted  all rows, original rows weighted so each source contributes
                    the same total weight (the original is about 10 times smaller)
 combined_balanced  original rows plus the class-balanced PhreshPhish subset

Same algorithm, settings and 32-feature extractor as v3. Active model untouched.

Usage:
    python ml/train_combined.py
"""
import datetime
import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from dataset_utils import FULL_DATASET, group_split, load_dataset
from feature_extractor import FEATURE_NAMES, extract_features

ML_DIR = Path(__file__).resolve().parent
EXP = ML_DIR / "dataset" / "experimental_phreshphish.csv"
MODEL_DIR = ML_DIR / "model"
TEMP = Path(os.environ.get("TEMP", "."))
EXP_CACHE = TEMP / "phresh_features.npz"
CUR_CACHE = TEMP / "original_features.npz"


def cached_features(df: pd.DataFrame, cache: Path) -> np.ndarray:
    if cache.exists():
        c = np.load(cache, allow_pickle=True)
        if int(c["n"]) == len(df) and list(c["names"]) == list(FEATURE_NAMES):
            return c["X"]
    X = np.array([extract_features(u) for u in df["url"]], dtype=float)
    np.savez(cache, X=X, n=len(df), names=np.array(FEATURE_NAMES))
    return X


def main() -> int:
    exp = pd.read_csv(EXP)
    X_exp = cached_features(exp, EXP_CACHE)
    cur = load_dataset(FULL_DATASET)
    X_cur = cached_features(cur, CUR_CACHE)
    train_idx, _ = group_split(cur)
    train_idx = np.array(train_idx)

    e_tr = np.flatnonzero((exp["split"] == "train").to_numpy())
    e_bal = np.flatnonzero(((exp["split"] == "train") & (exp["balanced"] == 1)).to_numpy())
    y_cur, y_exp = cur["label"].to_numpy(), exp["label"].to_numpy()

    def stack(exp_idx, cur_weight=1.0):
        X = np.vstack([X_cur[train_idx], X_exp[exp_idx]])
        y = np.concatenate([y_cur[train_idx], y_exp[exp_idx]])
        w = np.concatenate([np.full(len(train_idx), cur_weight), np.ones(len(exp_idx))])
        return X, y, w

    ratio = len(e_tr) / len(train_idx)
    variants = {
        "candidate_combined_concat": stack(e_tr),
        "candidate_combined_weighted": stack(e_tr, cur_weight=ratio),
        "candidate_combined_balanced": stack(e_bal),
    }

    for name, (X, y, w) in variants.items():
        out = MODEL_DIR / f"{name}.pkl"
        if out.exists():
            print(f"{out.name} exists; refusing to overwrite.", file=sys.stderr)
            return 1
        t = time.time()
        model = RandomForestClassifier(
            n_estimators=150, min_samples_leaf=2, max_features="sqrt",
            class_weight="balanced", n_jobs=-1, random_state=42,
        ).fit(X, y, sample_weight=w)
        order = np.argsort(model.feature_importances_)[::-1]
        joblib.dump({
            "model": model,
            "version": f"3.2-{name}",
            "algorithm": "Random Forest (candidate, not active)",
            "feature_names": list(FEATURE_NAMES),
            "feature_count": len(FEATURE_NAMES),
            "training_date": datetime.date.today().isoformat(),
            "dataset": "phishing_urls_full.csv train split + experimental_phreshphish.csv train split",
            "dataset_rows": int(len(y)),
            "metrics": {},
            "top_features": [{"name": FEATURE_NAMES[i], "importance": round(float(model.feature_importances_[i]), 4)}
                             for i in order],
        }, out, compress=3)
        print(f"{name}: {len(y)} rows ({int((y == 1).sum())} phishing) in {time.time() - t:.0f}s, "
              f"saved {out.name} ({out.stat().st_size / 1e6:.0f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

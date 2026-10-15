"""Compare the active model (v3) with candidate models on the SAME held-out data.

Read-only: no model or dataset is modified. Writes ml/model_comparison_results.json.

Evaluation sets
---------------
 eval_all       all eval-split rows of the experimental dataset (sites never used
                for training any candidate, and never used for training v3)
 eval_balanced  the class-balanced subset of the same rows
 original_test  v3's own held-out split from ml/dataset/phishing_urls_full.csv

Usage:
    python ml/compare_models.py
"""
import json
import os
import sys
import warnings
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score, roc_curve

from dataset_utils import FULL_DATASET, group_split, load_dataset
from feature_extractor import FEATURE_NAMES, extract_features, on_shared_hosting

warnings.filterwarnings("ignore")
ML_DIR = Path(__file__).resolve().parent
MODELS = {
    "v3 (active)": ML_DIR / "model" / "phishing_model.pkl",
    "candidate all": ML_DIR / "model" / "candidate_phresh_all.pkl",
    "candidate balanced": ML_DIR / "model" / "candidate_phresh_balanced.pkl",
}
CACHE = Path(os.environ.get("TEMP", ".")) / "phresh_features.npz"


def load_model(path):
    payload = joblib.load(path)
    assert list(payload["feature_names"]) == list(FEATURE_NAMES), f"feature mismatch in {path.name}"
    return payload["model"]


def metrics(y, p, thr=0.5):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {
        "n": int(len(y)), "benign": int((y == 0).sum()), "phishing": int((y == 1).sum()),
        "accuracy": round((tn + tp) / len(y), 4),
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
        "recall": round(tp / (tp + fn), 4) if (tp + fn) else None,
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else None,
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if len(set(y)) == 2:
        out["roc_auc"] = round(float(roc_auc_score(y, p)), 4)
        fpr, tpr, _ = roc_curve(y, p)
        ok = fpr <= 0.01
        out["recall_at_1pct_fpr"] = round(float(tpr[ok].max()), 4) if ok.any() else 0.0
    return out


def main() -> int:
    exp = pd.read_csv(ML_DIR / "dataset" / "experimental_phreshphish.csv")
    cached = np.load(CACHE, allow_pickle=True)
    X_exp = cached["X"]
    assert len(X_exp) == len(exp)

    cur = load_dataset(FULL_DATASET)
    _, te = group_split(cur)
    cur_test = cur.iloc[te].reset_index(drop=True)
    X_cur = np.array([extract_features(u) for u in cur_test["url"]], dtype=float)

    ev = exp[exp["split"] == "eval"].reset_index(drop=True)
    X_ev = X_exp[(exp["split"] == "eval").to_numpy()]
    y_ev = ev["label"].to_numpy()
    bal = (ev["balanced"] == 1).to_numpy()

    path = ev["url"].map(lambda u: urlparse(u).path)
    depth = path.str.strip("/").map(lambda p: 0 if not p else p.count("/") + 1)
    host = ev["url"].map(lambda u: (urlparse(u).hostname or "").lower())
    shared = host.map(on_shared_hosting).to_numpy()
    groups = {
        "benign, deep path (2+ segments)": (y_ev == 0) & (depth >= 2).to_numpy(),
        "benign, any path": (y_ev == 0) & (depth >= 1).to_numpy(),
        "benign, root only": (y_ev == 0) & (depth == 0).to_numpy(),
        "benign, starts with www": (y_ev == 0) & host.str.startswith("www.").to_numpy(),
        "benign, no www": (y_ev == 0) & ~host.str.startswith("www.").to_numpy(),
        "benign, on shared hosting": (y_ev == 0) & shared,
        "phishing, shared hosting": (y_ev == 1) & shared,
        "phishing, not shared hosting": (y_ev == 1) & ~shared,
        "phishing, with path": (y_ev == 1) & (depth >= 1).to_numpy(),
        "phishing, root only": (y_ev == 1) & (depth == 0).to_numpy(),
    }

    results = {"sets": {}, "subgroups": {}, "controls": {}}
    probs = {}
    for name, path_ in MODELS.items():
        m = load_model(path_)
        probs[name] = {
            "eval_all": m.predict_proba(X_ev)[:, 1],
            "original_test": m.predict_proba(X_cur)[:, 1],
        }

    for set_name, y, sel, key in (
        ("eval_all", y_ev, np.ones(len(y_ev), bool), "eval_all"),
        ("eval_balanced", y_ev[bal], bal, "eval_all"),
        ("original_test", cur_test["label"].to_numpy(), None, "original_test"),
    ):
        results["sets"][set_name] = {}
        for name in MODELS:
            p = probs[name][key]
            p = p[sel] if sel is not None else p
            results["sets"][set_name][name] = metrics(y, p)

    for g, mask in groups.items():
        results["subgroups"][g] = {"rows": int(mask.sum())}
        for name in MODELS:
            p = probs[name]["eval_all"][mask]
            pred = p >= 0.5
            if g.startswith("benign"):
                results["subgroups"][g][name] = {"flagged_as_phishing_pct": round(100 * float(pred.mean()), 2),
                                                 "mean_probability": round(float(p.mean()), 3)}
            else:
                results["subgroups"][g][name] = {"detected_pct": round(100 * float(pred.mean()), 2),
                                                 "mean_probability": round(float(p.mean()), 3)}

    # control: shuffled labels must give about 0.5
    train = exp["split"] == "train"
    idx = np.flatnonzero((train & (exp["balanced"] == 1)).to_numpy())
    rng = np.random.default_rng(0)
    y_shuf = rng.permutation(exp["label"].to_numpy()[idx])
    ctrl = RandomForestClassifier(n_estimators=150, min_samples_leaf=2, class_weight="balanced",
                                  n_jobs=-1, random_state=42).fit(X_exp[idx], y_shuf)
    results["controls"]["shuffled_labels_roc_auc"] = round(
        float(roc_auc_score(y_ev, ctrl.predict_proba(X_ev)[:, 1])), 4)

    # control: how much of the candidate's skill is host-level only
    path_cols = [i for i, n in enumerate(FEATURE_NAMES) if n in ("path_length", "path_depth")]
    keep = [i for i in range(len(FEATURE_NAMES)) if i not in path_cols]
    idx_all = np.flatnonzero(train.to_numpy())
    host_only = RandomForestClassifier(n_estimators=150, min_samples_leaf=2, class_weight="balanced",
                                       n_jobs=-1, random_state=42).fit(X_exp[idx_all][:, keep], exp["label"].to_numpy()[idx_all])
    results["controls"]["all_rows_without_path_features_roc_auc"] = round(
        float(roc_auc_score(y_ev, host_only.predict_proba(X_ev[:, keep])[:, 1])), 4)

    out = ML_DIR / "model_comparison_results.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")

    for set_name, per in results["sets"].items():
        print(f"\n== {set_name} ==")
        for name, m in per.items():
            print(f"  {name:20s} AUC {m.get('roc_auc')}  acc {m['accuracy']}  prec {m['precision']}  "
                  f"recall {m['recall']}  FPR {m['false_positive_rate']}  recall@1%FPR {m.get('recall_at_1pct_fpr')}  "
                  f"n={m['n']} cm={m['confusion']}")
    print("\n== subgroups on eval_all (benign: % wrongly flagged; phishing: % detected) ==")
    for g, v in results["subgroups"].items():
        cells = []
        for name in MODELS:
            e = v[name]
            cells.append(f"{name}: {e.get('flagged_as_phishing_pct', e.get('detected_pct'))}%")
        print(f"  {g:34s} n={v['rows']:6d}  " + " | ".join(cells))
    print("\ncontrols:", results["controls"])
    return 0


if __name__ == "__main__":
    sys.exit(main())

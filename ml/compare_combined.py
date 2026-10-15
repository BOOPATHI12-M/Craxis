"""Evaluate v3, the PhreshPhish-only candidate and the combined candidates.

Read-only. Same checks as compare_models.py plus two independent sources:
  independent    StealthPhisher URLs whose site and URL appear in NO training or
                 evaluation set used here, restricted to root-only URLs without
                 queries so that path length cannot decide the answer
  newer_phishing PhishTank URLs from the current feed that are in no training or
                 evaluation set (recall only, because it holds phishing only)

Usage:
    python ml/compare_combined.py [--stealth path.csv] [--phishtank path.csv]
"""
import argparse
import html
import json
import os
import re
import sys
import warnings
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd

from compare_models import metrics
from dataset_utils import FULL_DATASET, group_key, group_split, load_dataset
from feature_extractor import FEATURE_NAMES, extract_features, on_shared_hosting
from prepare_phreshphish import norm_key

warnings.filterwarnings("ignore")
ML_DIR = Path(__file__).resolve().parent
TEMP = Path(os.environ.get("TEMP", "."))

MODELS = {
    "v3 (active)": "phishing_model.pkl",
    "phresh only (all)": "candidate_phresh_all.pkl",
    "combined concat": "candidate_combined_concat.pkl",
    "combined weighted": "candidate_combined_weighted.pkl",
    "combined balanced": "candidate_combined_balanced.pkl",
}


def feats(urls):
    return np.array([extract_features(u) for u in urls], dtype=float)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stealth", default=str(ML_DIR / "source" / "StealthPhisher2025.csv"))
    ap.add_argument("--phishtank", default=str(TEMP / "ds" / "phishtank.csv"))
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    exp = pd.read_csv(ML_DIR / "dataset" / "experimental_phreshphish.csv")
    X_exp = np.load(TEMP / "phresh_features.npz", allow_pickle=True)["X"]
    cur = load_dataset(FULL_DATASET)
    _, te = group_split(cur)
    cur_test = cur.iloc[te].reset_index(drop=True)
    X_cur_all = np.load(TEMP / "original_features.npz", allow_pickle=True)["X"]
    X_cur = X_cur_all[np.array(te)]
    ev_mask = (exp["split"] == "eval").to_numpy()
    ev = exp[ev_mask].reset_index(drop=True)
    X_ev = X_exp[ev_mask]
    y_ev = ev["label"].to_numpy()
    bal = (ev["balanced"] == 1).to_numpy()

    used_sites = set(cur["group"]) | set(exp["site"])
    used_keys = set(cur["url"].map(norm_key)) | set(exp["url"].map(norm_key))

    # independent StealthPhisher set ------------------------------------------
    st = pd.read_csv(args.stealth, usecols=["URL", "Label"]).rename(columns={"URL": "url"})
    st["y"] = (st["Label"].astype(str).str.strip() == "Phishing").astype(int)
    st["site"] = st["url"].map(group_key)
    st["key"] = st["url"].map(norm_key)
    st = st[~st["site"].isin(used_sites) & ~st["key"].isin(used_keys)]
    parts = st["url"].map(urlparse)
    st = st[parts.map(lambda p: p.path in ("", "/") and not p.query and not p.fragment)]
    st = st.sample(frac=1, random_state=args.seed).drop_duplicates(["site", "y"])
    n = min(int(st["y"].value_counts().min()), 25000)
    st = pd.concat([st[st.y == 0].head(n), st[st.y == 1].head(n)])
    X_st = feats(st["url"])
    y_st = st["y"].to_numpy()

    # newer phishing --------------------------------------------------------------
    pt = None
    if Path(args.phishtank).exists():
        pt = pd.read_csv(args.phishtank)
        pt = pt[(pt.verified == "yes") & (pt.online == "yes")].copy()
        pt["url"] = pt["url"].map(lambda u: html.unescape(str(u).strip()))
        pt = pt[pt["url"].str.match(r"^https?://")]
        pt["key"] = pt["url"].map(norm_key)
        pt["site"] = pt["url"].map(group_key)
        pt = pt[~pt["key"].isin(used_keys) & ~pt["site"].isin(used_sites)].drop_duplicates("key")
        pt = pt.sample(min(20000, len(pt)), random_state=args.seed)
        pt["stripped"] = pt["url"].map(lambda u: re.sub(r"[?#].*$", "", u))
        X_pt = feats(pt["stripped"])
        pt_shared = pt["stripped"].map(lambda u: on_shared_hosting((urlparse(u).hostname or "").lower())).to_numpy()

    # subgroups on the PhreshPhish eval sites ------------------------------------
    path = ev["url"].map(lambda u: urlparse(u).path)
    depth = path.str.strip("/").map(lambda p: 0 if not p else p.count("/") + 1).to_numpy()
    host = ev["url"].map(lambda u: (urlparse(u).hostname or "").lower())
    shared = host.map(on_shared_hosting).to_numpy()
    cur_shared = cur_test["url"].map(lambda u: on_shared_hosting((urlparse(u).hostname or "").lower())).to_numpy()
    y_cur = cur_test["label"].to_numpy()

    groups = {
        "real benign, deep path": (y_ev == 0) & (depth >= 2),
        "real benign, root only": (y_ev == 0) & (depth == 0),
        "real benign, no www": (y_ev == 0) & ~host.str.startswith("www.").to_numpy(),
        "real benign, shared hosting": (y_ev == 0) & shared,
        "real phishing, shared hosting": (y_ev == 1) & shared,
        "real phishing, not shared": (y_ev == 1) & ~shared,
    }

    results = {"sets": {}, "groups": {}, "sizes": {
        "eval_all": int(len(y_ev)), "eval_balanced": int(bal.sum()), "original_test": int(len(y_cur)),
        "independent": int(len(y_st)), "newer_phishing": int(len(pt)) if pt is not None else 0,
        "original_test_benign_shared_hosting": int(((y_cur == 0) & cur_shared).sum()),
    }}
    for name, fname in MODELS.items():
        m = joblib.load(ML_DIR / "model" / fname)["model"]
        p_ev = m.predict_proba(X_ev)[:, 1]
        p_cur = m.predict_proba(X_cur)[:, 1]
        p_st = m.predict_proba(X_st)[:, 1]
        r = results["sets"].setdefault(name, {})
        r["eval_all"] = metrics(y_ev, p_ev)
        r["eval_balanced"] = metrics(y_ev[bal], p_ev[bal])
        r["original_test"] = metrics(y_cur, p_cur)
        r["independent"] = metrics(y_st, p_st)
        r["original_test_benign_shared_flagged_pct"] = round(
            100 * float((p_cur[(y_cur == 0) & cur_shared] >= 0.5).mean()), 1)
        if pt is not None:
            p_pt = m.predict_proba(X_pt)[:, 1]
            r["newer_phishing_detected_pct"] = round(100 * float((p_pt >= 0.5).mean()), 1)
            r["newer_phishing_shared_pct"] = round(100 * float((p_pt[pt_shared] >= 0.5).mean()), 1)
            r["newer_phishing_not_shared_pct"] = round(100 * float((p_pt[~pt_shared] >= 0.5).mean()), 1)
        for g, mask in groups.items():
            results["groups"].setdefault(g, {"rows": int(mask.sum())})[name] = round(
                100 * float((p_ev[mask] >= 0.5).mean()), 1)

    (ML_DIR / "combined_comparison_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    names = list(MODELS)
    print("rows:", results["sizes"])
    for key, title in (("eval_all", "PhreshPhish eval sites"), ("eval_balanced", "PhreshPhish eval, balanced"),
                       ("original_test", "v3 original held-out"), ("independent", "independent StealthPhisher homepages")):
        print(f"\n== {title} ==")
        for n_ in names:
            m = results["sets"][n_][key]
            print(f"  {n_:20s} AUC {m.get('roc_auc')}  prec {m['precision']}  recall {m['recall']}  "
                  f"FPR {m['false_positive_rate']}  recall@1%FPR {m.get('recall_at_1pct_fpr')}")
    print("\n== recall on newer unseen PhishTank (detected %: all / shared / not shared) ==")
    for n_ in names:
        r = results["sets"][n_]
        print(f"  {n_:20s} {r.get('newer_phishing_detected_pct')} / {r.get('newer_phishing_shared_pct')} / "
              f"{r.get('newer_phishing_not_shared_pct')}   | original-test synthetic benign on shared hosting flagged: "
              f"{r['original_test_benign_shared_flagged_pct']}%")
    print("\n== subgroups on PhreshPhish eval sites (benign: % wrongly flagged, phishing: % detected) ==")
    for g, v in results["groups"].items():
        print(f"  {g:30s} n={v['rows']:6d}  " + " | ".join(f"{n_}: {v[n_]}%" for n_ in names))
    return 0


if __name__ == "__main__":
    sys.exit(main())

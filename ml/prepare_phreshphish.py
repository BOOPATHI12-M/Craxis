"""Prepare an EXPERIMENTAL training dataset from PhreshPhish URLs.

This script does not train anything and does not touch the active model or the
existing datasets. It reads the URL table written by fetch_phreshphish_urls.py
and writes a separate, git-ignored CSV plus a counts report.

Rules (see PHRESHPHISH-FULL-AUDIT.md for the reasons)
-----------------------------------------------------
 1. Decode HTML entities.
 2. Reject rows with no scheme, a non-http(s) scheme, whitespace, an
    unparseable URL or an empty host. Schemes are never guessed.
 3. Remove the query string and fragment from EVERY row.
 4. Keep only months in which both classes are present in reasonable
    proportion (default 10 to 90 percent phishing).
 5. Remove URLs that appear with both labels, then remove duplicates.
 6. Remove URLs already present in our current dataset.
 7. Cap rows per (site, label). A site is the registrable domain, or the full
    hostname on shared hosting platforms.
 8. Assign every site to train or eval, never both. Sites in the current
    dataset's test split stay eval, sites in its training split stay train.
 9. Mark a class-balanced subset: within each cell of path depth, path length
    and www prefix, both classes are sampled to equal size.

No label is changed and no label is decided from a hostname.

Usage:
    python ml/prepare_phreshphish.py --input ml/source/phreshphish_urls.parquet
"""
import argparse
import hashlib
import html
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd

from dataset_utils import FULL_DATASET, group_key, group_split, load_dataset
from feature_extractor import FEATURE_NAMES, extract_features

ML_DIR = Path(__file__).resolve().parent
OUT_CSV = ML_DIR / "dataset" / "experimental_phreshphish.csv"
OUT_REPORT = ML_DIR / "dataset" / "experimental_phreshphish_report.json"

SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def clean_url(raw: str):
    """Return (cleaned_url, None) or (None, reject_reason)."""
    url = html.unescape(str(raw)).strip()
    if re.search(r"\s", url):
        return None, "whitespace"
    match = SCHEME_RE.match(url)
    if not match:
        return None, "no_scheme"
    scheme = match.group(0)[:-3].lower()
    if scheme not in ("http", "https"):
        return None, "scheme_not_http"
    try:
        parts = urlparse(url)
        host = parts.hostname or ""
    except ValueError:
        return None, "unparseable"
    if not host:
        return None, "empty_host"
    return f"{scheme}://{parts.netloc}{parts.path}", None


def norm_key(url: str) -> str:
    """Key for duplicate detection: scheme, www, trailing slash and case ignored."""
    parts = urlparse(url)
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    port = f":{parts.port}" if parts.port and parts.port not in (80, 443) else ""
    return f"{host}{port}{parts.path.rstrip('/').lower()}"


def stable_bucket(text: str, buckets: int = 100) -> int:
    return int(hashlib.sha1(text.encode("utf-8")).hexdigest(), 16) % buckets


def univariate_auc(frame: pd.DataFrame, sample: int, seed: int) -> list:
    from sklearn.metrics import roc_auc_score

    s = frame.sample(min(sample, len(frame)), random_state=seed)
    feats = pd.DataFrame([extract_features(u) for u in s["url"]], columns=FEATURE_NAMES)
    out = []
    for name in FEATURE_NAMES:
        try:
            a = roc_auc_score(s["label"].to_numpy(), feats[name].to_numpy())
            out.append((name, round(max(a, 1 - a), 3)))
        except ValueError:
            out.append((name, 0.5))
    return sorted(out, key=lambda kv: -kv[1])[:6]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", required=True, help="Parquet from fetch_phreshphish_urls.py")
    parser.add_argument("--cap", type=int, default=20, help="Max rows per site and label (default 20).")
    parser.add_argument("--min-phish", type=float, default=0.10, help="Lowest monthly phishing share kept.")
    parser.add_argument("--max-phish", type=float, default=0.90, help="Highest monthly phishing share kept.")
    parser.add_argument("--eval-percent", type=int, default=20, help="Share of new sites assigned to eval.")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    report = {"parameters": vars(args), "steps": []}

    def step(name, rows_before, rows_after, note=""):
        report["steps"].append({"step": name, "rows_before": rows_before, "rows_after": rows_after,
                                "removed": rows_before - rows_after, "note": note})
        print(f"{name:46s} {rows_before:8d} -> {rows_after:8d}  (-{rows_before - rows_after})  {note}")

    df = pd.read_parquet(args.input)[["url", "label", "date"]].copy()
    df["label"] = df["label"].map({"benign": 0, "phish": 1})
    if df["label"].isna().any():
        print("Unknown label values found. Stopping.", file=sys.stderr)
        return 1
    df["label"] = df["label"].astype(int)
    report["input_rows"] = len(df)
    n0 = len(df)
    print(f"input rows: {n0}")

    # 1-3 cleaning ----------------------------------------------------------
    cleaned, reasons = [], Counter()
    for raw in df["url"]:
        url, why = clean_url(raw)
        cleaned.append(url)
        if why:
            reasons[why] += 1
    df["url"] = cleaned
    df = df[df["url"].notna()].copy()
    report["rejected_by_cleaning"] = dict(reasons)
    step("cleaning (scheme, whitespace, parse, host)", n0, len(df), str(dict(reasons)))

    # 4 months -------------------------------------------------------------
    df["month"] = pd.to_datetime(df["date"]).dt.to_period("M").astype(str)
    share = df.groupby("month")["label"].mean()
    count = df.groupby("month").size()
    keep_months = set(share.index[(share >= args.min_phish) & (share <= args.max_phish) & (count >= 1000)])
    report["months_kept"] = sorted(keep_months)
    report["months_excluded"] = {m: {"rows": int(count[m]), "phish_share": round(float(share[m]), 3)}
                                 for m in share.index if m not in keep_months}
    n = len(df)
    df = df[df["month"].isin(keep_months)].copy()
    step("months with both classes", n, len(df), f"{len(keep_months)} months kept")

    # 5 conflicts and duplicates -------------------------------------------
    df["key"] = df["url"].map(norm_key)
    labels_per_key = df.groupby("key")["label"].nunique()
    conflict_keys = set(labels_per_key.index[labels_per_key > 1])
    n = len(df)
    df = df[~df["key"].isin(conflict_keys)].copy()
    step("remove URLs with both labels", n, len(df), f"{len(conflict_keys)} keys")
    n = len(df)
    df = df.sort_values(["date", "url"]).drop_duplicates("key", keep="first").copy()
    step("remove normalised duplicates", n, len(df))

    # 6 overlap with current dataset ----------------------------------------
    cur = load_dataset(FULL_DATASET)
    cur_keys = set(cur["url"].map(norm_key))
    n = len(df)
    df = df[~df["key"].isin(cur_keys)].copy()
    step("remove URLs already in current dataset", n, len(df))

    # 7 cap per site and label ----------------------------------------------
    df["site"] = df["url"].map(group_key)
    mixed_sites = set(df.groupby("site")["label"].nunique().loc[lambda s: s > 1].index)
    df["mixed_site"] = df["site"].isin(mixed_sites).astype(int)
    n = len(df)
    parts = []
    for (_, _), g in df.groupby(["site", "label"], sort=False):
        if len(g) > args.cap:
            g = g.iloc[rng.sample(range(len(g)), args.cap)]
        parts.append(g)
    df = pd.concat(parts, ignore_index=True)
    step(f"cap {args.cap} rows per site and label", n, len(df), f"{len(mixed_sites)} sites hold both labels")

    # 8 split by site ---------------------------------------------------------
    cur["site"] = cur["url"].map(group_key)
    _, cur_test_idx = group_split(cur)
    cur_test_sites = set(cur.iloc[cur_test_idx]["site"])
    cur_train_sites = set(cur["site"]) - cur_test_sites

    def assign(site):
        if site in cur_test_sites:
            return "eval"
        if site in cur_train_sites:
            return "train"
        return "eval" if stable_bucket(site) < args.eval_percent else "train"

    df["split"] = df["site"].map(assign)
    sites_split = df.groupby("site")["split"].nunique()
    assert int((sites_split > 1).sum()) == 0, "a site landed in both splits"
    report["sites_forced_eval_by_current_test"] = int(df["site"].isin(cur_test_sites).sum())
    report["sites_forced_train_by_current_train"] = int(df["site"].isin(cur_train_sites).sum())

    # 9 balanced subset -------------------------------------------------------
    path = df["url"].map(lambda u: urlparse(u).path)
    depth = path.str.strip("/").map(lambda p: 0 if not p else p.count("/") + 1).clip(upper=3)
    plen = pd.cut(path.str.len(), [-1, 1, 10, 30, 60, 10_000], labels=False)
    www = df["url"].map(lambda u: int((urlparse(u).hostname or "").startswith("www.")))
    df["cell"] = depth.astype(str) + "|" + plen.astype(str) + "|" + www.astype(str)
    df["balanced"] = 0
    for (_, _), g in df.groupby(["split", "cell"]):
        b, p = g[g.label == 0], g[g.label == 1]
        k = min(len(b), len(p))
        if k == 0:
            continue
        chosen = list(b.index[rng.sample(range(len(b)), k)]) + list(p.index[rng.sample(range(len(p)), k)])
        df.loc[chosen, "balanced"] = 1

    # output -----------------------------------------------------------------
    out = df[["url", "label", "site", "split", "month", "mixed_site", "balanced"]].copy()
    out["source"] = "phreshphish"
    out.to_csv(OUT_CSV, index=False)

    def counts(frame):
        return {s: {"rows": int(len(g)), "benign": int((g.label == 0).sum()), "phishing": int((g.label == 1).sum()),
                    "sites": int(g["site"].nunique())} for s, g in frame.groupby("split")}

    report["final"] = counts(df)
    report["balanced_subset"] = counts(df[df.balanced == 1])
    report["final_rows"] = len(df)
    report["balanced_rows"] = int(df["balanced"].sum())
    report["mixed_site_rows"] = int(df["mixed_site"].sum())

    # shortcut check -----------------------------------------------------------
    report["univariate_shortcuts"] = {
        "all_rows": univariate_auc(df, 40000, args.seed),
        "balanced_subset": univariate_auc(df[df.balanced == 1], 40000, args.seed),
    }
    shares = []
    for name, frame in (("all_rows", df), ("balanced_subset", df[df.balanced == 1])):
        p = frame["url"].map(lambda u: urlparse(u).path)
        row = {"subset": name}
        for lab, text in ((0, "benign"), (1, "phishing")):
            sel = frame["label"] == lab
            row[f"{text}_with_path_pct"] = round(100 * float((p[sel].str.strip("/") != "").mean()), 1)
            row[f"{text}_deep_pct"] = round(100 * float((p[sel].str.strip("/").str.count("/") >= 1).mean()), 1)
            row[f"{text}_www_pct"] = round(
                100 * float(frame.loc[sel, "url"].map(lambda u: (urlparse(u).hostname or "").startswith("www.")).mean()), 1)
        shares.append(row)
    report["class_shape_comparison"] = shares

    OUT_REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\nFINAL", json.dumps(report["final"]))
    print("BALANCED", json.dumps(report["balanced_subset"]))
    print("shortcuts all rows      :", report["univariate_shortcuts"]["all_rows"])
    print("shortcuts balanced only :", report["univariate_shortcuts"]["balanced_subset"])
    for row in shares:
        print(row)
    print(f"\nWrote {OUT_CSV}\nWrote {OUT_REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

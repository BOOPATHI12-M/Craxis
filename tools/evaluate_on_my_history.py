"""Measure how often each model flags pages YOU actually browse.

PRIVACY
-------
* You run this script on your own computer. Nothing is uploaded.
* It reads a TEMPORARY COPY of your browser's History file and deletes it.
* It prints ONLY aggregate numbers. No URL, title or domain is printed or saved,
  unless you pass --show-domains, which prints registrable domains only.
* Do not paste URLs anywhere. Only the printed numbers are needed.

What it measures
----------------
Pages you visited are assumed to be mostly benign. The share a model flags as
phishing is therefore an estimate of its false-positive rate on YOUR browsing.
Some visited pages may not be benign, so treat the numbers as an upper bound on
the false-positive rate, not an exact figure.

Usage (close Chrome or Edge first so the History file is not locked):
    python tools/evaluate_on_my_history.py
    python tools/evaluate_on_my_history.py --browser edge
    python tools/evaluate_on_my_history.py --history "C:/path/to/History"
"""
import argparse
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import warnings
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ml"))
warnings.filterwarnings("ignore")

MODELS = {
    "v3 (active)": "phishing_model.pkl",
}

BROWSER_DIRS = {
    "chrome": Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data",
    "edge": Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data",
}


def find_history(browser: str, profile: str) -> Path:
    base = BROWSER_DIRS[browser]
    path = base / profile / "History"
    if not path.exists():
        raise FileNotFoundError(f"No History file at {path}. Use --history to give the path.")
    return path


def read_urls(history_path: Path):
    """Copy the History database to a temp file, read URLs, delete the copy."""
    tmpdir = Path(tempfile.mkdtemp(prefix="history_eval_"))
    copy = tmpdir / "History.sqlite"
    try:
        try:
            shutil.copy2(history_path, copy)
        except PermissionError:
            raise SystemExit(
                "The History file is locked. Close Chrome/Edge completely (check the system tray) and run again."
            )
        con = sqlite3.connect(f"file:{copy.as_posix()}?mode=ro", uri=True)
        try:
            rows = con.execute("SELECT url, visit_count FROM urls WHERE hidden = 0").fetchall()
        finally:
            con.close()
        return rows
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--browser", choices=sorted(BROWSER_DIRS), default="chrome")
    ap.add_argument("--profile", default="Default")
    ap.add_argument("--history", help="Explicit path to a History file.")
    ap.add_argument("--cap", type=int, default=20, help="Max URLs per site (default 20).")
    ap.add_argument("--show-domains", action="store_true",
                    help="Also print the 10 registrable domains with most flagged pages.")
    args = ap.parse_args()

    import joblib
    import numpy as np
    from dataset_utils import group_key
    from feature_extractor import FEATURE_NAMES, extract_features, is_builtin_trusted, on_shared_hosting

    path = Path(args.history) if args.history else find_history(args.browser, args.profile)
    rows = read_urls(path)
    print(f"History entries read: {len(rows)}")

    seen, urls = set(), []
    skipped = {"not_http": 0, "local": 0, "duplicate": 0}
    for url, _ in rows:
        if not re.match(r"^https?://", url, re.I):
            skipped["not_http"] += 1
            continue
        try:
            p = urlparse(url)
            host = (p.hostname or "").lower()
        except ValueError:
            skipped["not_http"] += 1
            continue
        if not host or host == "localhost" or re.match(r"^(127\.|10\.|192\.168\.|169\.254\.)", host) \
                or host.endswith(".local") or host.endswith(".localhost"):
            skipped["local"] += 1
            continue
        clean = f"{p.scheme.lower()}://{p.netloc}{p.path}"      # same stripping used in training
        if clean in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(clean)
        urls.append((url, clean, group_key(clean)))
    print(f"Usable unique URLs: {len(urls)}  (skipped: {skipped})")
    if len(urls) < 200:
        print("Fewer than 200 URLs. The estimate would be unreliable.")
        return 1

    # cap per site so search results or one video site cannot dominate
    per_site, kept = {}, []
    for raw, clean, site in urls:
        per_site[site] = per_site.get(site, 0) + 1
        if per_site[site] <= args.cap:
            kept.append((raw, clean, site))
    print(f"After capping at {args.cap} URLs per site: {len(kept)} URLs on {len(per_site)} sites")

    X = np.array([extract_features(c) for _, c, _ in kept], dtype=float)
    X_raw = np.array([extract_features(r) for r, _, _ in kept], dtype=float)
    paths = [urlparse(c).path.strip("/") for _, c, _ in kept]
    deep = np.array([p.count("/") >= 1 for p in paths])
    has_path = np.array([p != "" for p in paths])
    hosts = [(urlparse(c).hostname or "").lower() for _, c, _ in kept]
    www = np.array([h.startswith("www.") for h in hosts])
    shared = np.array([on_shared_hosting(h) for h in hosts])
    trusted = np.array([is_builtin_trusted(c) for _, c, _ in kept])

    def pct(mask, flag):
        n = int(mask.sum())
        return "n/a" if n == 0 else f"{100 * flag[mask].mean():5.1f}%"

    print("\nShare of YOUR pages flagged as phishing at threshold 0.5 (lower is better).")
    print(f"Group sizes: all={len(kept)} deep-path={int(deep.sum())} root-only={int((~has_path).sum())} "
          f"www={int(www.sum())} no-www={int((~www).sum())} shared-hosting={int(shared.sum())} "
          f"built-in-trusted={int(trusted.sum())}\n")
    header = f"{'model':20s} {'all':>7s} {'no query':>9s} {'deep':>7s} {'root':>7s} {'www':>7s} {'no www':>7s} {'shared':>7s} {'not trusted':>12s}"
    print(header)
    print("-" * len(header))
    flagged_by_model = {}
    for name, fname in MODELS.items():
        mp = ROOT / "ml" / "model" / fname
        if not mp.exists():
            continue
        payload = joblib.load(mp)
        assert list(payload["feature_names"]) == list(FEATURE_NAMES)
        model = payload["model"]
        flag = model.predict_proba(X)[:, 1] >= 0.5
        flag_raw = model.predict_proba(X_raw)[:, 1] >= 0.5
        flagged_by_model[name] = flag
        everything = np.ones(len(kept), dtype=bool)
        print(f"{name:20s} {pct(everything, flag_raw):>7s} {pct(everything, flag):>9s} {pct(deep, flag):>7s} "
              f"{pct(~has_path, flag):>7s} {pct(www, flag):>7s} {pct(~www, flag):>7s} {pct(shared, flag):>7s} "
              f"{pct(~trusted, flag):>12s}")
    print("\nColumns: all = raw URLs as visited; the others use URLs with query and fragment removed.")
    print("'not trusted' excludes domains in the extension's built-in trusted list, which the extension caps anyway.")

    if args.show_domains and "v3 (active)" in flagged_by_model:
        from collections import Counter
        c = Counter(site for (_, _, site), f in zip(kept, flagged_by_model["v3 (active)"]) if f)
        print("\nDomains with most pages flagged by v3 (domains only):")
        for site, n in c.most_common(10):
            print(f"  {n:4d}  {site}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

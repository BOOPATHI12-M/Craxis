"""Fill "trusted_domains" in shared/config.json with the top Tranco domains.

Shared-hosting and user-content domains are excluded, because anyone can host
a page on them and they must never be treated as trusted.

Usage:
    python tools/build_trusted_domains.py [--count 1000]

Needs network access to https://tranco-list.eu
"""
import argparse
import io
import json
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "shared" / "config.json"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1000)
    args = parser.parse_args()

    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    shared = cfg["shared_hosting_suffixes"]

    print(f"Downloading {TRANCO_URL} ...")
    with urllib.request.urlopen(TRANCO_URL, timeout=120) as resp:
        raw = resp.read()
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        lines = zf.read(zf.namelist()[0]).decode("utf-8").splitlines()

    trusted = []
    for line in lines:
        _, _, domain = line.partition(",")
        domain = domain.strip().lower()
        if not domain or "." not in domain:
            continue
        if any(domain == s or domain.endswith("." + s) for s in shared):
            continue
        trusted.append(domain)
        if len(trusted) >= args.count:
            break

    cfg["trusted_domains"] = trusted
    CONFIG.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(trusted)} trusted domains to {CONFIG}")


if __name__ == "__main__":
    main()

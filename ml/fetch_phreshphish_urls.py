"""Download ONLY the url, label and date columns of the PhreshPhish dataset.

PhreshPhish (Dalton et al., 2025, arXiv 2507.10854, CC BY 4.0, for anti-phishing
research only) is 36.6 GB because every row includes the page HTML. Parquet
stores columns separately, so reading three columns with HTTP range requests
transfers about 27 MB in total.

Usage:
    python ml/fetch_phreshphish_urls.py --out ml/source/phreshphish_urls.parquet
    python ml/fetch_phreshphish_urls.py --out x.parquet --limit-files 2   # quick test

Requires: pip install pyarrow
The output holds real browsing URLs. Keep it local and do not commit it.
"""
import argparse
import io
import json
import sys
import time
import urllib.request
from pathlib import Path

REPO = "phreshphish/phreshphish"
API = f"https://huggingface.co/api/datasets/{REPO}/tree/main/data"
BASE = f"https://huggingface.co/datasets/{REPO}/resolve/main/data/"
UA = "phishing-guard-research/1.0"
COLUMNS = ["url", "label", "date"]


class RangeFile(io.RawIOBase):
    """Minimal seekable file over HTTP range requests."""

    def __init__(self, url):
        self.pos = 0
        self.bytes_received = 0
        req = urllib.request.Request(url, headers={"Range": "bytes=0-0", "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as resp:
            self.final_url = resp.geturl()
            self.size = int(resp.headers.get("Content-Range", "").split("/")[-1])
            resp.read()

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        self.pos = offset if whence == 0 else (self.pos + offset if whence == 1 else self.size + offset)
        return self.pos

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        if n == 0 or self.pos >= self.size:
            return b""
        end = min(self.pos + n, self.size) - 1
        req = urllib.request.Request(
            self.final_url, headers={"Range": f"bytes={self.pos}-{end}", "User-Agent": UA}
        )
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    data = resp.read()
                break
            except Exception:
                if attempt == 3:
                    raise
                time.sleep(2 * (attempt + 1))
        self.pos += len(data)
        self.bytes_received += len(data)
        return data

    def readinto(self, b):
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)


def list_files():
    req = urllib.request.Request(API + "?limit=1000", headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
        entries = json.loads(resp.read().decode())
    return sorted(e["path"].split("/")[-1] for e in entries if e["path"].endswith(".parquet"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, help="Output parquet path (keep outside git).")
    parser.add_argument("--limit-files", type=int, default=0, help="Only read the first N files (testing).")
    args = parser.parse_args()

    import pandas as pd
    import pyarrow.parquet as pq

    names = list_files()
    if args.limit_files:
        names = names[: args.limit_files]
    frames, sent = [], 0
    started = time.time()
    for i, name in enumerate(names, 1):
        handle = RangeFile(BASE + name)
        frame = pq.ParquetFile(handle).read(columns=COLUMNS).to_pandas()
        frame["split"] = "train" if name.startswith("train") else "test"
        frame["file"] = name
        frames.append(frame)
        sent += handle.bytes_received
        print(f"[{i:2d}/{len(names)}] {name:20s} rows={len(frame):6d}", flush=True)

    full = pd.concat(frames, ignore_index=True)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    full.to_parquet(out, index=False)
    print(f"Wrote {len(full)} rows to {out}  ({sent / 1e6:.1f} MB transferred, {time.time() - started:.0f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

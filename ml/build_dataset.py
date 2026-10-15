"""Build the training dataset from public feeds.

Sources
-------
* Phishing:   PhishTank "online-valid" feed (verified, currently online phishing URLs).
              http://data.phishtank.com/data/online-valid.csv
* Legitimate: Tranco top-sites ranking (research-oriented top list).
              https://tranco-list.eu/top-1m.csv.zip

Tranco only lists domains, not full URLs. Legitimate URLs are therefore built
from real domains plus synthetic paths:
  * 35% home page, 20% ordinary templates (help, search, blog, /login, ...),
  * 45% a path shape copied from a real phishing URL with every letter and
    digit randomised, so path length, depth and digit counts carry no signal,
  * 15% sit on a shared hosting platform (github.io, netlify.app, ...),
  * 45% of the rest get a subdomain such as www, accounts, login or secure,
  * 20% of shaped paths start with a security word such as "login".
This is a limitation: the legitimate class is synthetic at the path level, so
the model mostly learns host-level and keyword signals.

Usage
-----
    python ml/build_dataset.py                       # download both feeds
    python ml/build_dataset.py --phishtank-file pt.csv --tranco-file top-1m.csv.zip
    python ml/build_dataset.py --per-class 20000

Output: ml/dataset/phishing_urls_full.csv (columns: url,label,source) and
ml/dataset/DATASET-INFO.json with sources, counts and the download date.
The raw feeds are not stored in the repository. Check each feed's terms of
use before redistributing the generated CSV.
"""
import argparse
import csv
import datetime
import html
import io
import json
import random
import string
import sys
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

ML_DIR = Path(__file__).resolve().parent
DATASET_DIR = ML_DIR / "dataset"
OUT_CSV = DATASET_DIR / "phishing_urls_full.csv"
OUT_INFO = DATASET_DIR / "DATASET-INFO.json"

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
USER_AGENT = "phishing-guard-dataset-builder/1.0 (research)"

SLUGS = [
    "getting-started", "pricing", "features", "release-notes", "how-to-reset-settings",
    "annual-report", "careers", "press", "partners", "faq", "shipping-and-returns",
    "terms-of-service", "privacy-policy", "cookie-settings", "download", "status",
]
SEARCH_WORDS = ["weather", "news", "laptop", "recipes", "flights", "python", "football", "music"]

PATH_TEMPLATES = [
    "/", "/about", "/contact", "/products", "/help", "/support", "/careers", "/pricing",
    "/blog/{slug}", "/docs/{slug}", "/en/{slug}", "/support/article/{n}", "/products/item-{n}",
    "/search?q={word}", "/search?q={word}&page={p}", "/news/{y}/{m}/{slug}",
    "/user/{n}", "/category/{slug}?page={p}",
    # Benign pages that contain phishing-style keywords.
    "/login", "/signin", "/account", "/account/settings", "/security", "/verify-email",
    "/password/reset", "/billing", "/payment-methods",
]


def download(url: str, timeout: int = 180) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def read_tranco(path: str = None) -> list:
    raw = Path(path).read_bytes() if path else download(TRANCO_URL)
    if raw[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            raw = zf.read(zf.namelist()[0])
    domains = []
    for line in raw.decode("utf-8").splitlines():
        _, _, domain = line.partition(",")
        domain = domain.strip().lower()
        if domain and "." in domain:
            domains.append(domain)
    return domains


def read_phishtank(path: str = None) -> list:
    raw = Path(path).read_bytes() if path else download(PHISHTANK_URL)
    text = raw.decode("utf-8", errors="replace")
    urls = []
    for row in csv.DictReader(io.StringIO(text)):
        url = html.unescape((row.get("url") or "").strip())
        verified = (row.get("verified") or "yes").strip().lower()
        online = (row.get("online") or "yes").strip().lower()
        if not url or verified != "yes" or online != "yes":
            continue
        if not url.lower().startswith(("http://", "https://")):
            continue
        urls.append(url)
    return urls


# Share of legitimate samples placed on shared hosting platforms. Phishing is
# concentrated there, but so are many ordinary personal sites. 15% is an
# assumption, not a measurement: without it the model would flag every
# github.io or netlify.app page.
SHARED_HOSTING_SHARE = 0.15

HOST_PREFIXES = ["www", "m", "mail", "accounts", "account", "login", "signin", "secure", "support",
                 "help", "docs", "shop", "my", "portal", "id", "auth"]


def split_shape(url: str) -> str:
    """Return the path + query + fragment part of a URL (the part after the host)."""
    parsed = urlparse(url)
    shape = parsed.path or "/"
    if parsed.query:
        shape += "?" + parsed.query
    if parsed.fragment:
        shape += "#" + parsed.fragment
    return shape


def mask_shape(shape: str, rng: random.Random) -> str:
    """Keep length, depth and punctuation of a path but randomise letters and digits.

    This stops path length, depth and digit counts from being a shortcut that
    separates the two classes.
    """
    out = []
    for ch in shape:
        if ch.isdigit():
            out.append(rng.choice(string.digits))
        elif ch.isalpha() and ch.isascii():
            pool = string.ascii_lowercase if ch.islower() else string.ascii_uppercase
            out.append(rng.choice(pool))
        else:
            out.append(ch)
    return "".join(out)


def make_legit_url(domain: str, shapes: list, keywords: list, rng: random.Random,
                   shared_suffixes: list = None) -> str:
    scheme = "http" if rng.random() < 0.05 else "https"
    host = domain
    if shared_suffixes and rng.random() < SHARED_HOSTING_SHARE:
        # A benign personal or small-business site on a hosting platform.
        # The tenant name reuses the label of a real, ordinary domain.
        host = f"{domain.split('.')[0]}.{rng.choice(shared_suffixes)}"
    elif rng.random() < 0.45:
        prefix = "www" if rng.random() < 0.6 else rng.choice(HOST_PREFIXES)
        host = f"{prefix}.{domain}"

    roll = rng.random()
    if roll < 0.35:
        path = "/"
    elif roll < 0.55:
        path = rng.choice(PATH_TEMPLATES).format(
            slug=rng.choice(SLUGS), n=rng.randint(100, 999999), word=rng.choice(SEARCH_WORDS),
            p=rng.randint(1, 20), y=rng.randint(2019, 2026), m=f"{rng.randint(1, 12):02d}",
        )
    else:
        path = mask_shape(rng.choice(shapes), rng)
        # Some benign pages legitimately contain security words in the path.
        if rng.random() < 0.2 and path.count("/") >= 1:
            parts = path.split("/")
            parts[1] = rng.choice(keywords)
            path = "/".join(parts)
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{host}{path}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--per-class", type=int, default=15000, help="Samples per class (default 15000).")
    parser.add_argument("--tranco-depth", type=int, default=100000, help="Use the top N Tranco domains.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--phishtank-file", help="Local PhishTank CSV instead of downloading.")
    parser.add_argument("--tranco-file", help="Local Tranco CSV/ZIP instead of downloading.")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    print("Reading Tranco domains ...")
    domains = read_tranco(args.tranco_file)[: args.tranco_depth]
    print(f"  {len(domains)} domains")

    print("Reading PhishTank URLs ...")
    phish = list(dict.fromkeys(read_phishtank(args.phishtank_file)))
    print(f"  {len(phish)} unique verified online phishing URLs")

    n = min(args.per_class, len(phish), len(domains))
    if n < 100:
        print("Not enough data to build a dataset.", file=sys.stderr)
        return 1

    rng.shuffle(phish)
    phish_sample = phish[:n]

    from feature_extractor import SUSPICIOUS_KEYWORDS

    shapes = [split_shape(u) for u in phish_sample]
    legit_domains = rng.sample(domains, n)
    from feature_extractor import SHARED_HOSTING_SUFFIXES

    legit_sample = list(
        dict.fromkeys(
            make_legit_url(d, shapes, SUSPICIOUS_KEYWORDS, rng, SHARED_HOSTING_SUFFIXES) for d in legit_domains
        )
    )

    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    rows = [(u, 1, "phishtank") for u in phish_sample] + [(u, 0, "tranco+synthetic-paths") for u in legit_sample]
    rng.shuffle(rows)
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "label", "source"])
        writer.writerows(rows)

    info = {
        "generated_on": datetime.date.today().isoformat(),
        "seed": args.seed,
        "phishing": {"source": PHISHTANK_URL, "count": len(phish_sample), "available": len(phish)},
        "legitimate": {
            "source": TRANCO_URL,
            "count": len(legit_sample),
            "tranco_depth": args.tranco_depth,
            "note": "Real domains; path shapes copied from phishing URLs with letters and digits randomised.",
        },
        "unique_phishing_hosts": len({(urlparse(u).hostname or "") for u in phish_sample}),
    }
    OUT_INFO.write_text(json.dumps(info, indent=2), encoding="utf-8")
    print(f"Wrote {len(rows)} rows to {OUT_CSV}")
    print(f"Wrote {OUT_INFO}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

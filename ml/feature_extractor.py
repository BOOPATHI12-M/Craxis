"""URL feature extraction for the Craxis model.

Keywords, shorteners, brands and TLD lists are read from shared/config.json so
the extension (JavaScript) and the model (Python) always use the same lists.
The brand and registrable-domain logic mirrors shared/scoring.js; a parity test
in ml/tests checks that both implementations agree.
"""
import json
import math
import re
from pathlib import Path
from urllib.parse import urlparse

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "shared" / "config.json"

with open(_CONFIG_PATH, "r", encoding="utf-8") as _fh:
    CONFIG = json.load(_fh)

# Feature order is part of the model contract. Changing it requires retraining.
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "dot_count",
    "hyphen_count",
    "subdomain_count",
    "digit_count",
    "special_character_count",
    "query_parameter_count",
    "fragment_count",
    "https",
    "has_ip",
    "has_at_symbol",
    "suspicious_encoding_count",
    "suspicious_keyword_count",
    "hostname_entropy",
    "excessive_subdomain_depth",
    "unusual_port",
    "is_shortened_url",
    "is_punycode",
    # Added in feature set 3.0
    "hostname_hyphen_count",
    "hostname_digit_ratio",
    "path_depth",
    "suspicious_tld",
    "brand_in_domain",
    "brand_lookalike",
    "on_shared_hosting",
    "site_label_length",
    "site_label_digit_ratio",
    "site_label_consonant_run",
    "site_label_vowel_ratio",
    "tld_length",
]

SUSPICIOUS_KEYWORDS = list(CONFIG["keywords"])
SHORTENER_DOMAINS = list(CONFIG["shorteners"])
SUSPICIOUS_TLDS = set(CONFIG["suspicious_tlds"])
MULTI_PART_SUFFIXES = set(CONFIG["multi_part_suffixes"])
BRANDS = list(CONFIG["brands"])
SHARED_HOSTING_SUFFIXES = list(CONFIG["shared_hosting_suffixes"])
TRUSTED_DOMAINS = set(CONFIG["trusted_domains"])

_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def calculate_entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return round(-sum(p * math.log2(p) for p in prob), 4)


def is_ip_host(host: str) -> bool:
    return bool(_IPV4.match(host or ""))


def registrable_domain(host: str) -> str:
    """Return the registrable domain (example.com, example.co.uk) of a host."""
    host = (host or "").strip().lower().strip(".")
    if not host or is_ip_host(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i]
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def _glyph_variants(label: str) -> list:
    base = (
        label.replace("0", "o")
        .replace("3", "e")
        .replace("5", "s")
        .replace("rn", "m")
        .replace("vv", "w")
    )
    return list({base.replace("1", "l"), base.replace("1", "i")})


def _is_brand_own_domain(host: str, reg: str, brand: dict) -> bool:
    for d in brand["domains"]:
        if reg == d or host == d or host.endswith("." + d):
            return True
    return False


def detect_brand_abuse(hostname: str):
    """Return {"brand", "kind"} when a brand name is misused in a hostname, else None.

    kind is "brand-in-domain", "homoglyph" or "typosquat". Mirrors detectBrandAbuse
    in shared/scoring.js.
    """
    host = (hostname or "").strip().lower().strip(".")
    if not host or is_ip_host(host):
        return None
    reg = registrable_domain(host)
    label = reg.split(".")[0]
    tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]

    for brand in BRANDS:
        if _is_brand_own_domain(host, reg, brand):
            continue
        name = brand["name"]
        hit = name in host if brand["match"] == "contains" else name in tokens
        if hit:
            return {"brand": name, "kind": "brand-in-domain"}

    candidates = []
    for cand in [label] + label.split("-"):
        if cand and cand not in candidates:
            candidates.append(cand)

    for brand in BRANDS:
        if _is_brand_own_domain(host, reg, brand):
            continue
        name = brand["name"]
        for cand in candidates:
            if cand == name:
                continue
            if name in _glyph_variants(cand):
                return {"brand": name, "kind": "homoglyph"}
            if len(name) >= 6 and len(cand) >= 5 and edit_distance(cand, name) == 1:
                return {"brand": name, "kind": "typosquat"}
    return None


def is_builtin_trusted(url: str) -> bool:
    """True for HTTPS URLs on a built-in trusted domain. Mirrors trustStatus in scoring.js."""
    try:
        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").lower()
    except ValueError:
        return False
    if parsed.scheme != "https" or "@" in url or not host or is_ip_host(host):
        return False
    for suffix in SHARED_HOSTING_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return False
    return registrable_domain(host) in TRUSTED_DOMAINS


_VOWELS = set("aeiou")


def site_label_and_suffix(host: str):
    """Return (label, suffix) describing who controls the name.

    For shared hosting (name.github.io) the label is the tenant name (name).
    Otherwise it is the second-level label of the registrable domain.
    """
    host = (host or "").lower().strip(".")
    for suffix in SHARED_HOSTING_SUFFIXES:
        if host.endswith("." + suffix):
            tenant = host[: -len(suffix) - 1].split(".")[-1]
            return tenant, suffix
    reg = registrable_domain(host)
    parts = reg.split(".")
    return parts[0], ".".join(parts[1:])


def on_shared_hosting(host: str) -> bool:
    host = (host or "").lower().strip(".")
    return any(host == s or host.endswith("." + s) for s in SHARED_HOSTING_SUFFIXES)


def extract_features(url: str) -> list:
    """Extract the numerical feature vector (order = FEATURE_NAMES) from a URL."""
    if not isinstance(url, str):
        url = str(url) if url is not None else ""

    url_str = url.strip()
    url_lower = url_str.lower()

    port = None
    try:
        parse_target = url_str if "://" in url_str else "http://" + url_str
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        try:
            port = parsed.port
        except ValueError:
            port = None
    except Exception:
        hostname = ""
        path = ""
        query = ""
        fragment = ""

    url_length = len(url_str)
    hostname_length = len(hostname)
    path_length = len(path)
    dot_count = url_str.count(".")
    hyphen_count = url_str.count("-")
    subdomain_count = hostname.count(".")
    digit_count = sum(1 for ch in url_str if ch.isdigit())
    special_chars = set("?=&%@_~#+:")
    special_character_count = sum(1 for ch in url_str if ch in special_chars)
    query_parameter_count = len(query.split("&")) if query else 0
    fragment_count = 1 if fragment else 0
    https = 1 if url_lower.startswith("https://") else 0
    has_ip = 1 if is_ip_host(hostname) else 0
    has_at_symbol = 1 if "@" in url_str else 0
    suspicious_encoding_count = len(re.findall(r"%[0-9a-fA-F]{2}", url_str))
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    hostname_entropy = calculate_entropy(hostname)
    excessive_subdomain_depth = 1 if subdomain_count > 3 else 0
    unusual_port = 1 if (port is not None and port not in (80, 443)) else 0
    is_shortened_url = 1 if any(hostname == s or hostname.endswith("." + s) for s in SHORTENER_DOMAINS) else 0
    is_punycode = 1 if "xn--" in hostname else 0

    hostname_hyphen_count = hostname.replace("xn--", "").count("-")
    hostname_digits = sum(1 for ch in hostname if ch.isdigit())
    hostname_digit_ratio = round(hostname_digits / hostname_length, 4) if hostname_length else 0.0
    path_depth = len([seg for seg in path.split("/") if seg])
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    suspicious_tld = 1 if (tld in SUSPICIOUS_TLDS and not has_ip) else 0

    abuse = None if is_builtin_trusted(url_str) else detect_brand_abuse(hostname)
    brand_in_domain = 1 if abuse and abuse["kind"] == "brand-in-domain" else 0
    brand_lookalike = 1 if abuse and abuse["kind"] in ("homoglyph", "typosquat") else 0

    label, suffix = site_label_and_suffix(hostname)
    letters = [ch for ch in label if ch.isalpha()]
    site_label_length = len(label)
    site_label_digit_ratio = round(sum(ch.isdigit() for ch in label) / len(label), 4) if label else 0.0
    site_label_vowel_ratio = round(sum(ch in _VOWELS for ch in letters) / len(letters), 4) if letters else 0.0
    run = longest = 0
    for ch in label:
        if ch.isalpha() and ch not in _VOWELS:
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    shared = 1 if (hostname and on_shared_hosting(hostname)) else 0
    tld_length = len(suffix.split(".")[-1]) if suffix else 0

    return [
        url_length,
        hostname_length,
        path_length,
        dot_count,
        hyphen_count,
        subdomain_count,
        digit_count,
        special_character_count,
        query_parameter_count,
        fragment_count,
        https,
        has_ip,
        has_at_symbol,
        suspicious_encoding_count,
        suspicious_keyword_count,
        hostname_entropy,
        excessive_subdomain_depth,
        unusual_port,
        is_shortened_url,
        is_punycode,
        hostname_hyphen_count,
        hostname_digit_ratio,
        path_depth,
        suspicious_tld,
        brand_in_domain,
        brand_lookalike,
        shared,
        site_label_length,
        site_label_digit_ratio,
        longest,
        site_label_vowel_ratio,
        tld_length,
    ]


def get_feature_names() -> list:
    """Return the ordered list of feature names."""
    return list(FEATURE_NAMES)

"""Optional domain intelligence: registration age (RDAP) and TLS certificate checks.

Disabled unless the backend is started with AIPHISH_ENABLE_INTEL=1 AND the
request asks for it. Lookups go to a public RDAP service and to the site
itself, so they reveal the hostname outside your machine. Private, loopback and
link-local addresses are never contacted.
"""
import datetime
import ipaddress
import json
import socket
import ssl
import threading
import time
import urllib.request

from feature_extractor import registrable_domain

CACHE_TTL_SECONDS = 6 * 3600
RDAP_URL = "https://rdap.org/domain/{domain}"

_cache = {}
_lock = threading.Lock()


def intel_enabled() -> bool:
    import os

    return os.environ.get("AIPHISH_ENABLE_INTEL", "0") == "1"


def is_public_host(host: str) -> bool:
    """True only when every resolved address is a public, routable address."""
    if not host or host == "localhost":
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


def _cached(key):
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < CACHE_TTL_SECONDS:
            return True, hit[1]
    return False, None


def _store(key, value):
    with _lock:
        _cache[key] = (time.time(), value)
        if len(_cache) > 2000:
            oldest = min(_cache, key=lambda k: _cache[k][0])
            _cache.pop(oldest, None)


def parse_rdap_age_days(document: dict, now: datetime.datetime = None):
    """Registration age in days from an RDAP domain document, or None."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    for event in document.get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            raw = event["eventDate"].replace("Z", "+00:00")
            try:
                registered = datetime.datetime.fromisoformat(raw)
            except ValueError:
                continue
            if registered.tzinfo is None:
                registered = registered.replace(tzinfo=datetime.timezone.utc)
            return max((now - registered).days, 0)
    return None


def domain_age_days(host: str, timeout: float = 4.0):
    domain = registrable_domain(host)
    key = ("rdap", domain)
    found, value = _cached(key)
    if found:
        return value
    age = None
    try:
        req = urllib.request.Request(
            RDAP_URL.format(domain=domain),
            headers={"Accept": "application/rdap+json", "User-Agent": "ai-phishing-guard/1.1"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            age = parse_rdap_age_days(json.loads(resp.read().decode("utf-8")))
    except Exception:
        age = None
    _store(key, age)
    return age


def certificate_info(host: str, port: int = 443, timeout: float = 4.0) -> dict:
    """Validate the TLS certificate. Returns {"valid": bool|None, "age_days": int|None}."""
    key = ("cert", host, port)
    found, value = _cached(key)
    if found:
        return value
    result = {"valid": None, "age_days": None}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        not_before = ssl.cert_time_to_seconds(cert["notBefore"])
        age = int((time.time() - not_before) // 86400)
        result = {"valid": True, "age_days": max(age, 0)}
    except ssl.SSLCertVerificationError:
        result = {"valid": False, "age_days": None}
    except Exception:
        result = {"valid": None, "age_days": None}
    _store(key, result)
    return result


def lookup(host: str, use_tls: bool = True) -> dict:
    """Run the enabled lookups for a host. Returns an empty dict when not allowed."""
    host = (host or "").lower().strip(".")
    if not intel_enabled() or not is_public_host(host):
        return {}
    return {
        "domain_age_days": domain_age_days(host),
        "cert": certificate_info(host) if use_tls else {"valid": None, "age_days": None},
    }

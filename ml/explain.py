"""Per-website explanation of a model score.

For one URL, every feature is replaced in turn by the typical value seen on
legitimate training URLs (the median) and the model is asked again. The drop in
phishing probability is that feature's effect for THIS website.

    effect > 0   the feature pushes the score toward phishing
    effect < 0   the feature pushes the score toward legitimate

This is a one-feature-at-a-time estimate. Features interact inside a forest, so
the effects are an explanation of this score, not an exact decomposition, and
they do not have to add up to the total.
"""
import json
from pathlib import Path

import numpy as np

FEATURE_LABELS = {
    "url_length": "Address length (characters)",
    "hostname_length": "Hostname length (characters)",
    "path_length": "Path length (characters)",
    "dot_count": "Dots in the address",
    "hyphen_count": "Hyphens in the address",
    "subdomain_count": "Subdomain levels",
    "digit_count": "Digits in the address",
    "special_character_count": "Special characters in the address",
    "query_parameter_count": "Query parameters",
    "fragment_count": "Has a # fragment",
    "https": "Uses HTTPS",
    "has_ip": "Hostname is an IP address",
    "has_at_symbol": "Contains an @ symbol",
    "suspicious_encoding_count": "Percent-encoded characters",
    "suspicious_keyword_count": "Sensitive keywords (login, verify, bank...)",
    "hostname_entropy": "Hostname randomness (entropy)",
    "excessive_subdomain_depth": "More than 3 subdomain levels",
    "unusual_port": "Uses an unusual port",
    "is_shortened_url": "Is a link shortener",
    "is_punycode": "Uses punycode (look-alike characters)",
    "hostname_hyphen_count": "Hyphens in the hostname",
    "hostname_digit_ratio": "Share of digits in the hostname",
    "path_depth": "Path depth (folders)",
    "suspicious_tld": "Frequently abused top-level domain",
    "brand_in_domain": "Brand name inside an unrelated domain",
    "brand_lookalike": "Looks like a misspelt brand name",
    "on_shared_hosting": "Hosted on a free or shared platform",
    "site_label_length": "Site name length",
    "site_label_digit_ratio": "Share of digits in the site name",
    "site_label_consonant_run": "Longest run of consonants in the site name",
    "site_label_vowel_ratio": "Share of vowels in the site name",
    "tld_length": "Top-level domain length",
}

BOOLEAN_FEATURES = {
    "fragment_count", "https", "has_ip", "has_at_symbol", "excessive_subdomain_depth", "unusual_port",
    "is_shortened_url", "is_punycode", "suspicious_tld", "brand_in_domain", "brand_lookalike",
    "on_shared_hosting",
}


def load_baselines(path, feature_names):
    """Return the baseline dict, or None when it is missing or does not match the model."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if list(data.get("feature_names", [])) != list(feature_names):
        return None
    return data


def _display(name, value):
    if name in BOOLEAN_FEATURES:
        return "yes" if value >= 0.5 else "no"
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.2f}"


def explain(model, features, baselines, feature_names, top=6, min_points=0.5):
    """Explain one prediction. Returns a dict, or None when no baseline is available."""
    if baselines is None:
        return None
    x = np.asarray(features, dtype=float)
    legit = np.asarray(baselines["legit_median"], dtype=float)
    phish = np.asarray(baselines["phishing_median"], dtype=float)
    n = len(x)

    variants = np.tile(x, (n, 1))
    for i in range(n):
        variants[i, i] = legit[i]
    base = float(model.predict_proba(x.reshape(1, -1))[0][1])
    without = model.predict_proba(variants)[:, 1]
    effects = (base - without) * 100.0

    rows = []
    for i, name in enumerate(feature_names):
        effect = float(effects[i])
        if abs(effect) < min_points:
            continue
        rows.append({
            "name": name,
            "label": FEATURE_LABELS.get(name, name),
            "value": _display(name, x[i]),
            "typical_legitimate": _display(name, legit[i]),
            "typical_phishing": _display(name, phish[i]),
            "effect_points": round(effect, 1),
            "direction": "toward_phishing" if effect > 0 else "toward_legitimate",
        })
    rows.sort(key=lambda r: -abs(r["effect_points"]))
    return {
        "method": "one-feature-at-a-time replacement with the typical legitimate value",
        "baseline_source": baselines.get("source", "training data"),
        "phishing_probability": round(base, 4),
        "features": rows[:top],
    }

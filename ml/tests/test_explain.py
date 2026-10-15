import numpy as np
import pytest

import explain as ex
from feature_extractor import FEATURE_NAMES, extract_features


class FakeModel:
    """Phishing probability rises with the first feature (url_length)."""

    def predict_proba(self, X):
        X = np.asarray(X, dtype=float)
        p = np.clip(X[:, 0] / 100.0, 0, 1)
        return np.column_stack([1 - p, p])


def baselines():
    n = len(FEATURE_NAMES)
    return {"feature_names": list(FEATURE_NAMES), "legit_median": [20.0] + [0.0] * (n - 1),
            "phishing_median": [60.0] + [0.0] * (n - 1), "source": "test"}


def test_explanation_identifies_the_responsible_feature():
    x = [80.0] + [0.0] * (len(FEATURE_NAMES) - 1)
    out = ex.explain(FakeModel(), x, baselines(), FEATURE_NAMES)
    assert out["features"][0]["name"] == "url_length"
    assert out["features"][0]["effect_points"] == pytest.approx(60.0, abs=0.1)
    assert out["features"][0]["direction"] == "toward_phishing"
    assert out["features"][0]["typical_legitimate"] == "20"


def test_unavailable_without_baselines():
    assert ex.explain(FakeModel(), [0.0] * len(FEATURE_NAMES), None, FEATURE_NAMES) is None


def test_baselines_must_match_the_feature_list(tmp_path):
    path = tmp_path / "b.json"
    path.write_text('{"feature_names": ["a"], "legit_median": [0], "phishing_median": [0]}')
    assert ex.load_baselines(path, FEATURE_NAMES) is None
    assert ex.load_baselines(tmp_path / "missing.json", FEATURE_NAMES) is None


def test_every_feature_has_a_label():
    assert all(name in ex.FEATURE_LABELS for name in FEATURE_NAMES)


def test_api_explanation_is_optional_and_specific(monkeypatch):
    import app

    client = app.app.test_client()
    plain = client.post("/predict", json={"url": "https://example.com/"}).get_json()
    assert "explanation" not in plain

    a = client.post("/predict", json={"url": "http://172.16.0.1:8090/x.html", "explain": True}).get_json()
    b = client.post("/predict", json={"url": "https://en.wikipedia.org/wiki/Phishing", "explain": True}).get_json()
    assert a["explanation_available"] is True
    names_a = [f["name"] for f in a["explanation"]["features"]]
    names_b = [f["name"] for f in b["explanation"]["features"]]
    assert names_a != names_b          # different websites give different explanations
    assert any(f["effect_points"] > 0 for f in a["explanation"]["features"])

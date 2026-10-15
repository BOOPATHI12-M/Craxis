import datetime
import json
import sys
from pathlib import Path

import pytest

import domain_intel

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def client():
    import app as app_module

    return app_module.app.test_client()


def test_health(client):
    body = client.get("/health").get_json()
    assert body["status"] == "ok"
    assert body["feature_count"] > 0


def test_predict_returns_probability(client):
    body = client.post("/predict", json={"url": "https://www.example.com/"}).get_json()
    assert body["prediction"] in ("PHISHING", "LEGITIMATE")
    assert 0 <= body["ai_risk_score"] <= 100
    assert abs(body["phishing_probability"] + body["legitimate_probability"] - 1) < 0.01
    assert "intel" not in body


@pytest.mark.parametrize("payload", [{}, {"url": ""}, {"url": 5}, {"url": "x" * 5000}])
def test_predict_rejects_bad_input(client, payload):
    assert client.post("/predict", json=payload).status_code == 400


def test_predict_ranks_obvious_phishing_above_known_site(client):
    safe = client.post("/predict", json={"url": "https://www.wikipedia.org/"}).get_json()
    bad = client.post(
        "/predict", json={"url": "http://secure-update-paypal-login.verify-account.example-host.top/signin?id=88123"}
    ).get_json()
    assert bad["ai_risk_score"] > safe["ai_risk_score"]


def test_model_info_and_evaluation(client):
    info = client.get("/model-info").get_json()
    assert info["feature_count"] == len(info.get("top_features", [])) or info["feature_count"] > 0
    evaluation = client.get("/api/model-evaluation")
    assert evaluation.status_code in (200, 404)


def test_test_pages_block_path_traversal(client):
    assert client.get("/test-pages/..%2f..%2fapp.py").status_code in (403, 404)
    assert client.get("/test-pages/safe-https-test.html").status_code == 200


def test_intel_disabled_by_default(client, monkeypatch):
    monkeypatch.delenv("AIPHISH_ENABLE_INTEL", raising=False)
    body = client.post("/predict", json={"url": "https://example.com/", "intel": True}).get_json()
    assert "intel" not in body


def test_model_and_extractor_feature_lists_agree():
    import app as app_module
    from feature_extractor import FEATURE_NAMES

    assert app_module.model_obj.n_features_in_ == len(FEATURE_NAMES)


def test_parse_rdap_age():
    now = datetime.datetime(2026, 10, 15, tzinfo=datetime.timezone.utc)
    doc = {"events": [{"eventAction": "registration", "eventDate": "2026-10-05T00:00:00Z"}]}
    assert domain_intel.parse_rdap_age_days(doc, now) == 10
    assert domain_intel.parse_rdap_age_days({"events": []}, now) is None


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1", ""])
def test_intel_never_contacts_private_hosts(host):
    assert domain_intel.is_public_host(host) is False


def test_intel_lookup_is_empty_when_disabled(monkeypatch):
    monkeypatch.delenv("AIPHISH_ENABLE_INTEL", raising=False)
    assert domain_intel.lookup("example.com") == {}


def test_config_js_is_in_sync():
    import sync_config

    assert sync_config.DST.read_text(encoding="utf-8") == sync_config.render()


def test_dataset_info_is_valid_json_when_present():
    info = ROOT / "ml" / "dataset" / "DATASET-INFO.json"
    if info.exists():
        data = json.loads(info.read_text(encoding="utf-8"))
        assert data["phishing"]["count"] > 0

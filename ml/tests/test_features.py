import pandas as pd
import pytest

import feature_extractor as fx
from dataset_utils import group_key, group_split


def features(url):
    return dict(zip(fx.FEATURE_NAMES, fx.extract_features(url)))


def test_feature_vector_matches_names():
    vec = fx.extract_features("https://example.com/a?b=1")
    assert len(vec) == len(fx.FEATURE_NAMES) == len(set(fx.FEATURE_NAMES))


def test_basic_url_features():
    f = features("https://sub.example.com:8443/path/page?a=1&b=2#frag")
    assert f["https"] == 1
    assert f["has_ip"] == 0
    assert f["query_parameter_count"] == 2
    assert f["fragment_count"] == 1
    assert f["unusual_port"] == 1
    assert f["path_depth"] == 2
    assert f["subdomain_count"] == 2


def test_ip_at_and_punycode_flags():
    assert features("http://203.0.113.5/login")["has_ip"] == 1
    assert features("https://user@example.com/")["has_at_symbol"] == 1
    assert features("https://xn--pple-43d.com/")["is_punycode"] == 1


def test_keywords_and_shorteners_come_from_shared_config():
    f = features("https://bit.ly/verify-account")
    assert f["is_shortened_url"] == 1
    assert f["suspicious_keyword_count"] == 2


def test_brand_features_skip_trusted_domains():
    assert features("https://www.google.com/")["brand_in_domain"] == 0
    assert features("https://paypal-secure-login.com/")["brand_in_domain"] == 1
    assert features("https://paypa1.com/")["brand_lookalike"] == 1
    assert features("https://googleapis.com/x")["brand_in_domain"] == 0


def test_shared_hosting_uses_tenant_label():
    f = features("https://sp12ct-keldik.pages.dev/")
    assert f["on_shared_hosting"] == 1
    assert f["site_label_length"] == len("sp12ct-keldik")
    assert features("https://example.com/")["on_shared_hosting"] == 0


@pytest.mark.parametrize("bad", ["", "not a url", "http://", "://x", None, 123])
def test_extractor_never_raises(bad):
    assert len(fx.extract_features(bad)) == len(fx.FEATURE_NAMES)


def test_registrable_domain():
    assert fx.registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert fx.registrable_domain("www.example.com") == "example.com"
    assert fx.registrable_domain("127.0.0.1") == "127.0.0.1"


def test_group_key_groups_shared_hosting_by_host():
    assert group_key("https://a.example.com/x") == "example.com"
    assert group_key("https://one.pages.dev/") == "one.pages.dev"
    assert group_key("https://two.pages.dev/") == "two.pages.dev"


def test_group_split_has_no_group_overlap():
    rows = []
    for i in range(300):
        rows.append({"url": f"https://site{i % 60}.com/p{i}", "label": i % 2})
    df = pd.DataFrame(rows)
    df["group"] = df["url"].map(group_key)
    train_idx, test_idx = group_split(df)
    assert set(df.loc[train_idx, "group"]).isdisjoint(set(df.loc[test_idx, "group"]))
    assert len(train_idx) + len(test_idx) == len(df)

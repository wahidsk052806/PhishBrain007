"""Tests for the prefilter feature contract and the train/inference brand parity.

The prefilter is trained from `ml/preprocessing/url_features.py` and the backend
reuses that exact extractor, so a feature added on one side and not the other
would silently feed the model mismatched columns. These tests pin the parts that
can drift: the brand-token list versus the backend's configured BRAND_LIST, and
the shape of the brand-impersonation features themselves.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.preprocessing.url_features import (  # noqa: E402
    BRAND_TOKENS,
    FEATURE_NAMES,
    FREE_HOST_DOMAINS,
    extract_url_features_dict,
)

from app.core.config import get_settings  # noqa: E402
from app.ml.url_features import training_feature_names  # noqa: E402


def test_backend_and_training_agree_on_the_feature_list():
    """The backend must score with the same columns the model was trained on."""
    assert training_feature_names() == FEATURE_NAMES


def test_the_ml_brand_list_covers_every_configured_brand():
    """A brand the backend watches but the feature module ignores is a blind spot."""
    configured = set(get_settings().brands)
    missing = sorted(configured - set(BRAND_TOKENS))
    assert not missing, f"configured brands with no impersonation feature: {missing}"


@pytest.mark.parametrize(
    "url",
    [
        "https://www.paypal.com/signin",
        "https://paypal.com/",
    ],
)
def test_the_real_brand_domain_is_not_flagged_as_impersonation(url):
    f = extract_url_features_dict(url)
    assert f["brand_token_in_url"] == 1
    assert f["brand_impersonation"] == 0
    assert f["brand_leet_impersonation"] == 0


def test_brand_in_a_subdomain_of_someone_elses_domain_is_impersonation():
    f = extract_url_features_dict("https://paypal.secure-login-portal.top/signin")
    assert f["brand_impersonation"] == 1
    assert f["brand_token_in_subdomain"] == 1


def test_leet_substituted_brand_is_caught():
    f = extract_url_features_dict("https://paypa1-security.top/login/verify")
    assert f["brand_leet_impersonation"] == 1
    assert f["brand_token_in_url"] == 1


def test_a_brand_mentioned_only_in_the_path_is_not_host_impersonation():
    """Otherwise every encyclopedia article about a brand becomes a positive."""
    f = extract_url_features_dict("https://en.wikipedia.org/wiki/PayPal")
    assert f["brand_impersonation"] == 0
    assert f["brand_token_in_subdomain"] == 0


def test_free_hosting_domains_are_recognised():
    for url in (
        "https://something.vercel.app/login",
        "https://my-shop.weebly.com/account/update",
        "https://phish.duckdns.org/signin",
    ):
        assert extract_url_features_dict(url)["is_free_host"] == 1, url

    assert extract_url_features_dict("https://www.paypal.com/signin")["is_free_host"] == 0


def test_credential_path_and_depth_features():
    f = extract_url_features_dict("https://host.example/account/login/verify/confirm")
    assert f["credential_path_token_count"] >= 3
    assert f["path_depth"] == 4

    assert extract_url_features_dict("https://host.example/")["path_depth"] == 0


def test_feature_extraction_never_raises_on_junk():
    for value in ("", "not a url", "http://", "https://xn--pypal-4ve.com/", "javascript:alert(1)"):
        extract_url_features_dict(value)


def test_free_host_list_is_lowercase_registrable_domains():
    for domain in FREE_HOST_DOMAINS:
        assert domain == domain.lower()
        assert "/" not in domain


def test_one_off_outlook_context_is_consistently_evidenced():
    f = extract_url_features_dict("http://outlook-account-verify.webmail-login.top/session")
    assert f["brand_impersonation"] == 1
    assert f["credential_path_token_count"] >= 1


# --------------------------------------------------------------------------- #
# Health reporting
# --------------------------------------------------------------------------- #

def test_health_names_the_actual_database_and_cache_backends(client):
    """\"ok\" alone hid whether this was SQLite+memory or Postgres+Valkey."""
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["database_backend"] in {"sqlite", "postgres"}
    assert body["cache_backend"] in {"memory", "redis"}

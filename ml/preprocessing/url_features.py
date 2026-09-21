"""
url_features.py
----------------
URL feature extraction for the PhishBrain prefilter model.

This module intentionally MIRRORS the feature contract expected by the
FastAPI backend's URL analyzer (backend/app/analyzers/url/). Because the
backend and ML pipeline are developed by separate agents in this repo, this
file is self-contained (stdlib + tldextract only) so it can be trained and
evaluated independently, but the feature *names* and *semantics* below are
the ones the backend is expected to expose. If the backend's URL analyzer
output schema changes, update FEATURE_NAMES and extract_url_features() to
match — the model itself (ml/models/prefilter_catboost.py) is agnostic to
the exact feature set as long as train/predict use the same columns.

No network calls are made here: WHOIS/DNS/reputation lookups are the
backend's responsibility at inference time; this module only computes
lexical/structural features derivable from the URL string itself, which is
exactly what a lightweight CatBoost prefilter needs.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, fields
from urllib.parse import urlsplit

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:  # pragma: no cover - optional at import time
    _HAS_TLDEXTRACT = False

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work",
    "party", "gq", "link", "tk", "ml", "ga", "cf", "xyz", "top",
}
_SUSPICIOUS_KEYWORDS = (
    "login", "verify", "secure", "account", "update", "confirm", "bank",
    "signin", "billing", "webscr", "password", "suspend", "urgent",
)
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
}

# Brand tokens used for the impersonation features. Kept in step with the
# backend's BRAND_LIST (backend/tests asserts the two agree); the *features*
# must be computed identically at train and inference time, which is why the
# list lives here rather than being imported from the app.
BRAND_TOKENS: tuple[str, ...] = (
    "paypal", "microsoft", "apple", "google", "amazon", "facebook", "netflix",
    "bankofamerica", "chase", "wellsfargo", "dropbox", "linkedin", "instagram",
    "docusign", "adobe", "outlook", "office365",
)

# Free hosting / site-builder / tunnel domains. Phishing on these is routine and
# purely lexical models miss it: the URL shape (`something.vercel.app/login`)
# looks like an ordinary page, so the host being a shared tenant is the signal.
FREE_HOST_DOMAINS: frozenset[str] = frozenset({
    "000webhostapp.com", "appspot.com", "blogspot.com", "bubbleapps.io", "duckdns.org",
    "firebaseapp.com", "github.io", "gitlab.io", "glitch.me", "herokuapp.com",
    "netlify.app", "ngrok.io", "ngrok-free.app", "onrender.com", "pages.dev",
    "repl.co", "replit.app", "r2.dev", "surge.sh", "trycloudflare.com",
    "vercel.app", "web.app", "webflow.io", "weebly.com", "wixsite.com",
    "wordpress.com", "workers.dev", "zapier.app",
})

_CREDENTIAL_PATH_TOKENS = (
    "login", "signin", "sign-in", "sign_in", "verify", "verification", "account",
    "secure", "security", "update", "confirm", "webscr", "password", "reset",
    "billing", "auth", "session", "unlock", "recover",
)

_LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "2": "z", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
})


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@dataclass
class URLFeatures:
    url_length: int = 0
    hostname_length: int = 0
    path_length: int = 0
    query_length: int = 0
    num_dots: int = 0
    num_hyphens: int = 0
    num_digits: int = 0
    num_subdomains: int = 0
    num_query_params: int = 0
    num_percent_encoded: int = 0
    has_ip_host: int = 0
    has_at_symbol: int = 0
    has_https: int = 0
    has_port: int = 0
    is_shortener: int = 0
    suspicious_tld: int = 0
    suspicious_keyword_count: int = 0
    domain_entropy: float = 0.0
    path_entropy: float = 0.0
    digit_ratio: float = 0.0
    special_char_ratio: float = 0.0
    tld_length: int = 0
    is_punycode: int = 0
    # Brand impersonation. A brand token on a domain that is not that brand's is
    # the single strongest lexical clue available, and none of the pure
    # length/count/entropy features above can express it.
    brand_token_in_url: int = 0
    brand_impersonation: int = 0
    brand_leet_impersonation: int = 0
    brand_token_in_subdomain: int = 0
    brand_hyphenated: int = 0
    # Hosting shape.
    is_free_host: int = 0
    subdomain_count_gt_two: int = 0
    domain_has_digit: int = 0
    # Path shape.
    credential_path_token_count: int = 0
    path_depth: int = 0

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}


FEATURE_NAMES: list[str] = [f.name for f in fields(URLFeatures)]


def _split_host(hostname: str) -> tuple[str, str, str]:
    """Return (subdomain, domain, suffix). Falls back to naive split if
    tldextract is unavailable (keeps this module import-safe without deps)."""
    if _HAS_TLDEXTRACT:
        ext = tldextract.extract(hostname)
        return ext.subdomain, ext.domain, ext.suffix
    parts = hostname.split(".")
    if len(parts) <= 2:
        return "", parts[0] if parts else "", parts[-1] if len(parts) > 1 else ""
    return ".".join(parts[:-2]), parts[-2], parts[-1]


def partition_host(hostname: str) -> tuple[str, str, str]:
    """Public wrapper around the subdomain/domain/suffix split.

    Exposed so dataset-building scripts can measure host *structure* (does this
    URL sit on a subdomain?) rather than re-implementing public-suffix logic
    and getting `.co.uk`-style hosts wrong.
    """
    return _split_host(hostname or "")


def extract_url_features(url: str) -> URLFeatures:
    """Compute lexical/structural features for a single URL string."""
    url = (url or "").strip()
    feats = URLFeatures()
    if not url:
        return feats

    parsed = urlsplit(url if "://" in url else f"http://{url}")
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    feats.url_length = len(url)
    feats.hostname_length = len(hostname)
    feats.path_length = len(path)
    feats.query_length = len(query)
    feats.num_dots = url.count(".")
    feats.num_hyphens = url.count("-")
    feats.num_digits = sum(c.isdigit() for c in url)
    feats.num_percent_encoded = url.count("%")
    feats.has_ip_host = int(bool(_IP_RE.match(hostname)))
    feats.has_at_symbol = int("@" in url)
    feats.has_https = int(parsed.scheme == "https")
    feats.has_port = int(parsed.port is not None)
    feats.is_shortener = int(hostname.lower() in _SHORTENERS)
    feats.num_query_params = len([p for p in query.split("&") if p])

    subdomain, domain, suffix = _split_host(hostname)
    feats.num_subdomains = len([p for p in subdomain.split(".") if p])
    feats.suspicious_tld = int(suffix.lower() in _SUSPICIOUS_TLDS)
    feats.tld_length = len(suffix)
    feats.is_punycode = int("xn--" in hostname.lower())

    lowered = url.lower()
    feats.suspicious_keyword_count = sum(kw in lowered for kw in _SUSPICIOUS_KEYWORDS)

    host_lower = hostname.lower()
    registered = f"{domain}.{suffix}".lower() if suffix else host_lower
    path_lower = path.lower()
    deleet = host_lower.translate(_LEET_MAP)

    host_tokens = [t for t in BRAND_TOKENS if t in host_lower]
    path_tokens = [t for t in BRAND_TOKENS if t in path_lower]
    # Only count brand tokens that the *leet-normalized* host reveals and the raw
    # host hides (paypa1, g00gle). Normalizing everything would match nearly any
    # URL, so the comparison is deliberately narrow.
    leet_tokens = [t for t in BRAND_TOKENS if t in deleet and t not in host_lower]

    feats.brand_token_in_url = int(bool(host_tokens or path_tokens or leet_tokens))
    feats.brand_leet_impersonation = int(bool(leet_tokens))
    feats.brand_impersonation = int(
        bool(host_tokens and not any(t in registered for t in host_tokens))
    )
    feats.brand_token_in_subdomain = int(
        bool(host_tokens and subdomain and any(t in subdomain.lower() for t in host_tokens))
    )
    feats.brand_hyphenated = int(
        any(f"{t}-" in host_lower or f"-{t}" in host_lower for t in host_tokens)
    )

    feats.is_free_host = int(registered in FREE_HOST_DOMAINS)
    feats.subdomain_count_gt_two = int(feats.num_subdomains > 2)
    feats.domain_has_digit = int(any(c.isdigit() for c in domain))

    feats.credential_path_token_count = sum(1 for t in _CREDENTIAL_PATH_TOKENS if t in path_lower)
    feats.path_depth = len([seg for seg in path_lower.split("/") if seg])

    feats.domain_entropy = shannon_entropy(domain)
    feats.path_entropy = shannon_entropy(path)
    feats.digit_ratio = feats.num_digits / feats.url_length if feats.url_length else 0.0
    special_chars = sum(not c.isalnum() for c in url)
    feats.special_char_ratio = special_chars / feats.url_length if feats.url_length else 0.0

    return feats


def extract_url_features_dict(url: str) -> dict:
    return extract_url_features(url).to_dict()


def extract_batch(urls: list[str]) -> list[dict]:
    return [extract_url_features_dict(u) for u in urls]

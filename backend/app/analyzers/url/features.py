"""Deterministic URL feature extraction and risk scoring."""
from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

import tldextract

from app.analyzers.url.typosquatting import detect_typosquatting
from app.core.config import get_settings
from app.schemas.analysis import LayerEvidence

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "work", "gq", "cf", "tk", "ml",
    "ga", "loan", "men", "review", "country", "kim", "science", "party",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st",
}

SUSPICIOUS_TOKENS = [
    "login", "verify", "secure", "account", "update", "confirm", "signin",
    "banking", "webscr", "suspend", "billing", "invoice", "reset", "unlock",
    "authenticate", "wallet",
]

REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "next", "dest", "destination", "continue", "return"}

# Latin look-alike (confusable) characters commonly used in homograph attacks.
CONFUSABLE_MAP = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u04bb": "h", "\u0501": "d",
    "\u0455": "s",
}


def _count_scripts(hostname: str) -> set[str]:
    scripts: set[str] = set()
    for ch in hostname:
        cp = ord(ch)
        if cp < 128:
            scripts.add("latin")
        elif 0x0400 <= cp <= 0x04FF:
            scripts.add("cyrillic")
        elif 0x0370 <= cp <= 0x03FF:
            scripts.add("greek")
        elif 0x4E00 <= cp <= 0x9FFF:
            scripts.add("han")
        else:
            scripts.add("other")
    return scripts


def _has_confusable_mix(hostname: str) -> bool:
    """True if the hostname mixes scripts in a way that suggests a
    homograph/IDN attack (e.g. Latin letters mixed with Cyrillic look-alikes)."""
    decoded = hostname
    scripts = _count_scripts(decoded)
    if len(scripts) <= 1:
        return False
    if "latin" in scripts and any(s in scripts for s in ("cyrillic", "greek")):
        return True
    return False


def extract_url_features(url: str) -> dict:
    settings = get_settings()
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    ext = tldextract.extract(url)
    registered_domain = ext.registered_domain or hostname
    subdomain = ext.subdomain or ""
    tld = ext.suffix.split(".")[-1] if ext.suffix else ""

    path = parsed.path or ""
    query = parsed.query or ""
    decoded_path = unquote(path)

    is_ip_host = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)) or (":" in hostname and hostname.count(":") >= 2)
    is_punycode = "xn--" in hostname.lower()

    features = {
        "url_length": len(url),
        "hostname": hostname,
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "subdomain_count": len([p for p in subdomain.split(".") if p]) if subdomain else 0,
        "dot_count": hostname.count("."),
        "hyphen_count": hostname.count("-"),
        "special_char_count": len(re.findall(r"[^a-zA-Z0-9.\-:/?=&%]", url)),
        "is_ip_host": is_ip_host,
        "is_https": parsed.scheme.lower() == "https",
        "has_percent_encoding": "%" in url,
        "has_hex_encoding": bool(re.search(r"%[0-9a-fA-F]{2}", url)),
        "suspicious_token_hits": [t for t in SUSPICIOUS_TOKENS if t in decoded_path.lower() or t in query.lower()],
        "brand_token_hits": [b for b in settings.brands if b in hostname.lower() and b != registered_domain.split(".")[0].lower()],
        "tld": tld,
        "suspicious_tld": tld.lower() in SUSPICIOUS_TLDS,
        "is_shortener": registered_domain.lower() in URL_SHORTENERS,
        "excessive_subdomains": (len([p for p in subdomain.split(".") if p]) if subdomain else 0) >= 3,
        "suspicious_path_pattern": bool(re.search(r"(login|secure|account).*\.(php|html)?$", decoded_path.lower())),
        "redirect_param_present": any(p in REDIRECT_PARAMS for p in re.findall(r"([a-zA-Z_]+)=", query)),
        "is_punycode": is_punycode,
        "homograph_suspected": _has_confusable_mix(hostname),
        "registered_domain": registered_domain,
    }
    return features


def score_url_features(features: dict, brands: list[str] | None = None) -> LayerEvidence:
    settings = get_settings()
    brands = brands if brands is not None else settings.brands
    indicators: list[str] = []
    score = 0.0

    if features["is_ip_host"]:
        score += 20
        indicators.append("Hostname is a raw IP address")
    if not features["is_https"]:
        score += 8
        indicators.append("URL does not use HTTPS")
    if features["has_hex_encoding"]:
        score += 6
        indicators.append("URL contains percent/hex encoded characters")
    if features["suspicious_token_hits"]:
        score += min(15, 5 * len(features["suspicious_token_hits"]))
        indicators.append(f"Suspicious keywords in path/query: {', '.join(features['suspicious_token_hits'][:5])}")
    if features["brand_token_hits"]:
        score += 15
        indicators.append(f"Brand name(s) present outside registered domain: {', '.join(features['brand_token_hits'])}")
    if features["suspicious_tld"]:
        score += 10
        indicators.append(f"Suspicious top-level domain: .{features['tld']}")
    if features["is_shortener"]:
        score += 10
        indicators.append("URL uses a known link-shortening service")
    if features["excessive_subdomains"]:
        score += 8
        indicators.append("Excessive number of subdomains")
    if features["suspicious_path_pattern"]:
        score += 8
        indicators.append("Path resembles a fake login/verification page")
    if features["redirect_param_present"]:
        score += 8
        indicators.append("URL contains an open-redirect style parameter")
    if features["is_punycode"]:
        score += 12
        indicators.append("Hostname uses punycode (xn--) encoding")
    if features["homograph_suspected"]:
        score += 20
        indicators.append("Hostname mixes character scripts, suggesting a homograph/IDN attack")
    if features["hyphen_count"] >= 3:
        score += 6
        indicators.append("Hostname contains many hyphens")
    if features["url_length"] > 100:
        score += 5
        indicators.append("Unusually long URL")

    typo = detect_typosquatting(features["hostname"], brands)
    if typo:
        if typo.kind == "lookalike":
            score += 80
            indicators.append(
                f"Hostname contains '{typo.brand}' with character substitution"
                + (f" ({', '.join(typo.chars)})" if typo.chars else "")
                + " — classic typosquatting pattern"
            )
        else:
            score += 45 if (typo.distance == 1 or typo.kind == "swap") else 30
            indicators.append(
                f"Possible typosquat of '{typo.brand}' (edit distance {typo.distance})"
            )
        features["typosquat"] = {
            "brand": typo.brand,
            "distance": typo.distance,
            "similarity": typo.similarity,
            "kind": typo.kind,
            "chars": typo.chars,
        }
    else:
        features["typosquat"] = None

    score = max(0.0, min(100.0, score))
    return LayerEvidence(
        layer="url",
        risk_score=score,
        indicators=indicators,
        details=features,
        unavailable=False,
    )


def analyze_url(url: str, brands: list[str] | None = None) -> LayerEvidence:
    features = extract_url_features(url)
    return score_url_features(features, brands=brands)

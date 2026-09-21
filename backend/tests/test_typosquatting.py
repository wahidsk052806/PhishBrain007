from app.analyzers.url.typosquatting import detect_typosquatting


def test_detects_typosquat():
    match = detect_typosquatting("paypa1.com", ["paypal"])
    assert match is not None
    assert match.brand == "paypal"


def test_exact_brand_not_flagged():
    match = detect_typosquatting("paypal.com", ["paypal"])
    assert match is None


def test_subdomain_not_flagged():
    match = detect_typosquatting("login.paypal.com", ["paypal"])
    assert match is None


def test_detects_homoglyph_lookalike():
    match = detect_typosquatting("g00gle.com", ["google"])
    assert match is not None
    assert match.brand == "google"
    assert match.kind == "lookalike"
    assert match.chars == ["o→0", "o→0"]


def test_detects_lookalike_embedded_in_label():
    match = detect_typosquatting("paypa1-security.top", ["paypal"])
    assert match is not None
    assert match.brand == "paypal"
    assert match.kind == "lookalike"


def test_one_for_i_lookalike():
    match = detect_typosquatting("netfl1x.com", ["netflix"])
    assert match is not None
    assert match.brand == "netflix"
    assert match.kind == "lookalike"


def test_adjacent_swap_promoted_to_swap_kind():
    match = detect_typosquatting("googel.com", ["google"])
    assert match is not None
    assert match.brand == "google"
    assert match.kind == "swap"


def test_short_homoglyph_fragment_not_a_lookalike():
    # "5bi" inside "5billion" must not match brand "sbi" (len < 5 substring rule).
    assert detect_typosquatting("5billion.com", ["sbi"]) is None


def test_exact_brand_in_subdomain_not_flagged():
    assert detect_typosquatting("www.google.com", ["google"]) is None

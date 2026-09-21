from app.analyzers.url.features import analyze_url, extract_url_features


def test_extract_features_basic():
    f = extract_url_features("https://www.google.com/search?q=x")
    assert f["is_https"] is True
    assert f["is_ip_host"] is False


def test_suspicious_ip_and_token():
    ev = analyze_url("http://192.168.1.5/login/verify.php?redirect=http://evil.com")
    assert ev.risk_score > 0
    assert any("IP" in i for i in ev.indicators)


def test_punycode_flag():
    f = extract_url_features("http://xn--pypal-4ve.com/login")
    assert f["is_punycode"] is True

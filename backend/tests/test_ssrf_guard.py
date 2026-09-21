import ipaddress

import pytest

from app.core.security import SSRFBlockedError, _embedded_ipv4, _is_private_ip, guard_url, validate_scheme


def test_blocks_localhost():
    with pytest.raises(SSRFBlockedError):
        guard_url("http://localhost/admin")


def test_blocks_loopback_ip():
    with pytest.raises(SSRFBlockedError):
        guard_url("http://127.0.0.1/secret")


def test_blocks_private_ip():
    with pytest.raises(SSRFBlockedError):
        guard_url("http://192.168.1.1/")


def test_blocks_link_local_metadata():
    with pytest.raises(SSRFBlockedError):
        guard_url("http://169.254.169.254/latest/meta-data/")


def test_blocks_bad_scheme():
    with pytest.raises(SSRFBlockedError):
        validate_scheme("file:///etc/passwd")


def test_allows_public_host():
    result = guard_url("https://example.com/")
    assert result.hostname == "example.com"


# --- IPv4-in-IPv6 transition formats ---------------------------------------
# Regression: on a NAT64/DNS64 network the resolver answers with addresses
# inside 64:ff9b::/96, which `ipaddress` marks reserved. Judging the wrapper
# instead of the embedded address rejected every ordinary public site.


def test_allows_nat64_encoded_public_address():
    # 64:ff9b::9765:9d15 == 151.101.157.21 (public)
    assert _is_private_ip("64:ff9b::9765:9d15") is False


def test_blocks_nat64_encoded_private_address():
    # 64:ff9b::c0a8:101 == 192.168.1.1 (private)
    assert _is_private_ip("64:ff9b::c0a8:101") is True


def test_blocks_nat64_encoded_loopback():
    # 64:ff9b::7f00:1 == 127.0.0.1
    assert _is_private_ip("64:ff9b::7f00:1") is True


def test_allows_nat64_local_use_public_address():
    # 64:ff9b:1::9765:9d15 == 151.101.157.21
    assert _is_private_ip("64:ff9b:1::9765:9d15") is False


def test_blocks_malformed_nat64_local_use():
    # Non-zero reserved bits: an unknown form must not be trusted.
    assert _is_private_ip("64:ff9b:1:1::9765:9d15") is True


def test_allows_six_to_four_public_address():
    # 2002:9765:9d15::/48 is 151.101.157.21
    assert _is_private_ip("2002:9765:9d15::1") is False


def test_blocks_six_to_four_private_address():
    assert _is_private_ip("2002:c0a8:101::1") is True


def test_blocks_ipv4_mapped_loopback():
    assert _is_private_ip("::ffff:127.0.0.1") is True


def test_allows_ipv4_mapped_public():
    assert _is_private_ip("::ffff:151.101.157.21") is False


def test_still_blocks_real_private_ipv6():
    assert _is_private_ip("fd00::1") is True
    assert _is_private_ip("fe80::1") is True
    assert _is_private_ip("2001:db8::1") is True


def test_still_allows_global_ipv6():
    assert _is_private_ip("2606:4700:4700::1111") is False


def test_embedded_ipv4_unwraps_only_transition_forms():
    assert _embedded_ipv4(ipaddress.ip_address("64:ff9b::9765:9d15")) == ipaddress.ip_address(
        "151.101.157.21"
    )
    assert _embedded_ipv4(ipaddress.ip_address("2002:9765:9d15::1")) == ipaddress.ip_address(
        "151.101.157.21"
    )
    assert _embedded_ipv4(ipaddress.ip_address("2606:4700::1111")) is None


def test_nat64_ip_literal_is_guarded_on_embedded_address():
    with pytest.raises(SSRFBlockedError):
        guard_url("http://[64:ff9b::c0a8:101]/admin")
    allowed = guard_url("http://[64:ff9b::9765:9d15]/")
    assert allowed.hostname == "64:ff9b::9765:9d15"

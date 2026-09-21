"""Tests for the email layer.

The email path is reachable from both the dashboard and the browser extension
(which parses Gmail/Outlook in the content script), but it had no backend test
coverage at all — nothing pinned the spoofing, language or auth-header rules.
These cover each scoring rule, the caps that stop keyword stuffing from
saturating the score, and the score clamp.
"""
from __future__ import annotations

from app.analyzers.email.analyzer import WEIGHTS, analyze_email, _extract_domain, _parse_auth_header


def _clean() -> dict:
    """A boring, legitimate transactional email: must score nothing."""
    return {
        "sender": "receipts@shop.example.com",
        "reply_to": None,
        "display_name": "Example Shop",
        "subject": "Your order has shipped",
        "body": "Thanks for your order. Track it from your account page.",
        "links": [],
        "raw_headers": None,
        "has_attachments": False,
    }


def test_a_clean_email_scores_zero_and_raises_no_indicators():
    evidence = analyze_email(**_clean())

    assert evidence.layer == "email"
    assert evidence.risk_score == 0.0
    assert evidence.indicators == []
    assert evidence.unavailable is False


# --------------------------------------------------------------------------- #
# Header-level spoofing
# --------------------------------------------------------------------------- #

def test_reply_to_on_a_different_domain_is_flagged():
    payload = _clean()
    payload["reply_to"] = "collect@totally-different-domain.tld"

    evidence = analyze_email(**payload)

    assert evidence.risk_score >= 18
    assert any("Reply-To domain" in i for i in evidence.indicators)
    assert evidence.details["reply_to_domain"] == "totally-different-domain.tld"


def test_reply_to_on_the_same_domain_is_not_flagged():
    payload = _clean()
    payload["reply_to"] = "support@shop.example.com"

    evidence = analyze_email(**payload)

    assert evidence.risk_score == 0.0


def test_display_name_impersonating_a_brand_from_another_domain_is_flagged():
    payload = _clean()
    payload["display_name"] = "PayPal Service"
    payload["sender"] = "service@secure-mailer.net"

    evidence = analyze_email(**payload)

    assert evidence.risk_score >= 20
    assert any("Display name references 'paypal'" in i for i in evidence.indicators)


def test_display_name_matching_its_own_brand_domain_is_not_flagged():
    payload = _clean()
    payload["display_name"] = "PayPal"
    payload["sender"] = "service@paypal.com"

    evidence = analyze_email(**payload)

    assert evidence.risk_score == 0.0


# --------------------------------------------------------------------------- #
# Language categories
# --------------------------------------------------------------------------- #

def test_each_language_category_contributes_its_weight():
    cases = {
        "urgency": ("Act now, this will expire", ""),
        "threat": ("", "Your account will be suspended"),
        "credential": ("", "Please verify your account"),
        "financial": ("", "Send a wire transfer today"),
        "prize": ("", "You have won a free gift"),
    }
    for category, (subject, body) in cases.items():
        payload = _clean()
        payload["subject"] = subject
        payload["body"] = body
        evidence = analyze_email(**payload)

        assert evidence.risk_score >= WEIGHTS[category], category
        assert any(category in i.lower() for i in evidence.indicators), category


def test_keyword_stuffing_is_capped_instead_of_saturating_the_score():
    payload = _clean()
    payload["subject"] = " ".join(
        ["urgent immediately act now expire within 24 hours final notice asap"] * 5
    )
    payload["body"] = "urgent immediately act now expire within 24 hours final notice asap"

    evidence = analyze_email(**payload)

    # The cap is weight * 3, not one hit per occurrence.
    assert evidence.risk_score == WEIGHTS["urgency"] * 3
    assert evidence.risk_score < 100


def test_score_is_clamped_to_one_hundred():
    evidence = analyze_email(
        sender="attacker@evil.tld",
        reply_to="collector@other.tld",
        display_name="PayPal Apple Microsoft",
        subject="URGENT final notice: your account will be suspended",
        body=(
            "Act now to verify your account and confirm your password. Send a wire transfer, "
            "claim your prize, you have won a lottery. Legal action and penalty apply, "
            "unauthorized access detected, account locked."
        ),
        links=["https://paypal.com|https://evil.tld/collect"],
        raw_headers="Authentication-Results: spf=fail dkim=fail dmarc=fail",
        has_attachments=True,
    )

    assert evidence.risk_score == 100.0


# --------------------------------------------------------------------------- #
# Links
# --------------------------------------------------------------------------- #

def test_link_text_domain_mismatched_with_href_is_flagged():
    payload = _clean()
    payload["links"] = ["https://www.paypal.com/login|https://evil-collector.top/login"]

    evidence = analyze_email(**payload)

    assert evidence.details["mismatched_links"] == 1
    assert evidence.risk_score >= 20
    assert any("mismatched with actual href" in i for i in evidence.indicators)


def test_link_mismatch_is_detected_on_tlds_tldextract_cannot_resolve():
    """A cheap or newly delegated TLD must not switch the check off.

    `tldextract` reports no registrable domain for a suffix outside the
    public-suffix list; that used to make the comparison a silent no-op.
    """
    payload = _clean()
    payload["links"] = ["https://www.paypal.com/login|https://collect.paypal-login.zzz/login"]

    evidence = analyze_email(**payload)

    assert evidence.details["mismatched_links"] == 1


def test_plain_hrefs_without_text_are_skipped_not_miscounted():
    payload = _clean()
    payload["links"] = ["https://evil.tld/a", "https://evil.tld/b"]

    evidence = analyze_email(**payload)

    assert evidence.details["mismatched_links"] == 0


def test_brand_mentioned_in_body_from_another_domain_is_flagged():
    payload = _clean()
    payload["body"] = "Your PayPal account needs attention."

    evidence = analyze_email(**payload)

    assert evidence.details["brand_domain_mismatch"] is True
    assert any("brand not matching the sending domain" in i for i in evidence.indicators)


# --------------------------------------------------------------------------- #
# Attachments and authentication headers
# --------------------------------------------------------------------------- #

def test_attachment_alone_is_not_treated_as_suspicious():
    payload = _clean()
    payload["has_attachments"] = True

    assert analyze_email(**payload).risk_score == 0.0


def test_attachment_combined_with_pressure_language_is_flagged():
    payload = _clean()
    payload["has_attachments"] = True
    payload["body"] = "Please verify your account using the attached form."

    evidence = analyze_email(**payload)

    assert any("Attachment present" in i for i in evidence.indicators)


def test_failed_authentication_headers_are_flagged_per_mechanism():
    payload = _clean()
    payload["raw_headers"] = "Authentication-Results: spf=fail dkim=pass dmarc=fail"

    evidence = analyze_email(**payload)

    assert evidence.details["spf"] == "fail"
    assert evidence.details["dkim"] == "pass"
    assert evidence.details["dmarc"] == "fail"
    assert evidence.risk_score == 30
    assert sum("authentication failed" in i for i in evidence.indicators) == 2


def test_missing_headers_are_reported_as_unavailable_not_as_a_failure():
    evidence = analyze_email(**_clean())

    assert evidence.details["spf"] == "Not available from browser context"
    assert evidence.details["dkim"] == "Not available from browser context"
    assert evidence.details["dmarc"] == "Not available from browser context"


def test_auth_header_parser_reads_case_insensitively():
    assert _parse_auth_header("SPF=FAIL", "spf") == "fail"
    assert _parse_auth_header("some text dkim=pass more", "dkim") == "pass"
    assert _parse_auth_header("no mechanisms here", "dmarc") == "not_found"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def test_extract_domain_uses_the_registrable_domain():
    assert _extract_domain("Support <user@mail.brand.co.uk>") == "brand.co.uk"
    assert _extract_domain("user@example.com") == "example.com"
    assert _extract_domain("") == ""


def test_details_record_the_raw_hits_for_auditing():
    payload = _clean()
    payload["body"] = "Urgent: verify your account."

    details = analyze_email(**payload).details

    assert details["urgency_hits"]
    assert details["credential_hits"]
    # The registrable domain, not the full host.
    assert details["sender_domain"] == "example.com"

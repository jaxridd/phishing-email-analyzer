"""Tests for header-based phishing checks."""

from pathlib import Path

from analyzer.header_checks import (
    check_authentication,
    check_display_name,
    check_return_path,
    run_header_checks,
)
from analyzer.models import ParsedEmail
from analyzer.parser import parse_email

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def load(name):
    return parse_email((SAMPLES / name).read_text(encoding="utf-8"))


def test_phishing_sample_triggers_expected_rules():
    ids = rule_ids(run_header_checks(load("phishing_contoso_login.eml")))
    assert {
        "HDR-SPF-FAIL",
        "HDR-DKIM-MISSING",
        "HDR-DMARC-FAIL",
        "HDR-REPLYTO-MISMATCH",
        "HDR-RETURNPATH-MISMATCH",
    } <= ids


def test_legitimate_sample_has_no_header_findings():
    assert run_header_checks(load("legitimate_contoso_newsletter.eml")) == []


def test_missing_auth_results_gives_single_finding():
    assert rule_ids(check_authentication("")) == {"HDR-AUTH-MISSING"}


def test_spf_softfail_is_low_severity():
    findings = check_authentication("spf=softfail dkim=pass dmarc=pass")
    assert len(findings) == 1
    assert findings[0].rule_id == "HDR-SPF-SOFTFAIL"
    assert findings[0].severity == "low"


def test_subdomain_return_path_is_not_a_mismatch():
    email = ParsedEmail(from_address="news@contoso.example", return_path="bounce@mail.contoso.example")
    assert check_return_path(email) == []


def test_brand_impersonation_in_display_name():
    email = ParsedEmail(display_name="PayPal Support", from_address="help@random-site.example")
    assert rule_ids(check_display_name(email)) == {"HDR-DISPLAYNAME-BRAND"}


def test_real_brand_domain_is_not_flagged():
    email = ParsedEmail(display_name="PayPal", from_address="service@paypal.com")
    assert check_display_name(email) == []


def test_email_address_in_display_name():
    email = ParsedEmail(display_name="support@bank.example", from_address="x@attacker.example")
    assert "HDR-DISPLAYNAME-EMAIL" in rule_ids(check_display_name(email))

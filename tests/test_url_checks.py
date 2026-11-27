"""Tests for link-based phishing checks."""

from pathlib import Path

from analyzer.models import Link, ParsedEmail
from analyzer.parser import parse_email
from analyzer.url_checks import run_url_checks

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def check(url, text=""):
    return rule_ids(run_url_checks(ParsedEmail(links=[Link(url=url, display_text=text)])))


def test_phishing_sample_triggers_expected_rules():
    email = parse_email((SAMPLES / "phishing_contoso_login.eml").read_text(encoding="utf-8"))
    assert {"URL-TEXT-MISMATCH", "URL-IP-ADDRESS", "URL-NO-HTTPS"} <= rule_ids(run_url_checks(email))


def test_legitimate_sample_has_no_link_findings():
    email = parse_email((SAMPLES / "legitimate_contoso_newsletter.eml").read_text(encoding="utf-8"))
    assert run_url_checks(email) == []


def test_generic_link_text_is_not_a_mismatch():
    assert check("https://contoso.example/login", "Click here") == set()


def test_www_and_bare_domain_are_not_a_mismatch():
    assert check("https://www.contoso.example/page", "contoso.example/page") == set()


def test_url_shortener():
    assert "URL-SHORTENER" in check("https://bit.ly/abc123")


def test_punycode_domain():
    assert "URL-PUNYCODE" in check("https://xn--pypal-4ve.com/login")


def test_brand_lookalike_domain():
    assert "URL-BRAND-LOOKALIKE" in check("https://paypal-secure-login.example/verify")


def test_real_brand_domain_is_not_flagged():
    assert check("https://www.paypal.com/signin") == set()


def test_non_web_links_are_skipped():
    assert check("mailto:help@contoso.example") == set()

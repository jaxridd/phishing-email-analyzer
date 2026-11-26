"""Tests for the email parser."""

from pathlib import Path

import pytest

from analyzer.parser import EmailParseError, parse_email

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def load_sample(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


@pytest.fixture
def phishing_email():
    return parse_email(load_sample("phishing_contoso_login.eml"))


@pytest.fixture
def legit_email():
    return parse_email(load_sample("legitimate_contoso_newsletter.eml"))


def test_parses_sender_fields(phishing_email):
    assert phishing_email.from_address == "security@contoso-bank-alerts.example"
    assert phishing_email.display_name == "Contoso Bank Security"
    assert phishing_email.reply_to == "support@account-verify-help.example"
    assert phishing_email.return_path == "bounce@mailer-update.example"


def test_parses_subject_and_auth_results(phishing_email):
    assert "URGENT" in phishing_email.subject
    assert "spf=fail" in phishing_email.auth_results
    assert "dmarc=fail" in phishing_email.auth_results


def test_extracts_html_link_with_display_text(phishing_email):
    assert len(phishing_email.links) == 1
    link = phishing_email.links[0]
    assert link.url == "http://192.0.2.10/contoso/login.php"
    assert link.display_text == "https://www.contoso-bank.example/secure-login"


def test_lists_attachment_without_opening(phishing_email):
    assert len(phishing_email.attachments) == 1
    assert phishing_email.attachments[0].filename == "Account_Statement.html"


def test_legitimate_email_has_no_attachments(legit_email):
    assert legit_email.attachments == []
    assert "spf=pass" in legit_email.auth_results


def test_extracts_plain_text_urls():
    raw = (
        "From: someone@example.com\n"
        "Subject: Test\n"
        "\n"
        "Visit https://example.com/page. Thanks!\n"
    )
    parsed = parse_email(raw)
    assert [link.url for link in parsed.links] == ["https://example.com/page"]


def test_rejects_empty_input():
    with pytest.raises(EmailParseError):
        parse_email("   ")


def test_rejects_oversized_input():
    with pytest.raises(EmailParseError):
        parse_email("From: a@example.com\nSubject: big\n\n" + "A" * 1_100_000)


def test_rejects_text_that_is_not_an_email():
    with pytest.raises(EmailParseError):
        parse_email("just some random text with no headers")

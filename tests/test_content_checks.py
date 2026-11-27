"""Tests for content and attachment phishing checks."""

from pathlib import Path

from analyzer.content_checks import check_attachment, run_content_checks
from analyzer.models import Attachment, ParsedEmail
from analyzer.parser import parse_email

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def load(name):
    return parse_email((SAMPLES / name).read_text(encoding="utf-8"))


def test_phishing_sample_triggers_expected_rules():
    ids = rule_ids(run_content_checks(load("phishing_contoso_login.eml")))
    assert {"CNT-URGENCY", "CNT-CREDENTIAL-REQUEST", "ATT-RISKY-TYPE"} <= ids


def test_legitimate_sample_has_no_content_findings():
    assert run_content_checks(load("legitimate_contoso_newsletter.eml")) == []


def test_password_warning_is_not_a_credential_request():
    email = ParsedEmail(text_body="We will never ask for your password by email.")
    assert "CNT-CREDENTIAL-REQUEST" not in rule_ids(run_content_checks(email))


def test_urgency_is_case_insensitive():
    email = ParsedEmail(subject="FINAL NOTICE: Act Now")
    assert "CNT-URGENCY" in rule_ids(run_content_checks(email))


def test_double_extension_attachment():
    findings = check_attachment(Attachment(filename="Invoice.pdf.exe"))
    assert rule_ids(findings) == {"ATT-DOUBLE-EXTENSION"}


def test_archive_attachment_is_medium():
    findings = check_attachment(Attachment(filename="documents.zip"))
    assert findings[0].rule_id == "ATT-ARCHIVE"
    assert findings[0].severity == "medium"


def test_pdf_attachment_is_not_flagged():
    assert check_attachment(Attachment(filename="statement.pdf")) == []

"""Header-based phishing checks: authentication results and sender mismatches."""

from analyzer.models import Finding, ParsedEmail


def run_header_checks(email: ParsedEmail) -> list[Finding]:
    """Run all header checks and return any findings.

    TODO (Day 2): SPF/DKIM/DMARC results, Reply-To and Return-Path
    mismatches, display name impersonation.
    """
    raise NotImplementedError

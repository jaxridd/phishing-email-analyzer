"""Link-based phishing checks."""

from analyzer.models import Finding, ParsedEmail


def run_url_checks(email: ParsedEmail) -> list[Finding]:
    """Run all link checks and return any findings.

    TODO (Day 3): text/destination mismatch, raw IP URLs, URL shorteners,
    lookalike domains.
    """
    raise NotImplementedError

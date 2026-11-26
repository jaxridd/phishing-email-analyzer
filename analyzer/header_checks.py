"""Content and attachment phishing checks."""

from analyzer.models import Finding, ParsedEmail


def run_content_checks(email: ParsedEmail) -> list[Finding]:
    """Run all content and attachment checks and return any findings.

    TODO (Day 3): urgency language, credential requests, risky attachments.
    """
    raise NotImplementedError

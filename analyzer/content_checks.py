"""Content and attachment phishing checks."""

import re

from bs4 import BeautifulSoup

from analyzer.models import Attachment, Finding, ParsedEmail

# Phrases that pressure the reader to act quickly.
URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bact now\b",
    r"\bfinal (notice|warning)\b",
    r"\bwithin \d+ (hours|hrs|days)\b",
    r"\b(account|access) (will be|has been) (suspended|locked|disabled|closed)\b",
    r"\b(suspension|suspended|permanently locked)\b",
    r"\b(expires?|expiring) (today|soon)\b",
]

# Phrases that ask the reader to hand over credentials or sensitive data.
# These match requests ("confirm your password"), not warnings ("we will never ask for your password").
CREDENTIAL_PATTERNS = [
    r"\b(confirm|verify|enter|update|provide|validate|reset) (your )?"
    r"(username|password|login|credentials|account|identity|payment)",
    r"\busername and password\b",
    r"\b(social security|credit card|bank account|routing) number\b",
    r"\bpin number\b",
]

# Attachment types that can run code or disguise malicious content.
HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".msi", ".jar",
    ".hta", ".html", ".htm", ".iso", ".img", ".lnk",
    ".docm", ".xlsm", ".pptm",  # Office files with macros
}
MEDIUM_RISK_EXTENSIONS = {".zip", ".rar", ".7z"}  # archives can hide other files
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}

PHISHING = "T1566"                    # MITRE ATT&CK: Phishing
PHISHING_FOR_INFORMATION = "T1598"    # MITRE ATT&CK: Phishing for Information
SPEARPHISHING_ATTACHMENT = "T1566.001"


def run_content_checks(email: ParsedEmail) -> list[Finding]:
    """Run all content and attachment checks and return any findings."""
    text = get_readable_text(email)
    findings: list[Finding] = []
    findings.extend(check_urgency(text))
    findings.extend(check_credential_request(text))
    for attachment in email.attachments:
        findings.extend(check_attachment(attachment))
    return findings


def get_readable_text(email: ParsedEmail) -> str:
    """Combine the subject, plain-text body, and HTML body (with tags removed) into one string."""
    html_text = BeautifulSoup(email.html_body, "html.parser").get_text(" ") if email.html_body else ""
    combined = " ".join([email.subject, email.text_body, html_text])
    return " ".join(combined.split()).lower()


def find_matches(text: str, patterns: list[str]) -> list[str]:
    """Return the text matched by each pattern that appears, in order."""
    matches = []
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            matches.append(match.group(0))
    return matches


def check_urgency(text: str) -> list[Finding]:
    """Flag pressure language that rushes the reader into acting."""
    matches = find_matches(text, URGENCY_PATTERNS)
    if not matches:
        return []
    return [Finding("CNT-URGENCY", "content", "medium",
                    "The email uses urgent or threatening language to pressure the reader.",
                    "Matched: " + ", ".join(f'"{m}"' for m in matches), PHISHING)]


def check_credential_request(text: str) -> list[Finding]:
    """Flag requests for passwords, account verification, or financial details."""
    matches = find_matches(text, CREDENTIAL_PATTERNS)
    if not matches:
        return []
    return [Finding("CNT-CREDENTIAL-REQUEST", "content", "high",
                    "The email asks the reader to provide login credentials or sensitive information.",
                    "Matched: " + ", ".join(f'"{m}"' for m in matches), PHISHING_FOR_INFORMATION)]


def get_extensions(filename: str) -> list[str]:
    """Return every extension in a filename, for example 'invoice.pdf.exe' -> ['.pdf', '.exe']."""
    parts = filename.lower().split(".")
    return ["." + part for part in parts[1:]] if len(parts) > 1 else []


def check_attachment(attachment: Attachment) -> list[Finding]:
    """Flag risky attachment types and double extensions that disguise a file's real type."""
    extensions = get_extensions(attachment.filename)
    if not extensions:
        return []

    final_ext = extensions[-1]

    if len(extensions) >= 2 and extensions[-2] in DOCUMENT_EXTENSIONS and final_ext in HIGH_RISK_EXTENSIONS:
        return [Finding("ATT-DOUBLE-EXTENSION", "attachment", "high",
                        "An attachment uses a double extension to disguise a dangerous file as a document.",
                        attachment.filename, SPEARPHISHING_ATTACHMENT)]

    if final_ext in HIGH_RISK_EXTENSIONS:
        return [Finding("ATT-RISKY-TYPE", "attachment", "high",
                        f"An attachment is a {final_ext} file, which can run code or imitate a login page.",
                        attachment.filename, SPEARPHISHING_ATTACHMENT)]

    if final_ext in MEDIUM_RISK_EXTENSIONS:
        return [Finding("ATT-ARCHIVE", "attachment", "medium",
                        "An attachment is a compressed archive, which can hide other files from scanners.",
                        attachment.filename, SPEARPHISHING_ATTACHMENT)]

    return []

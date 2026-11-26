"""Shared data models used across the analyzer modules."""

from dataclasses import dataclass, field


@dataclass
class Link:
    """A link found in the email body."""

    url: str
    display_text: str = ""


@dataclass
class Attachment:
    """Metadata for an email attachment. Attachment contents are never opened."""

    filename: str
    content_type: str = ""


@dataclass
class ParsedEmail:
    """Structured representation of a raw email."""

    from_address: str = ""
    display_name: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    auth_results: str = ""
    text_body: str = ""
    html_body: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)


@dataclass
class Finding:
    """A single phishing indicator detected by a rule."""

    rule_id: str
    category: str          # "header", "link", "content", or "attachment"
    severity: str          # "low", "medium", or "high"
    description: str
    evidence: str = ""
    attack_technique: str = ""  # MITRE ATT&CK ID, for example "T1566.002"


@dataclass
class AnalysisResult:
    """Final output of an analysis run."""

    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "Low"
    attack_techniques: list[str] = field(default_factory=list)
    ai_explanation: str = ""
    ai_available: bool = False

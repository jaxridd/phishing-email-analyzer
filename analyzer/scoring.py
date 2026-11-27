"""Calculates the risk score, verdict, and ATT&CK techniques from findings."""

from analyzer.models import Finding

SEVERITY_WEIGHTS = {"low": 10, "medium": 20, "high": 35}
MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 60


def score_findings(findings: list[Finding]) -> tuple[int, str, list[str]]:
    """Return (score, verdict, attack_techniques) for a list of findings.

    Each rule counts once toward the score, even if it matched several times
    (for example, three suspicious links), so one repeated problem can't
    inflate the score on its own.
    """
    unique_rules: dict[str, Finding] = {}
    for finding in findings:
        unique_rules.setdefault(finding.rule_id, finding)

    score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in unique_rules.values())
    techniques = sorted({f.attack_technique for f in findings if f.attack_technique})
    return score, get_verdict(score), techniques


def get_verdict(score: int) -> str:
    """Convert a numeric score into a Low, Medium, or High verdict."""
    if score >= HIGH_THRESHOLD:
        return "High"
    if score >= MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"

"""Calculates the risk score, verdict, and ATT&CK techniques from findings."""

from analyzer.models import Finding

SEVERITY_WEIGHTS = {"low": 10, "medium": 20, "high": 35}
MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 60


def score_findings(findings: list[Finding]) -> tuple[int, str, list[str]]:
    """Return (score, verdict, attack_techniques) for a list of findings.

    TODO (Day 4): sum weights, apply thresholds, collect unique techniques.
    """
    raise NotImplementedError

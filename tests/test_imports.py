"""Smoke test to confirm the analyzer package imports correctly."""

from analyzer import models


def test_models_import():
    finding = models.Finding(
        rule_id="TEST-1",
        category="header",
        severity="low",
        description="Example finding",
    )
    assert finding.severity == "low"

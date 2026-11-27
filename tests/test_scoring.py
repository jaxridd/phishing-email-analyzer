"""Tests for scoring and the full analysis pipeline."""

from pathlib import Path

from analyzer.models import Finding
from analyzer.pipeline import analyze_email
from analyzer.scoring import get_verdict, score_findings

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def make_finding(rule_id, severity, technique=""):
    return Finding(rule_id, "header", severity, "test", attack_technique=technique)


def test_no_findings_scores_zero_and_low():
    assert score_findings([]) == (0, "Low", [])


def test_repeated_rule_counts_once():
    findings = [make_finding("URL-SHORTENER", "medium")] * 3
    score, _, _ = score_findings(findings)
    assert score == 20


def test_verdict_thresholds():
    assert get_verdict(29) == "Low"
    assert get_verdict(30) == "Medium"
    assert get_verdict(59) == "Medium"
    assert get_verdict(60) == "High"


def test_techniques_are_unique_and_sorted():
    findings = [
        make_finding("A", "low", "T1566.002"),
        make_finding("B", "low", "T1566"),
        make_finding("C", "low", "T1566.002"),
    ]
    _, _, techniques = score_findings(findings)
    assert techniques == ["T1566", "T1566.002"]


def test_pipeline_rates_phishing_sample_high():
    raw = (SAMPLES / "phishing_contoso_login.eml").read_text(encoding="utf-8")
    _, result = analyze_email(raw, use_ai=False)
    assert result.verdict == "High"


def test_pipeline_rates_legitimate_sample_low():
    raw = (SAMPLES / "legitimate_contoso_newsletter.eml").read_text(encoding="utf-8")
    _, result = analyze_email(raw, use_ai=False)
    assert result.verdict == "Low"
    assert result.score == 0

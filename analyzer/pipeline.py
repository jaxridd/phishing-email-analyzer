"""Runs the full analysis: parse, check, score, and explain."""

from analyzer.content_checks import run_content_checks
from analyzer.header_checks import run_header_checks
from analyzer.llm import explain_findings
from analyzer.models import AnalysisResult, ParsedEmail
from analyzer.parser import parse_email
from analyzer.scoring import score_findings
from analyzer.url_checks import run_url_checks


def analyze_email(raw_email: str, use_ai: bool = True) -> tuple[ParsedEmail, AnalysisResult]:
    """Analyze a raw email and return the parsed email and the analysis result.

    Raises:
        EmailParseError: if the input can't be parsed (passed up from the parser).
    """
    email = parse_email(raw_email)

    findings = run_header_checks(email) + run_url_checks(email) + run_content_checks(email)
    score, verdict, techniques = score_findings(findings)

    result = AnalysisResult(
        findings=findings,
        score=score,
        verdict=verdict,
        attack_techniques=techniques,
    )

    if use_ai:
        result.ai_explanation, result.ai_available = explain_findings(email, result)

    return email, result

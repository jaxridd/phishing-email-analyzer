"""Builds downloadable Markdown and JSON reports."""

from analyzer.models import AnalysisResult


def to_markdown(result: AnalysisResult) -> str:
    """Return the analysis as a Markdown report. TODO (Day 5)."""
    raise NotImplementedError


def to_json(result: AnalysisResult) -> str:
    """Return the analysis as a JSON report. TODO (Day 5)."""
    raise NotImplementedError

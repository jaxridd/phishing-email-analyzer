"""Generates plain-language explanations using the Google Gemini API."""

import os

from analyzer.models import AnalysisResult, ParsedEmail

DEFAULT_MODEL = "gemini-2.5-flash"


def get_model_name() -> str:
    """Return the Gemini model name, configurable through GEMINI_MODEL."""
    return os.getenv("GEMINI_MODEL", DEFAULT_MODEL)


def explain_findings(email: ParsedEmail, result: AnalysisResult) -> tuple[str, bool]:
    """Return (explanation, ai_available).

    TODO (Day 4): build the prompt from findings and a short email excerpt,
    call Gemini, handle missing keys and API errors with a rules-only fallback.
    """
    raise NotImplementedError

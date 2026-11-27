"""Tests for the Gemini explanation module. No real API calls are made."""

from analyzer import llm
from analyzer.models import AnalysisResult, Finding, ParsedEmail

EMAIL = ParsedEmail(from_address="a@example.com", subject="Test", text_body="Hello " * 500)
RESULT = AnalysisResult(
    findings=[Finding("HDR-SPF-FAIL", "header", "medium", "SPF failed.", "spf=fail")],
    score=20,
    verdict="Low",
)


def test_missing_api_key_uses_fallback(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    text, available = llm.explain_findings(EMAIL, RESULT)
    assert available is False
    assert "no Gemini API key" in text


def test_api_error_uses_fallback(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")

    def broken_call(prompt, api_key):
        raise ConnectionError("network down")

    monkeypatch.setattr(llm, "call_gemini", broken_call)
    text, available = llm.explain_findings(EMAIL, RESULT)
    assert available is False
    assert "ConnectionError" in text


def test_successful_call_returns_ai_text(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
    monkeypatch.setattr(llm, "call_gemini", lambda prompt, api_key: "  **Summary:** test  ")
    text, available = llm.explain_findings(EMAIL, RESULT)
    assert available is True
    assert text == "**Summary:** test"


def test_prompt_marks_email_as_untrusted_and_limits_length():
    prompt = llm.build_prompt(EMAIL, RESULT)
    assert "<untrusted_email_excerpt>" in prompt
    assert "SPF failed." in prompt
    body_line = next(line for line in prompt.splitlines() if line.startswith("Body:"))
    assert len(body_line) <= len("Body: ") + llm.MAX_EXCERPT_CHARS

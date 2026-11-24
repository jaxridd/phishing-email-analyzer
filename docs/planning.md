# Project Planning Document: AI Phishing Email Analyzer

**Author:** Jax Riddell
**Course:** COSC 4272 Senior Seminar
**Project:** AI-Assisted Software Development Project

---

## 1. Problem Statement

Phishing is one of the most common ways attackers gain access to organizations. It is especially common in financial services, where employees and members are targeted with fake login pages, fraudulent invoices, and impersonation of trusted brands. Many phishing emails can be identified by technical signs in the email headers and links, such as failed authentication checks, mismatched sender addresses, and links that point somewhere other than what they display. However, these signs are hidden from most users and take time for IT staff to check manually.

This project builds a tool that analyzes a raw email, identifies phishing indicators using rule-based checks, assigns a risk score, and uses AI to explain the findings in plain language so both technical and non-technical users can understand why an email is suspicious.

## 2. Project Objectives

1. Parse raw email files (`.eml` or pasted source) into headers, body, links, and attachments.
2. Detect common phishing indicators in headers, links, content, and attachments using deterministic rules.
3. Produce a consistent, explainable risk score and verdict (Low, Medium, High).
4. Map findings to relevant MITRE ATT&CK techniques.
5. Use Google Gemini to generate a plain-language explanation and recommended actions.
6. Continue working in rules-only mode if the AI service is unavailable.
7. Allow users to export the analysis as a report.
8. Demonstrate AI-assisted development across planning, coding, testing, and documentation.

## 3. Functional Requirements

Full details are in `requirements.md`. Summary:

| ID | Requirement |
|---|---|
| FR-1 | Accept email input by pasting raw source or uploading an `.eml` file |
| FR-2 | Parse headers, plain-text and HTML body, links, and attachment metadata |
| FR-3 | Check SPF, DKIM, and DMARC results from authentication headers |
| FR-4 | Detect From, Reply-To, and Return-Path domain mismatches |
| FR-5 | Detect display name impersonation |
| FR-6 | Detect suspicious links (text/destination mismatch, IP-based URLs, shorteners, lookalike domains) |
| FR-7 | Detect urgency language and credential requests |
| FR-8 | Flag risky attachment file types |
| FR-9 | Calculate a weighted risk score and verdict |
| FR-10 | Map findings to MITRE ATT&CK techniques |
| FR-11 | Generate an AI explanation and recommended actions |
| FR-12 | Fall back to rules-only output if AI is unavailable |
| FR-13 | Export results as Markdown or JSON |

## 4. System Features

- **Email input:** paste raw email text or upload an `.eml` file.
- **Header analysis:** authentication results and sender mismatches.
- **Link analysis:** hidden destinations, raw IP links, shorteners, and lookalike domains.
- **Content and attachment analysis:** pressure language, credential requests, and dangerous file types.
- **Risk scoring:** weighted, rule-based score with a clear verdict.
- **MITRE ATT&CK mapping:** each finding linked to a technique where applicable.
- **AI explanation:** Gemini summarizes the findings and recommends next steps.
- **Report export:** download results for documentation or ticketing.

## 5. Software Design

### 5.1 Architecture

```
User (Streamlit UI)
      │  raw email / .eml upload
      ▼
parser.py ──► ParsedEmail (headers, body, links, attachments)
      │
      ├─► header_checks.py ─┐
      ├─► url_checks.py ────┼─► list[Finding]
      └─► content_checks.py ┘
                             │
                             ▼
                      scoring.py ──► score, verdict, ATT&CK techniques
                             │
                             ▼
                        llm.py (Gemini) ──► explanation (or fallback text)
                             │
                             ▼
                      report.py ──► Markdown / JSON export
```

### 5.2 Module Responsibilities

| Module | Responsibility |
|---|---|
| `app.py` | Streamlit interface, input handling, displaying results |
| `analyzer/parser.py` | Converts raw email into a `ParsedEmail` object |
| `analyzer/header_checks.py` | Authentication results and sender mismatch checks |
| `analyzer/url_checks.py` | Link extraction and suspicious link checks |
| `analyzer/content_checks.py` | Urgency language, credential requests, risky attachments |
| `analyzer/scoring.py` | Weights, total score, verdict, ATT&CK mapping |
| `analyzer/llm.py` | Gemini API call, prompt building, error handling, fallback |
| `analyzer/report.py` | Markdown and JSON report generation |
| `analyzer/models.py` | Shared data classes (`ParsedEmail`, `Finding`, `AnalysisResult`) |

### 5.3 Core Data Model

- **ParsedEmail:** sender, display name, reply-to, return-path, subject, authentication results, plain-text body, HTML body, list of links, list of attachments.
- **Finding:** rule ID, category, severity (low/medium/high), description, evidence, ATT&CK technique ID.
- **AnalysisResult:** list of findings, total score, verdict, ATT&CK techniques, AI explanation.

### 5.4 Scoring Approach

Each rule has a fixed weight. The total score determines the verdict:

| Score | Verdict |
|---|---|
| 0–29 | Low |
| 30–59 | Medium |
| 60+ | High |

Rules decide the verdict. The AI only explains it. This keeps results consistent, testable, and reliable even if the AI is wrong or unavailable.

### 5.5 Security and Privacy Design

- The API key is stored in a `.env` file locally and in Streamlit secrets when deployed. It is never committed.
- Input size is limited to prevent oversized uploads.
- Only a short excerpt of the email plus the structured findings are sent to the AI.
- Emails are not stored after analysis.
- Only synthetic sample emails are used for testing.

## 6. Technology Stack

| Area | Technology |
|---|---|
| Language | Python 3.11+ |
| User interface | Streamlit |
| Email parsing | Python standard library `email` package |
| HTML link parsing | BeautifulSoup |
| AI | Google Gemini API (`google-genai` SDK) |
| Configuration | `python-dotenv` |
| Testing | pytest |
| Version control | Git and GitHub |
| Deployment | Streamlit Community Cloud |
| AI development tools | Claude (planning, design, code assistance, documentation) |

## 7. Development Timeline

| Day | Tasks |
|---|---|
| Day 1 (Tue) | Planning document, requirements specification, repository setup, project skeleton, AI usage log |
| Day 2 (Wed) | Email parser, header checks, synthetic sample emails, initial tests |
| Day 3 (Thu) | Link checks, content and attachment checks |
| Day 4 (Fri) | Scoring, ATT&CK mapping, Gemini integration, Streamlit interface |
| Day 5 (Sat) | Report export, error handling, additional tests, deployment, screenshots |
| Day 6 (Sun) | README, final AI usage log review, portfolio update, submission |

# Requirements Specification: AI Phishing Email Analyzer

## 1. Project Scope

### In Scope
- Analyzing a single email at a time from pasted raw source or an uploaded `.eml` file
- Rule-based detection of phishing indicators in headers, links, content, and attachment names
- Weighted risk scoring with a Low, Medium, or High verdict
- Mapping findings to MITRE ATT&CK techniques
- AI-generated explanations using the Google Gemini API
- Exporting results as Markdown or JSON
- A web interface built with Streamlit

### Out of Scope
- Connecting to live mailboxes (Outlook, Gmail, IMAP)
- Opening, executing, or scanning attachment contents
- Visiting or detonating links
- Automatically blocking, deleting, or quarantining email
- Storing analysis history or user accounts
- Guaranteeing detection of every phishing email

## 2. Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| FR-1 | The system shall accept email input by pasting raw email source into a text area. | Must |
| FR-2 | The system shall accept email input by uploading an `.eml` file. | Must |
| FR-3 | The system shall parse the From address, display name, Reply-To, Return-Path, subject, and authentication headers. | Must |
| FR-4 | The system shall extract the plain-text body and HTML body. | Must |
| FR-5 | The system shall extract all links, including the visible link text and actual destination for HTML links. | Must |
| FR-6 | The system shall list attachment file names and types without opening them. | Must |
| FR-7 | The system shall report SPF, DKIM, and DMARC results when present and flag failures or missing results. | Must |
| FR-8 | The system shall flag when the Reply-To or Return-Path domain differs from the From domain. | Must |
| FR-9 | The system shall flag display names that reference a known brand or role while the sending domain does not match. | Should |
| FR-10 | The system shall flag links whose visible text shows a different domain than the actual destination. | Must |
| FR-11 | The system shall flag links that use a raw IP address, a known URL shortener, or a lookalike domain. | Must |
| FR-12 | The system shall flag urgency or pressure language in the subject and body. | Must |
| FR-13 | The system shall flag requests for passwords, account verification, or payment details. | Must |
| FR-14 | The system shall flag attachments with risky extensions (for example `.exe`, `.js`, `.html`, `.docm`, `.zip`). | Must |
| FR-15 | The system shall calculate a total risk score from weighted findings and assign a verdict of Low, Medium, or High. | Must |
| FR-16 | The system shall map applicable findings to MITRE ATT&CK technique IDs. | Should |
| FR-17 | The system shall send the findings and a short email excerpt to Google Gemini and display a plain-language explanation with recommended actions. | Must |
| FR-18 | The system shall display rules-only results with a clear notice if the AI service is unavailable or no API key is configured. | Must |
| FR-19 | The system shall allow the user to download the analysis as a Markdown or JSON report. | Should |
| FR-20 | The system shall display clear error messages for empty, invalid, or oversized input. | Must |

## 3. Non-Functional Requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-1 | Performance | Rule-based analysis shall complete in under 2 seconds for a typical email. AI explanations should return in under 15 seconds. |
| NFR-2 | Reliability | The application shall not crash on malformed email input and shall show a helpful error message instead. |
| NFR-3 | Security | The API key shall be stored in environment variables or Streamlit secrets and never committed to the repository. |
| NFR-4 | Privacy | Emails shall not be stored after analysis, and only a limited excerpt shall be sent to the AI service. |
| NFR-5 | Input Limits | Input shall be limited to 1 MB. |
| NFR-6 | Consistency | The same email shall always produce the same score and verdict, independent of the AI response. |
| NFR-7 | Usability | Results shall be understandable by a non-technical user, with severity clearly labeled. |
| NFR-8 | Maintainability | Code shall be modular, with each type of check in its own module, and follow PEP 8 style. |
| NFR-9 | Testability | Parser, check, and scoring functions shall be covered by automated pytest tests. |
| NFR-10 | Availability | The application shall be deployed to Streamlit Community Cloud with a public URL. |

## 4. Assumptions

- Users can obtain the raw source of an email (for example, "Show original" in Gmail or "View message source" in Outlook).
- Authentication results (SPF, DKIM, DMARC) are added by the receiving mail server in the `Authentication-Results` header. If missing, they are reported as unavailable rather than failed.
- The Google Gemini free tier provides enough requests for development, testing, and demonstration.
- All testing uses synthetic sample emails with fictional organizations, not real user or workplace emails.
- The tool supports, but does not replace, human judgment and organizational security processes.

## 5. Constraints

- The project must be completed within one week.
- Only free or low-cost services may be used.
- The tool runs as a single-user web application with no database.

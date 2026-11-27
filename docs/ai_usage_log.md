# AI Usage Log

**Project:** AI Phishing Email Analyzer
**Author:** Jax Riddell
**AI tool used:** Claude (Anthropic)

This log documents how AI tools were used throughout the development lifecycle. Each entry records the prompt, a summary of the AI response, my modifications, and the final result.

---

## Entry 1: Brainstorming Project Ideas

**Date:** November 24, 2026
**Phase:** Requirements and planning

**Prompt:**
> I want to start brainstorming what I'm going to do for my project. Give me some ideas that I could even put on my current resume.

**AI response (summary):**
Suggested four security-focused project ideas aligned with junior cybersecurity and networking roles: an AI security log analyzer, a phishing email analyzer, an AI help desk ticket triage tool, and an Nmap scan explainer. Each included the purpose, technology stack, effort level, and an example resume bullet. Recommended a design where rule-based logic detects issues and the AI only explains them.

**My modifications:**
Narrowed the list to the phishing email analyzer because phishing is highly relevant to financial institutions and easy to demonstrate. Asked for additional options to compare against before committing.

**Result:**
Selected the phishing email analyzer as a leading candidate.

---

## Entry 2: Comparing Additional Cybersecurity Project Options

**Date:** November 24, 2026
**Phase:** Requirements and planning

**Prompt:**
> I like the phishing email analyzer. What are some other options that would look impressive for the roles I'm applying to? I'm trying to break into cyber.

**AI response (summary):**
Suggested a vulnerability prioritizer using NVD, CISA KEV, and EPSS data, a Sigma detection rule generator, an Active Directory security auditor, and a threat intelligence indicator extractor. Also suggested ways to make the phishing analyzer stand out: authentication header parsing, link reputation checks, rule-based scoring, MITRE ATT&CK mapping, and report export.

**My modifications:**
Compared the options against my one-week deadline. Chose the phishing analyzer with the suggested enhancements because it balances impact and feasibility. Moved link reputation lookups to a stretch goal.

**Result:**
Final project selected: AI Phishing Email Analyzer with header analysis, link analysis, rule-based scoring, ATT&CK mapping, AI explanations, and report export.

---

## Entry 3: Project Planning Against Assignment Requirements

**Date:** November 24, 2026
**Phase:** Planning and design

**Prompt:**
> It's due in 5 days, so let's do the phishing analyzer. Let's plan it out now. Use the assignment PDF to ensure I meet all requirements.

**AI response (summary):**
Created a requirements checklist mapped to the assignment PDF, a feature list split into core and stretch goals, a modular project structure, a technology stack, and a day-by-day schedule with commit targets. Recommended Anthropic or Google Gemini for the AI component.

**My modifications:**
Chose Google Gemini instead of Anthropic because it offers a free tier. Adjusted the schedule to account for the Thanksgiving holiday. Reviewed the generated planning document and requirements specification for accuracy.

**Result:**
Created `docs/planning.md` and `requirements.md`, and set up the project folder structure.

---

## Entry 4: Implementing the Email Parser

**Date:** November 25, 2026
**Phase:** Implementation

**Prompt:**
> Let's continue working through this project, also you need to explain what we're actually doing.

**AI response (summary):**
Generated `parser.py`, which validates input, reads headers with Python's email library, separates display names from addresses, combines authentication results, walks MIME parts to separate text, HTML, and attachments, and extracts links with both their visible text and actual destination. Also generated 9 pytest tests and explained how raw emails and MIME parts are structured.

**My modifications:**
Reviewed the parser logic against the sample phishing email to confirm it extracted the hidden link destination correctly. Fixed a file setup issue where module contents were placed in the wrong files, which caused a circular import error.

**Result:**
Parser complete with 10 passing tests.

---

## Entry 5: Implementing Header Checks

**Date:** November 26, 2026
**Phase:** Implementation and testing

**Prompt:**
> Done, 10 passed. Let's continue.

**AI response (summary):**
Generated `header_checks.py` with four checks: SPF, DKIM, and DMARC authentication results; Reply-To domain mismatch; Return-Path domain mismatch; and display name impersonation using a list of commonly spoofed brands. Each check returns findings with a rule ID, severity, evidence, and MITRE ATT&CK technique. Also generated 8 pytest tests, including false-positive tests for subdomain bounce addresses and real brand domains, and explained what SPF, DKIM, and DMARC verify.

**My modifications:**
Reviewed the severity levels and confirmed Return-Path mismatches should stay low severity because legitimate mailing services use separate bounce domains. Noted that the base domain comparison does not handle domains like .co.uk and added it as a future enhancement.

**Result:**
Header checks complete. All 18 tests passed, and the phishing sample triggered all five expected header rules while the legitimate sample triggered none.

---

## Entry 6: Implementing Link Checks

**Date:** November 26, 2026
**Phase:** Implementation and testing

**Prompt:**
> Let's check the links.

**AI response (summary):**
Generated `url_checks.py` with five checks per link: visible text versus actual destination mismatch, raw IP address links, URL shorteners, lookalike domains (punycode and brand names in non-brand domains), and links without HTTPS. Reused the brand list and base domain function from the header checks module. Also generated 9 pytest tests covering each rule and false positives such as "Click here" text and the real paypal.com domain.

**My modifications:**
Verified that the phishing sample's hidden link (displaying the bank's domain but pointing to a raw IP address) was caught by the mismatch and IP address checks. Confirmed that www and non-www versions of the same domain were not flagged as mismatches.

**Result:**
Link checks complete. All 27 tests passed.

---

## Entry 7: Implementing Content and Attachment Checks

**Date:** November 26, 2026
**Phase:** Implementation and testing

**Prompt:**
> Let's do the last check modules.

**AI response (summary):**
Generated `content_checks.py` with checks for urgency language, credential requests, and risky attachments. Urgency and credential checks use regex patterns, and credential patterns were written to match requests but not warnings such as "we will never ask for your password." Attachment checks flag double extensions, executable and macro-enabled file types, HTML attachments, and archives without opening the files. Also generated 7 pytest tests.

**My modifications:**
Tested that the legitimate sample email, which contains the word "password" in a security warning, did not trigger a credential request finding. Reviewed the attachment risk levels and kept archives at medium severity since they are commonly used for legitimate file sharing.

**Result:**
All three check modules complete. All 34 tests passed.

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



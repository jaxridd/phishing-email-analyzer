"""Header-based phishing checks: authentication results and sender mismatches."""

import re

from analyzer.models import Finding, ParsedEmail

# Brands commonly impersonated in phishing. A display name mentioning one of these
# is suspicious when the sending domain does not belong to that brand.
KNOWN_BRANDS = {
    "paypal": "paypal",
    "microsoft": "microsoft",
    "office 365": "microsoft",
    "outlook": "microsoft",
    "apple": "apple",
    "amazon": "amazon",
    "google": "google",
    "netflix": "netflix",
    "docusign": "docusign",
    "chase": "chase",
    "wells fargo": "wellsfargo",
    "bank of america": "bankofamerica",
}

SPF_FAIL_RESULTS = {"fail", "permerror"}
SPF_WEAK_RESULTS = {"softfail", "neutral"}
DKIM_FAIL_RESULTS = {"fail", "permerror"}
DMARC_FAIL_RESULTS = {"fail", "permerror"}

PHISHING = "T1566"       # MITRE ATT&CK: Phishing
IMPERSONATION = "T1656"  # MITRE ATT&CK: Impersonation


def run_header_checks(email: ParsedEmail) -> list[Finding]:
    """Run all header checks and return any findings."""
    findings: list[Finding] = []
    findings.extend(check_authentication(email.auth_results))
    findings.extend(check_reply_to(email))
    findings.extend(check_return_path(email))
    findings.extend(check_display_name(email))
    return findings


# ---------- Authentication (SPF, DKIM, DMARC) ----------

def get_auth_result(auth_results: str, method: str) -> str:
    """Return the result for one method (for example 'spf=fail' -> 'fail'), or ''."""
    match = re.search(rf"\b{method}=(\w+)", auth_results)
    return match.group(1) if match else ""


def check_authentication(auth_results: str) -> list[Finding]:
    """Flag failed or missing SPF, DKIM, and DMARC results."""
    if not auth_results:
        return [Finding(
            rule_id="HDR-AUTH-MISSING",
            category="header",
            severity="low",
            description="No authentication results were found, so the sender could not be verified.",
        )]

    findings: list[Finding] = []
    spf = get_auth_result(auth_results, "spf")
    dkim = get_auth_result(auth_results, "dkim")
    dmarc = get_auth_result(auth_results, "dmarc")

    if spf in SPF_FAIL_RESULTS:
        findings.append(Finding("HDR-SPF-FAIL", "header", "medium",
                                "SPF failed: the sending server is not authorized to send for this domain.",
                                f"spf={spf}", PHISHING))
    elif spf in SPF_WEAK_RESULTS:
        findings.append(Finding("HDR-SPF-SOFTFAIL", "header", "low",
                                "SPF returned a weak result, so the sending server is not clearly authorized.",
                                f"spf={spf}", PHISHING))
    elif spf in ("", "none"):
        findings.append(Finding("HDR-SPF-MISSING", "header", "low",
                                "No SPF result was found for the sending domain."))

    if dkim in DKIM_FAIL_RESULTS:
        findings.append(Finding("HDR-DKIM-FAIL", "header", "medium",
                                "DKIM failed: the message signature is invalid or the message was altered.",
                                f"dkim={dkim}", PHISHING))
    elif dkim in ("", "none"):
        findings.append(Finding("HDR-DKIM-MISSING", "header", "low",
                                "The message is not DKIM signed, so its origin cannot be confirmed.",
                                f"dkim={dkim or 'missing'}"))

    if dmarc in DMARC_FAIL_RESULTS:
        findings.append(Finding("HDR-DMARC-FAIL", "header", "high",
                                "DMARC failed: the message does not pass the sending domain's own authentication policy.",
                                f"dmarc={dmarc}", PHISHING))
    elif dmarc in ("", "none"):
        findings.append(Finding("HDR-DMARC-MISSING", "header", "low",
                                "No DMARC result was found for the sending domain."))

    return findings


# ---------- Sender mismatches ----------

def get_domain(address: str) -> str:
    """Return the domain part of an email address, or '' if there isn't one."""
    return address.rsplit("@", 1)[1].lower() if "@" in address else ""


def get_base_domain(domain: str) -> str:
    """Return the last two labels of a domain (mail.contoso.com -> contoso.com).

    This is a simplification. Domains like example.co.uk would need a public
    suffix list to handle correctly.
    """
    labels = domain.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def domains_match(address_a: str, address_b: str) -> bool:
    """Return True if two addresses share the same base domain."""
    return get_base_domain(get_domain(address_a)) == get_base_domain(get_domain(address_b))


def check_reply_to(email: ParsedEmail) -> list[Finding]:
    """Flag a Reply-To address that sends replies to a different domain."""
    if email.reply_to and email.from_address and not domains_match(email.reply_to, email.from_address):
        return [Finding("HDR-REPLYTO-MISMATCH", "header", "medium",
                        "Replies would go to a different domain than the sender's.",
                        f"From: {email.from_address} | Reply-To: {email.reply_to}", PHISHING)]
    return []


def check_return_path(email: ParsedEmail) -> list[Finding]:
    """Flag a Return-Path on a different domain. Low severity because mailing services do this legitimately."""
    if email.return_path and email.from_address and not domains_match(email.return_path, email.from_address):
        return [Finding("HDR-RETURNPATH-MISMATCH", "header", "low",
                        "The bounce address (Return-Path) is on a different domain than the sender.",
                        f"From: {email.from_address} | Return-Path: {email.return_path}")]
    return []


# ---------- Display name impersonation ----------

def check_display_name(email: ParsedEmail) -> list[Finding]:
    """Flag display names that impersonate a brand or contain a different email address."""
    name = email.display_name.lower()
    from_domain = get_domain(email.from_address)
    if not name or not from_domain:
        return []

    findings: list[Finding] = []

    if "@" in name and get_domain(name) != from_domain:
        findings.append(Finding("HDR-DISPLAYNAME-EMAIL", "header", "high",
                                "The display name shows a different email address than the real sender.",
                                f"Display name: {email.display_name} | Actual sender: {email.from_address}",
                                IMPERSONATION))

    for brand, brand_domain in KNOWN_BRANDS.items():
        if brand in name and brand_domain not in from_domain.replace("-", ""):
            findings.append(Finding("HDR-DISPLAYNAME-BRAND", "header", "high",
                                    f"The display name mentions {brand.title()}, but the email was not sent from their domain.",
                                    f"Display name: {email.display_name} | Actual sender: {email.from_address}",
                                    IMPERSONATION))
            break  # one brand finding is enough

    return findings

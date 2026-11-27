"""Link-based phishing checks."""

import ipaddress
import re
from urllib.parse import urlparse

from analyzer.header_checks import KNOWN_BRANDS, get_base_domain
from analyzer.models import Finding, Link, ParsedEmail

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
}

# Display text that looks like a domain, for example "contoso.com/login".
DOMAIN_LIKE = re.compile(r"^[\w.-]+\.[a-z]{2,}(/\S*)?$", re.IGNORECASE)

SPEARPHISHING_LINK = "T1566.002"  # MITRE ATT&CK: Phishing: Spearphishing Link


def run_url_checks(email: ParsedEmail) -> list[Finding]:
    """Run all link checks on every web link in the email."""
    findings: list[Finding] = []
    for link in email.links:
        host = get_host(link.url)
        if not host:
            continue  # skip mailto:, tel:, and other non-web links
        findings.extend(check_text_mismatch(link, host))
        findings.extend(check_ip_address(link, host))
        findings.extend(check_shortener(link, host))
        findings.extend(check_lookalike(link, host))
        findings.extend(check_https(link))
    return findings


def get_host(url: str) -> str:
    """Return the lowercase hostname of an http(s) URL, or '' if it isn't one."""
    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in ("http", "https"):
        return ""
    return (parsed.hostname or "").lower()


def get_display_host(display_text: str) -> str:
    """Return the hostname shown in a link's visible text, or '' if the text isn't a URL."""
    text = display_text.strip()
    if text.lower().startswith(("http://", "https://")):
        return get_host(text)
    if DOMAIN_LIKE.match(text):
        return get_host("http://" + text)
    return ""  # text like "Click here" doesn't claim a destination


def check_text_mismatch(link: Link, host: str) -> list[Finding]:
    """Flag links whose visible text shows one domain but actually go to another."""
    shown_host = get_display_host(link.display_text)
    if shown_host and get_base_domain(shown_host) != get_base_domain(host):
        return [Finding("URL-TEXT-MISMATCH", "link", "high",
                        "A link shows one website but actually goes to a different one.",
                        f"Shows: {link.display_text} | Goes to: {link.url}", SPEARPHISHING_LINK)]
    return []


def check_ip_address(link: Link, host: str) -> list[Finding]:
    """Flag links that point to a raw IP address instead of a domain name."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return []
    return [Finding("URL-IP-ADDRESS", "link", "medium",
                    "A link points to a raw IP address instead of a website name.",
                    link.url, SPEARPHISHING_LINK)]


def check_shortener(link: Link, host: str) -> list[Finding]:
    """Flag shortened links, which hide the real destination."""
    if host.removeprefix("www.") in URL_SHORTENERS:
        return [Finding("URL-SHORTENER", "link", "medium",
                        "A link uses a URL shortener, which hides where it really goes.",
                        link.url, SPEARPHISHING_LINK)]
    return []


def check_lookalike(link: Link, host: str) -> list[Finding]:
    """Flag internationalized (punycode) domains and domains that misuse a brand name."""
    if "xn--" in host:
        return [Finding("URL-PUNYCODE", "link", "high",
                        "A link uses an internationalized domain, which can disguise lookalike characters.",
                        link.url, SPEARPHISHING_LINK)]

    base_label = get_base_domain(host).split(".")[0]
    compact_host = host.replace("-", "")
    for brand_token in set(KNOWN_BRANDS.values()):
        if brand_token in compact_host and base_label != brand_token:
            return [Finding("URL-BRAND-LOOKALIKE", "link", "medium",
                            f"A link uses the name '{brand_token}' in a domain that doesn't belong to that brand.",
                            link.url, SPEARPHISHING_LINK)]
    return []


def check_https(link: Link) -> list[Finding]:
    """Flag links that don't use HTTPS. Low severity because some legitimate sites still use HTTP."""
    if urlparse(link.url).scheme.lower() == "http":
        return [Finding("URL-NO-HTTPS", "link", "low",
                        "A link does not use a secure (HTTPS) connection.",
                        link.url)]
    return []

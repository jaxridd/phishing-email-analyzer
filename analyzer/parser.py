"""Parses raw email source into a ParsedEmail object."""

import re
from email import message_from_string, policy
from email.message import EmailMessage
from email.utils import parseaddr

from bs4 import BeautifulSoup

from analyzer.models import Attachment, Link, ParsedEmail

MAX_INPUT_BYTES = 1_000_000  # 1 MB limit (NFR-5)

# Matches http:// or https:// URLs in plain text, stopping at whitespace or quotes.
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
TRAILING_PUNCTUATION = ".,;:!?)]}"


class EmailParseError(Exception):
    """Raised when the input cannot be parsed as an email."""


def parse_email(raw_email: str) -> ParsedEmail:
    """Parse raw email text into a ParsedEmail.

    Raises:
        EmailParseError: if the input is empty, too large, or not an email.
    """
    _validate_input(raw_email)

    try:
        message = message_from_string(raw_email, policy=policy.default)
    except Exception as exc:  # the email library can raise many error types
        raise EmailParseError(f"Could not read the email: {exc}") from exc

    if not message.get("From") and not message.get("Subject"):
        raise EmailParseError(
            "This doesn't look like a raw email. Make sure you copied the full "
            "source, including headers like From and Subject."
        )

    display_name, from_address = parseaddr(str(message.get("From", "")))
    text_body, html_body, attachments = _extract_parts(message)

    return ParsedEmail(
        from_address=from_address.lower(),
        display_name=display_name,
        reply_to=parseaddr(str(message.get("Reply-To", "")))[1].lower(),
        return_path=parseaddr(str(message.get("Return-Path", "")))[1].lower(),
        subject=str(message.get("Subject", "")),
        auth_results=_get_auth_results(message),
        text_body=text_body,
        html_body=html_body,
        links=_extract_links(text_body, html_body),
        attachments=attachments,
    )


def _validate_input(raw_email: str) -> None:
    """Reject empty, non-text, or oversized input before parsing."""
    if not isinstance(raw_email, str) or not raw_email.strip():
        raise EmailParseError("No email content was provided.")
    if len(raw_email.encode("utf-8", errors="ignore")) > MAX_INPUT_BYTES:
        raise EmailParseError("The email is larger than the 1 MB limit.")


def _get_auth_results(message: EmailMessage) -> str:
    """Combine all Authentication-Results headers into one lowercase string."""
    headers = message.get_all("Authentication-Results") or []
    combined = " ".join(str(header) for header in headers)
    return " ".join(combined.split()).lower()  # collapse line breaks and extra spaces


def _extract_parts(message: EmailMessage) -> tuple[str, str, list[Attachment]]:
    """Walk every MIME part and sort it into text, HTML, or attachment."""
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []

    for part in message.walk():
        if part.is_multipart():
            continue  # containers hold other parts but no content themselves

        filename = part.get_filename()
        if part.get_content_disposition() == "attachment" or filename:
            attachments.append(
                Attachment(
                    filename=filename or "unnamed",
                    content_type=part.get_content_type(),
                )
            )
            continue  # attachments are listed but never opened

        content_type = part.get_content_type()
        if content_type == "text/plain":
            text_parts.append(_decode_part(part))
        elif content_type == "text/html":
            html_parts.append(_decode_part(part))

    return "\n".join(text_parts), "\n".join(html_parts), attachments


def _decode_part(part: EmailMessage) -> str:
    """Return a part's text, falling back safely if the encoding is broken."""
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError, KeyError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _extract_links(text_body: str, html_body: str) -> list[Link]:
    """Collect links from HTML anchor tags and plain-text URLs, without duplicates."""
    links: list[Link] = []
    seen: set[str] = set()

    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        for anchor in soup.find_all("a", href=True):
            url = anchor["href"].strip()
            if url and url not in seen:
                links.append(Link(url=url, display_text=anchor.get_text(strip=True)))
                seen.add(url)

    for match in URL_PATTERN.findall(text_body):
        url = match.rstrip(TRAILING_PUNCTUATION)
        if url not in seen:
            links.append(Link(url=url, display_text=url))
            seen.add(url)

    return links

"""Parses raw email source into a ParsedEmail object."""

from analyzer.models import ParsedEmail

MAX_INPUT_BYTES = 1_000_000  # 1 MB limit (NFR-5)


class EmailParseError(Exception):
    """Raised when the input cannot be parsed as an email."""


def parse_email(raw_email: str) -> ParsedEmail:
    """Parse raw email text into a ParsedEmail.

    TODO (Day 2): validate input size and content, parse headers with the
    standard library email package, extract text and HTML bodies, links,
    and attachment metadata.
    """
    raise NotImplementedError

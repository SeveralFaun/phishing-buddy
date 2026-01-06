"""EML file parsing utilities."""

import email
import email.policy
from email import message_from_bytes
from typing import Dict, List, Optional, Tuple


def parse_eml_file(file_path: str) -> Tuple[email.message.EmailMessage, bytes]:
    """
    Parse an EML file and return the email message object and raw bytes.

    Args:
        file_path: Path to the .eml file

    Returns:
        Tuple of (EmailMessage, raw_bytes)

    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the file cannot be parsed as an email
    """
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        msg = message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception as e:
        raise ValueError(f"Failed to parse EML file: {e}")

    return msg, raw_bytes


def extract_headers(msg: email.message.EmailMessage) -> Dict[str, List[str]]:
    """
    Extract all headers from the email message, preserving duplicates.

    Email headers can appear multiple times (e.g., Received headers).
    We preserve all values as a list to maintain full information.

    Args:
        msg: Parsed email message

    Returns:
        Dictionary mapping header names to lists of values
    """
    headers: Dict[str, List[str]] = {}

    # Iterate through all header items to preserve duplicates
    for name, value in msg.items():
        # Normalize header name but preserve original case in values
        name_lower = name.lower()
        if name_lower not in headers:
            headers[name_lower] = []
        headers[name_lower].append(value)

    return headers


def get_key_headers(msg: email.message.EmailMessage) -> Dict[str, str]:
    """
    Extract key headers as single values (first occurrence if multiple).

    Args:
        msg: Parsed email message

    Returns:
        Dictionary with From, To, Subject, Date, Message-ID, Return-Path
    """
    key_headers = {}
    for key in ["From", "To", "Subject", "Date", "Message-ID", "Return-Path"]:
        value = msg.get(key, "")
        key_headers[key] = value if value else ""

    return key_headers


def extract_body_parts(
    msg: email.message.EmailMessage,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract text/plain and text/html parts from the email.

    Skips attachments (Content-Disposition: attachment) and handles
    charset decoding safely.

    Args:
        msg: Parsed email message

    Returns:
        Tuple of (text_plain, text_html), either can be None
    """
    text_plain: Optional[str] = None
    text_html: Optional[str] = None

    def walk_parts(part: email.message.EmailMessage) -> None:
        nonlocal text_plain, text_html

        # Check if this is an attachment
        content_disposition = part.get("Content-Disposition", "")
        if content_disposition and "attachment" in content_disposition.lower():
            return

        # Get content type
        content_type = part.get_content_type()

        # Extract text/plain
        if content_type == "text/plain" and text_plain is None:
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        text_plain = payload.decode(charset, errors="replace")
                    except (UnicodeDecodeError, LookupError):
                        # Fallback to utf-8 if charset is invalid
                        text_plain = payload.decode("utf-8", errors="replace")
            except Exception:
                pass  # Skip if decoding fails

        # Extract text/html
        elif content_type == "text/html" and text_html is None:
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        text_html = payload.decode(charset, errors="replace")
                    except (UnicodeDecodeError, LookupError):
                        # Fallback to utf-8 if charset is invalid
                        text_html = payload.decode("utf-8", errors="replace")
            except Exception:
                pass  # Skip if decoding fails

        # Recurse into multipart messages
        if part.is_multipart():
            for subpart in part.iter_parts():
                walk_parts(subpart)

    walk_parts(msg)

    return text_plain, text_html



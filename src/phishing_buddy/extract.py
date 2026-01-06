"""URL and domain extraction from email content.

This module contains TODO stubs that must be implemented.
All functions should raise NotImplementedError until implemented.
"""

from typing import Dict, List

from .models import DomainCount, UrlFinding


def extract_urls_from_headers(headers: Dict[str, List[str]]) -> List[UrlFinding]:
    """
    Extract URLs from email headers.

    Headers like From, Reply-To, List-Unsubscribe, etc. may contain URLs.
    This function should scan all header values for URL patterns.

    Args:
        headers: Dictionary mapping header names to lists of values

    Returns:
        List of UrlFinding objects with source indicating the header name

    Raises:
        NotImplementedError: This function must be implemented
    """
    raise NotImplementedError(
        "extract_urls_from_headers must be implemented. "
        "Scan header values for URL patterns and return UrlFinding objects."
    )


def extract_urls_from_text(text: str, source: str) -> List[UrlFinding]:
    """
    Extract URLs from email body text (plain text or HTML).

    Requirements:
    - Handle defanged patterns: hxxp/hxxps, [.] and (.)
    - For HTML: extract href/src attributes from <a>, <img>, <link>, etc.
    - Strip trailing punctuation from URLs
    - Provide context snippets where possible

    Args:
        text: The text content (plain text or HTML)
        source: Source identifier like "body:text/plain" or "body:text/html"

    Returns:
        List of UrlFinding objects with source and optional context

    Raises:
        NotImplementedError: This function must be implemented
    """
    raise NotImplementedError(
        "extract_urls_from_text must be implemented. "
        "Handle defanged URLs (hxxp, [.], (.)), extract from HTML href/src, "
        "strip trailing punctuation, and provide context snippets."
    )


def extract_domains(url_findings: List[UrlFinding]) -> List[DomainCount]:
    """
    Extract and count unique domains from URL findings.

    Requirements:
    - Use urlparse(url).hostname to handle credentials, ports, and IPv6
    - Normalize domains using tldextract
    - Keep IP addresses and localhost as-is (don't normalize)
    - Count occurrences per domain

    Note: We use hostname instead of netloc because:
    - hostname gives us just the domain/IP without port or credentials
    - netloc includes port and credentials which we don't need for domain analysis
    - This allows proper handling of IPv6 addresses and credentials in URLs

    Args:
        url_findings: List of UrlFinding objects

    Returns:
        List of DomainCount objects sorted by count (descending)

    Raises:
        NotImplementedError: This function must be implemented
    """
    raise NotImplementedError(
        "extract_domains must be implemented. "
        "Use urlparse().hostname to extract domains, normalize with tldextract, "
        "preserve IPs and localhost, and count occurrences."
    )



"""Tests for URL extraction functions."""

import pytest

from phishing_buddy.extract import extract_urls_from_headers, extract_urls_from_text
from phishing_buddy.models import UrlFinding


def test_extract_urls_from_headers():
    """Test extraction of URLs from email headers."""
    headers = {
        "from": ["sender@example.com"],
        "reply-to": ["https://example.com/reply"],
        "list-unsubscribe": ["<https://example.com/unsubscribe>"],
    }

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        extract_urls_from_headers(headers)

    # Once implemented, should return list of UrlFinding objects
    # Expected behavior:
    # - Extract URLs from header values
    # - Return UrlFinding with source like "header:Reply-To"
    # - Handle angle brackets and other formatting


def test_extract_urls_from_text_plain():
    """Test extraction of URLs from plain text body."""
    text = "Visit https://example.com/page for more info. Also check hxxp://evil.com/test"

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        extract_urls_from_text(text, "body:text/plain")

    # Once implemented, should:
    # - Extract https://example.com/page
    # - Handle defanged hxxp://evil.com/test (convert to http://)
    # - Strip trailing punctuation
    # - Provide context snippets


def test_extract_urls_from_text_html():
    """Test extraction of URLs from HTML body."""
    html = """
    <html>
    <body>
    <a href="https://example.com/link">Click here</a>
    <img src="https://example.com/image.png" />
    <link rel="stylesheet" href="https://example.com/style.css" />
    </body>
    </html>
    """

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        extract_urls_from_text(html, "body:text/html")

    # Once implemented, should:
    # - Extract href from <a> tags
    # - Extract src from <img> tags
    # - Extract href from <link> tags
    # - Handle defanged patterns in HTML
    # - Provide context snippets


def test_extract_urls_defanged_patterns():
    """Test handling of defanged URL patterns."""
    text = "Check hxxp://evil[.]com and hxxps://bad(.)site/path"

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        extract_urls_from_text(text, "body:text/plain")

    # Once implemented, should:
    # - Convert hxxp:// to http://
    # - Convert hxxps:// to https://
    # - Replace [.] with .
    # - Replace (.) with .
    # - Result: http://evil.com and https://bad.site/path


def test_extract_urls_trailing_punctuation():
    """Test stripping trailing punctuation from URLs."""
    text = "Visit https://example.com/page. Also see https://test.com/path!"

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        extract_urls_from_text(text, "body:text/plain")

    # Once implemented, should:
    # - Strip trailing . from first URL
    # - Strip trailing ! from second URL
    # - URLs should be: https://example.com/page and https://test.com/path



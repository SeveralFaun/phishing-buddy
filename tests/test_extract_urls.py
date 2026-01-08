"""Tests for URL extraction functions."""

import pytest

from phishing_buddy.extract import extract_urls_from_headers, extract_urls_from_text
from phishing_buddy.models import UrlFinding


def test_extract_urls_from_headers():
    headers = {
        "from": ["sender@example.com"],
        "reply-to": ["https://example.com/reply"],
        "list-unsubscribe": ["<https://example.com/unsubscribe>"],
    }

    results = extract_urls_from_headers(headers)

    urls = {u.url for u in results}
    sources = {u.source for u in results}

    assert "https://example.com/reply" in urls
    assert "https://example.com/unsubscribe" in urls

    # Source should include header name (your extractor uses lowercase keys from parser)
    assert "header:reply-to" in sources
    assert "header:list-unsubscribe" in sources

    # Context should exist and be a string (truncated header value)
    assert all(isinstance(u.context, str) or u.context is None for u in results)


def test_extract_urls_from_text_plain():
    text = "Visit https://example.com/page for more info. Also check hxxp://evil.com/test"

    results = extract_urls_from_text(text, "body:text/plain")
    urls = {u.url for u in results}

    assert "https://example.com/page" in urls
    # defanged hxxp -> http
    assert "http://evil.com/test" in urls

    # should include context snippets
    assert all(u.context is None or isinstance(u.context, str) for u in results)
    assert any(u.context and "example.com/page" in u.context for u in results)


def test_extract_urls_from_text_html():
    html = """
    <html>
    <body>
    <a href="https://example.com/link">Click here</a>
    <img src="https://example.com/image.png" />
    <link rel="stylesheet" href="https://example.com/style.css" />
    </body>
    </html>
    """

    results = extract_urls_from_text(html, "body:text/html")
    urls = {u.url for u in results}

    assert "https://example.com/link" in urls
    assert "https://example.com/image.png" in urls
    assert "https://example.com/style.css" in urls

    # should provide context snippets from HTML
    assert any(u.context and "href" in u.context.lower() for u in results)


def test_extract_urls_defanged_patterns():
    text = "Check hxxp://evil[.]com and hxxps://bad(.)site/path"

    results = extract_urls_from_text(text, "body:text/plain")
    urls = {u.url for u in results}

    assert "http://evil.com" in urls
    assert "https://bad.site/path" in urls


def test_extract_urls_trailing_punctuation():
    text = "Visit https://example.com/page. Also see https://test.com/path!"

    results = extract_urls_from_text(text, "body:text/plain")
    urls = {u.url for u in results}

    assert "https://example.com/page" in urls
    assert "https://test.com/path" in urls

    # Make sure punctuation-stripped versions are present (not the punctuated ones)
    assert "https://example.com/page." not in urls
    assert "https://test.com/path!" not in urls
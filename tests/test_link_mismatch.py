"""Tests for link mismatch detection."""

import pytest

from phishing_buddy.analyze import detect_link_mismatch
from phishing_buddy.models import Flag


def test_detect_link_mismatch_positive():
    html = """
    <html>
    <body>
    <a href="https://evil.com/phish">https://bank.com/login</a>
    </body>
    </html>
    """

    flags = detect_link_mismatch(html)

    assert len(flags) == 1
    f = flags[0]
    assert f.id == "LINK_MISMATCH"
    assert f.severity == "high"
    assert "visible_domain" in f.evidence
    assert "href_domain" in f.evidence
    assert f.evidence["visible_domain"] == "bank.com"
    assert f.evidence["href_domain"] == "evil.com"


def test_detect_link_mismatch_negative():
    html = """
    <html>
    <body>
    <a href="https://bank.com/login">https://bank.com/login</a>
    </body>
    </html>
    """

    flags = detect_link_mismatch(html)
    assert flags == []


def test_detect_link_mismatch_multiple():
    html = """
    <html>
    <body>
    <a href="https://evil1.com">https://legit1.com</a>
    <a href="https://evil2.com">Click here</a>
    </body>
    </html>
    """

    flags = detect_link_mismatch(html)

    # With the conservative approach, the first anchor should be flagged.
    # The second anchor ("Click here") may or may not be flagged depending on your heuristics.
    # If your implementation only flags when visible text contains a domain, expect 1.
    assert len(flags) == 1
    assert flags[0].id == "LINK_MISMATCH"
    assert flags[0].evidence["visible_domain"] == "legit1.com"
    assert flags[0].evidence["href_domain"] == "evil1.com"


def test_detect_link_mismatch_anchor_text_only():
    html = """
    <html>
    <body>
    <a href="https://evil.com">Click here to login to your bank</a>
    </body>
    </html>
    """

    flags = detect_link_mismatch(html)

    # If visible text contains no URL/domain token, we should NOT flag
    # (avoids false positives on generic "click here").
    assert flags == []


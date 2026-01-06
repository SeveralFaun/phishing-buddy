"""Tests for link mismatch detection."""

import pytest

from phishing_buddy.analyze import detect_link_mismatch
from phishing_buddy.models import Flag


def test_detect_link_mismatch_positive():
    """Test detection of link mismatch (visible text vs href)."""
    html = """
    <html>
    <body>
    <a href="https://evil.com/phish">https://bank.com/login</a>
    </body>
    </html>
    """

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        detect_link_mismatch(html)

    # Once implemented, should:
    # - Detect that visible text shows bank.com but href is evil.com
    # - Return Flag with id="LINK_MISMATCH", severity="high"
    # - Include evidence with both domains


def test_detect_link_mismatch_negative():
    """Test that matching links don't trigger false positives."""
    html = """
    <html>
    <body>
    <a href="https://bank.com/login">https://bank.com/login</a>
    </body>
    </html>
    """

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        detect_link_mismatch(html)

    # Once implemented, should:
    # - Not flag matching domains
    # - Return empty list


def test_detect_link_mismatch_multiple():
    """Test detection of multiple link mismatches."""
    html = """
    <html>
    <body>
    <a href="https://evil1.com">https://legit1.com</a>
    <a href="https://evil2.com">Click here</a>
    </body>
    </html>
    """

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        detect_link_mismatch(html)

    # Once implemented, should:
    # - Detect both mismatches
    # - Return list of 2 Flag objects


def test_detect_link_mismatch_anchor_text_only():
    """Test detection when anchor text is not a URL."""
    html = """
    <html>
    <body>
    <a href="https://evil.com">Click here to login to your bank</a>
    </body>
    </html>
    """

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        detect_link_mismatch(html)

    # Once implemented, should:
    # - Extract domain from anchor text if it contains a URL
    # - Or handle non-URL anchor text appropriately
    # - May need to extract domain from text like "bank.com" in "login to your bank"



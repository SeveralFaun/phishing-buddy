"""Tests for authentication results parsing."""

import pytest

from phishing_buddy.analyze import parse_authentication_results
from phishing_buddy.models import AuthSummary


def test_parse_authentication_results_basic():
    """Test parsing of basic Authentication-Results header."""
    headers = {
        "authentication-results": [
            "example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"
        ]
    }

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        parse_authentication_results(headers)

    # Once implemented, should return:
    # AuthSummary(spf="pass", dkim="pass", dmarc="pass", raw=[...])


def test_parse_authentication_results_failures():
    """Test parsing of failed authentication results."""
    headers = {
        "authentication-results": [
            "example.com; spf=fail smtp.mailfrom=evil.com; dkim=fail; dmarc=fail"
        ]
    }

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        parse_authentication_results(headers)

    # Once implemented, should return:
    # AuthSummary(spf="fail", dkim="fail", dmarc="fail", raw=[...])


def test_parse_authentication_results_multiple():
    """Test parsing when multiple Authentication-Results headers exist."""
    headers = {
        "authentication-results": [
            "server1.com; spf=pass",
            "server2.com; dkim=pass; dmarc=pass",
        ]
    }

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        parse_authentication_results(headers)

    # Once implemented, should:
    # - Parse all occurrences
    # - Extract final statuses (may need to handle precedence)
    # - Include all raw values in raw list


def test_parse_authentication_results_missing():
    """Test parsing when Authentication-Results header is missing."""
    headers = {
        "from": ["sender@example.com"],
    }

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        parse_authentication_results(headers)

    # Once implemented, should return:
    # AuthSummary(spf="none", dkim="none", dmarc="none", raw=[])


def test_parse_authentication_results_error_statuses():
    """Test parsing of error statuses (permerror, temperror)."""
    headers = {
        "authentication-results": [
            "example.com; spf=permerror; dkim=temperror; dmarc=neutral"
        ]
    }

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        parse_authentication_results(headers)

    # Once implemented, should return:
    # AuthSummary(spf="permerror", dkim="temperror", dmarc="neutral", raw=[...])



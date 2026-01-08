"""Tests for authentication results parsing."""

import pytest

from phishing_buddy.analyze import parse_authentication_results
from phishing_buddy.models import AuthSummary


def test_parse_authentication_results_basic():
    headers = {
        "authentication-results": [
            "example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"
        ]
    }

    result = parse_authentication_results(headers)

    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"
    assert result.raw == headers["authentication-results"]


def test_parse_authentication_results_failures():
    headers = {
        "authentication-results": [
            "example.com; spf=fail smtp.mailfrom=evil.com; dkim=fail; dmarc=fail"
        ]
    }

    result = parse_authentication_results(headers)

    assert result.spf == "fail"
    assert result.dkim == "fail"
    assert result.dmarc == "fail"
    assert result.raw == headers["authentication-results"]


def test_parse_authentication_results_multiple():
    headers = {
        "authentication-results": [
            "server1.com; spf=pass",
            "server2.com; dkim=pass; dmarc=pass",
        ]
    }

    result = parse_authentication_results(headers)

    # We expect it to combine across multiple header occurrences
    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"
    assert result.raw == headers["authentication-results"]


def test_parse_authentication_results_missing():
    headers = {
        "from": ["sender@example.com"],
    }

    result = parse_authentication_results(headers)

    # If header is missing, treat as "none"
    assert result.spf == "unknown"
    assert result.dkim == "unknown"
    assert result.dmarc == "unknown"
    assert result.raw == []


def test_parse_authentication_results_error_statuses():
    headers = {
        "authentication-results": [
            "example.com; spf=permerror; dkim=temperror; dmarc=neutral"
        ]
    }

    result = parse_authentication_results(headers)

    assert result.spf == "permerror"
    assert result.dkim == "temperror"
    assert result.dmarc == "neutral"
    assert result.raw == headers["authentication-results"]
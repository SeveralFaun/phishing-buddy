"""Tests for domain extraction functions."""

import pytest

from phishing_buddy.extract import extract_domains
from phishing_buddy.models import DomainCount, UrlFinding


def test_extract_domains_basic():
    url_findings = [
        UrlFinding(url="https://example.com/page", source="body:text/html"),
        UrlFinding(url="https://example.com/other", source="body:text/html"),
        UrlFinding(url="http://test.com/path", source="body:text/plain"),
    ]

    result = extract_domains(url_findings)

    assert result == [
        DomainCount(domain="example.com", count=2),
        DomainCount(domain="test.com", count=1),
    ]


def test_extract_domains_with_credentials():
    url_findings = [
        UrlFinding(url="https://user:pass@example.com/page", source="body:text/html"),
    ]

    result = extract_domains(url_findings)

    assert result == [DomainCount(domain="example.com", count=1)]


def test_extract_domains_with_ports():
    url_findings = [
        UrlFinding(url="https://example.com:8080/page", source="body:text/html"),
    ]

    result = extract_domains(url_findings)

    assert result == [DomainCount(domain="example.com", count=1)]


def test_extract_domains_ip_addresses():
    url_findings = [
        UrlFinding(url="http://192.168.1.1/page", source="body:text/html"),
        UrlFinding(url="http://[2001:db8::1]/path", source="body:text/html"),
    ]

    result = extract_domains(url_findings)

    # Order is count desc then domain asc (your implementation)
    assert result == [
        DomainCount(domain="192.168.1.1", count=1),
        DomainCount(domain="2001:db8::1", count=1),
    ]


def test_extract_domains_localhost():
    url_findings = [
        UrlFinding(url="http://localhost:3000/page", source="body:text/html"),
    ]

    result = extract_domains(url_findings)

    assert result == [DomainCount(domain="localhost", count=1)]


def test_extract_domains_tldextract_normalization():
    url_findings = [
        UrlFinding(url="https://subdomain.example.co.uk/page", source="body:text/html"),
    ]

    result = extract_domains(url_findings)

    # Expect registered domain (eTLD+1)
    assert result == [DomainCount(domain="example.co.uk", count=1)]

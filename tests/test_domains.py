"""Tests for domain extraction functions."""

import pytest

from phishing_buddy.extract import extract_domains
from phishing_buddy.models import DomainCount, UrlFinding


def test_extract_domains_basic():
    """Test basic domain extraction from URLs."""
    url_findings = [
        UrlFinding(url="https://example.com/page", source="body:text/html"),
        UrlFinding(url="https://example.com/other", source="body:text/html"),
        UrlFinding(url="http://test.com/path", source="body:text/plain"),
    ]

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        extract_domains(url_findings)

    # Once implemented, should return:
    # [
    #   DomainCount(domain="example.com", count=2),
    #   DomainCount(domain="test.com", count=1),
    # ]


def test_extract_domains_with_credentials():
    """Test domain extraction from URLs with credentials."""
    url_findings = [
        UrlFinding(url="https://user:pass@example.com/page", source="body:text/html"),
    ]

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        extract_domains(url_findings)

    # Once implemented, should:
    # - Use urlparse().hostname to get just the domain
    # - Ignore credentials and path
    # - Return DomainCount(domain="example.com", count=1)


def test_extract_domains_with_ports():
    """Test domain extraction from URLs with ports."""
    url_findings = [
        UrlFinding(url="https://example.com:8080/page", source="body:text/html"),
    ]

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        extract_domains(url_findings)

    # Once implemented, should:
    # - Use urlparse().hostname to get domain without port
    # - Return DomainCount(domain="example.com", count=1)


def test_extract_domains_ip_addresses():
    """Test domain extraction preserves IP addresses."""
    url_findings = [
        UrlFinding(url="http://192.168.1.1/page", source="body:text/html"),
        UrlFinding(url="http://[2001:db8::1]/path", source="body:text/html"),
    ]

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        extract_domains(url_findings)

    # Once implemented, should:
    # - Preserve IP addresses as-is (don't normalize with tldextract)
    # - Return DomainCount(domain="192.168.1.1", count=1)
    # - Return DomainCount(domain="2001:db8::1", count=1)


def test_extract_domains_localhost():
    """Test domain extraction preserves localhost."""
    url_findings = [
        UrlFinding(url="http://localhost:3000/page", source="body:text/html"),
    ]

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        extract_domains(url_findings)

    # Once implemented, should:
    # - Preserve localhost as-is (don't normalize)
    # - Return DomainCount(domain="localhost", count=1)


def test_extract_domains_tldextract_normalization():
    """Test domain normalization using tldextract."""
    url_findings = [
        UrlFinding(url="https://subdomain.example.co.uk/page", source="body:text/html"),
    ]

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        extract_domains(url_findings)

    # Once implemented, should:
    # - Use tldextract to normalize domain
    # - Extract registered domain: example.co.uk
    # - Return DomainCount(domain="example.co.uk", count=1)



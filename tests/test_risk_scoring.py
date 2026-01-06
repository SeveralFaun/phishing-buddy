"""Tests for risk score computation."""

import pytest

from phishing_buddy.analyze import compute_risk_score
from phishing_buddy.models import AuthSummary, DomainCount, Flag, UrlFinding


def test_compute_risk_score_basic():
    """Test basic risk score computation."""
    urls = [
        UrlFinding(url="https://example.com/page", source="body:text/html"),
    ]
    domains = [DomainCount(domain="example.com", count=1)]
    auth_summary = AuthSummary(spf="pass", dkim="pass", dmarc="pass", raw=[])
    flags = []

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        compute_risk_score(urls, domains, auth_summary, flags)

    # Once implemented, should:
    # - Return tuple of (score: int, flags: List[Flag])
    # - Score should be 0-100
    # - Flags should explain scoring decisions


def test_compute_risk_score_auth_failures():
    """Test risk score increases with authentication failures."""
    urls = []
    domains = []
    auth_summary = AuthSummary(spf="fail", dkim="fail", dmarc="fail", raw=[])
    flags = []

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        compute_risk_score(urls, domains, auth_summary, flags)

    # Once implemented, should:
    # - Increase score due to auth failures
    # - Add flags explaining the increase


def test_compute_risk_score_many_urls():
    """Test risk score increases with many URLs."""
    urls = [
        UrlFinding(url=f"https://evil{i}.com/page", source="body:text/html")
        for i in range(10)
    ]
    domains = [DomainCount(domain=f"evil{i}.com", count=1) for i in range(10)]
    auth_summary = AuthSummary(spf="pass", dkim="pass", dmarc="pass", raw=[])
    flags = []

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        compute_risk_score(urls, domains, auth_summary, flags)

    # Once implemented, should:
    # - Increase score due to many URLs/domains
    # - Add flags explaining the increase


def test_compute_risk_score_with_flags():
    """Test risk score computation considers existing flags."""
    urls = []
    domains = []
    auth_summary = AuthSummary(spf="pass", dkim="pass", dmarc="pass", raw=[])
    flags = [
        Flag(
            id="LINK_MISMATCH",
            severity="high",
            message="Link mismatch detected",
            evidence={},
        )
    ]

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        compute_risk_score(urls, domains, auth_summary, flags)

    # Once implemented, should:
    # - Increase score due to high severity flag
    # - Add additional flags explaining scoring decisions


def test_compute_risk_score_explainable():
    """Test that risk score is explainable via flags."""
    urls = [
        UrlFinding(url="https://suspicious.com/page", source="body:text/html"),
    ]
    domains = [DomainCount(domain="suspicious.com", count=1)]
    auth_summary = AuthSummary(spf="softfail", dkim="none", dmarc="none", raw=[])
    flags = []

    # This should raise NotImplementedError until implemented
    with pytest.raises(NotImplementedError):
        score, score_flags = compute_risk_score(urls, domains, auth_summary, flags)

    # Once implemented, should:
    # - Return flags that explain why score is what it is
    # - Each contributing factor should have a flag
    # - Flags should have appropriate severity levels



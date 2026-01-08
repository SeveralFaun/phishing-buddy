"""Tests for risk score computation."""

import pytest

from phishing_buddy.analyze import compute_risk_score
from phishing_buddy.models import AuthSummary, DomainCount, Flag, UrlFinding


def test_compute_risk_score_basic():
    urls = [UrlFinding(url="https://example.com/page", source="body:text/html")]
    domains = [DomainCount(domain="example.com", count=1)]
    auth_summary = AuthSummary(spf="pass", dkim="pass", dmarc="pass", raw=[])
    flags = []

    score, score_flags = compute_risk_score(urls, domains, auth_summary, flags)

    assert isinstance(score, int)
    assert 0 <= score <= 100
    assert isinstance(score_flags, list)
    # With all auth passing and only 1 URL/domain, score should be low (often 0)
    assert score <= 5


def test_compute_risk_score_auth_failures():
    urls = []
    domains = []
    auth_summary = AuthSummary(spf="fail", dkim="fail", dmarc="fail", raw=[])
    flags = []

    score, score_flags = compute_risk_score(urls, domains, auth_summary, flags)

    assert score > 0
    ids = {f.id for f in score_flags}
    # Expect flags explaining failures
    assert "AUTH_DMARC_FAIL" in ids
    assert "AUTH_SPF_FAIL" in ids
    assert "AUTH_DKIM_FAIL" in ids


def test_compute_risk_score_many_urls():
    urls = [UrlFinding(url=f"https://evil{i}.com/page", source="body:text/html") for i in range(10)]
    domains = [DomainCount(domain=f"evil{i}.com", count=1) for i in range(10)]
    auth_summary = AuthSummary(spf="pass", dkim="pass", dmarc="pass", raw=[])
    flags = []

    score, score_flags = compute_risk_score(urls, domains, auth_summary, flags)

    assert score > 0
    ids = {f.id for f in score_flags}
    assert "MANY_URLS" in ids
    assert "MANY_DOMAINS" in ids


def test_compute_risk_score_with_flags():
    urls = []
    domains = []
    auth_summary = AuthSummary(spf="pass", dkim="pass", dmarc="pass", raw=[])
    flags = [
        Flag(id="LINK_MISMATCH", severity="high", message="Link mismatch detected", evidence={})
    ]

    score, score_flags = compute_risk_score(urls, domains, auth_summary, flags)

    assert score > 0
    ids = {f.id for f in score_flags}
    # Your scoring adds a scoring flag when LINK_MISMATCH exists
    assert "SCORE_LINK_MISMATCH" in ids


def test_compute_risk_score_explainable():
    urls = [UrlFinding(url="https://suspicious.com/page", source="body:text/html")]
    domains = [DomainCount(domain="suspicious.com", count=1)]
    auth_summary = AuthSummary(spf="softfail", dkim="none", dmarc="none", raw=[])
    flags = []

    score, score_flags = compute_risk_score(urls, domains, auth_summary, flags)

    assert 0 <= score <= 100
    assert len(score_flags) >= 1

    # Ensure every scoring flag includes points evidence (per our implementation)
    for f in score_flags:
        assert "points" in f.evidence
        assert isinstance(f.evidence["points"], int)
        assert f.evidence["points"] > 0

    # Expect weak/missing auth to contribute
    ids = {f.id for f in score_flags}
    assert "AUTH_SPF_WEAK" in ids
    assert "AUTH_DKIM_MISSING" in ids
    assert "AUTH_DMARC_MISSING" in ids



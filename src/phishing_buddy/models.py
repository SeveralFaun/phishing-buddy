"""Data models for phishing email triage reports."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class UrlFinding:
    """Represents a URL found in email headers or body."""

    url: str
    source: str  # e.g., "header:From", "body:text/plain", "body:text/html"
    context: Optional[str] = None  # Optional short snippet around the URL


@dataclass
class DomainCount:
    """Represents a domain and how many times it appears."""

    domain: str
    count: int


@dataclass
class AuthSummary:
    """Authentication results summary from email headers."""

    spf: str  # pass|fail|none|permerror|temperror|neutral|softfail|unknown
    dkim: str
    dmarc: str
    raw: List[str] = field(default_factory=list)  # Raw Authentication-Results header values


@dataclass
class Flag:
    """A detection flag indicating a potential issue."""

    id: str
    severity: str  # low|med|high
    message: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Report:
    """Complete triage report for a phishing email."""

    source_file: str
    timestamp_utc: str
    headers: Dict[str, List[str]]  # Preserves duplicate headers
    key_headers: Dict[str, str]  # From, To, Subject, Date, Message-ID, Return-Path
    auth_summary: AuthSummary
    urls: List[UrlFinding]
    domains: List[DomainCount]
    flags: List[Flag]
    risk_score: int  # 0-100
    raw_preview: Optional[Dict[str, str]] = None  # Optional preview of text/plain and text/html



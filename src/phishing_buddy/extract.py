"""URL and domain extraction from email content."""

import html
import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

import tldextract

from .models import DomainCount, UrlFinding


# -----------------------------
# Regexes / constants
# -----------------------------

# Conservative direct URL matcher (good baseline)
_URL_REGEX = re.compile(
    r"""(?ix)
    \b(
        https?://[^\s<>"'{}|\\^`\[\]]+
        |
        ftp://[^\s<>"'{}|\\^`\[\]]+
        |
        www\.[^\s<>"'{}|\\^`\[\]]+
    )
    """
)

# URL-ish matcher that also catches common defang forms
_URLISH_REGEX = re.compile(
    r"""(?ix)\b(
        (?:https?|hxxps?|ftp)://[^\s<>"'{}|\\^`]+
        |
        www(?:\.|\[\.\])[^\s<>"'{}|\\^`]+
    )"""
)

# Common HTML attribute capture
_HTML_ATTR_REGEX = re.compile(
    r"""(?ix)\b(?:href|src)\s*=\s*(?:
        "(?P<dq>[^"]+)" |
        '(?P<sq>[^']+)' |
        (?P<bare>[^\s>]+)
    )"""
)

_ALLOWED_SCHEMES = {"http", "https", "ftp"}

_DEFANG_REPLACEMENTS = [
    (re.compile(r"(?i)\bhxxps://"), "https://"),
    (re.compile(r"(?i)\bhxxp://"), "http://"),
    (re.compile(r"(?i)\bwww\[\.\]"), "www."),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
]


# -----------------------------
# Helpers
# -----------------------------

def _clean_url(candidate: str) -> Optional[str]:
    """
    Normalize/defang and validate a candidate URL.
    - HTML-unescape entities (&amp; -> &)
    - Defang: hxxp/hxxps, [.] and (.)
    - Strip wrappers and trailing punctuation
    - Add scheme for www.*
    - Validate via urlparse
    """
    if not candidate:
        return None

    s = html.unescape(candidate.strip())

    # Defang normalization
    for pat, repl in _DEFANG_REPLACEMENTS:
        s = pat.sub(repl, s)

    # Strip wrappers
    s = s.strip().strip("<>\"'")

    # Strip common trailing punctuation
    s = s.rstrip(".,;:!?)\"])'}")

    # Add scheme for www.*
    if s.lower().startswith("www."):
        s = "http://" + s

    # Unquote percent-escapes once (nice for readability)
    try:
        s = unquote(s)
    except Exception:
        pass

    parsed = urlparse(s)

    # Only accept schemes we care about
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return None

    if not parsed.netloc and not parsed.path:
        return None

    return s


def _context_snippet(text: str, start: int, end: int, max_len: int = 200) -> str:
    left = max(0, start - 60)
    right = min(len(text), end + 60)
    snippet = text[left:right]
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if len(snippet) > max_len:
        snippet = snippet[: max_len - 3] + "..."
    return snippet


def _find_urls_in_string(text: str) -> List[Tuple[str, int, int]]:
    """
    Return raw URL candidates + spans from generic text.
    Includes:
    - standard URLs via _URL_REGEX
    - defanged/url-ish via _URLISH_REGEX
    - angle-bracket wrapped values <...>
    """
    candidates: List[Tuple[str, int, int]] = []

    for m in _URL_REGEX.finditer(text):
        candidates.append((m.group(1), m.start(1), m.end(1)))

    for m in _URLISH_REGEX.finditer(text):
        candidates.append((m.group(1), m.start(1), m.end(1)))

    for m in re.finditer(r"<([^>]+)>", text):
        candidates.append((m.group(1), m.start(1), m.end(1)))

    return candidates


# -----------------------------
# Public API
# -----------------------------

def extract_urls_from_headers(headers: Dict[str, List[str]]) -> List[UrlFinding]:
    """
    Extract URLs from email headers.
    Returns UrlFinding with source 'header:<headername>' and short context.
    """
    findings: List[UrlFinding] = []
    seen: Set[Tuple[str, str]] = set()  # (cleaned_url, source)

    for header_name, values in headers.items():
        source = f"header:{header_name}"

        for value in values:
            if not value:
                continue

            candidates = _find_urls_in_string(value)
            if not candidates:
                continue

            # Keep context as the header value (truncated)
            ctx = value.strip()
            if len(ctx) > 160:
                ctx = ctx[:157] + "..."

            for raw, _s, _e in candidates:
                cleaned = _clean_url(raw)
                if not cleaned:
                    continue

                key = (cleaned, source)
                if key in seen:
                    continue
                seen.add(key)

                findings.append(UrlFinding(url=cleaned, source=source, context=ctx))

    return findings


def extract_urls_from_text(text: str, source: str) -> List[UrlFinding]:
    """
    Extract URLs from email body text (plain text or HTML).

    Requirements:
    - Handle defanged patterns: hxxp/hxxps, [.] and (.); www[.]
    - For HTML: extract href/src attributes
    - Strip trailing punctuation from URLs
    - Provide context snippets where possible
    """
    if not text:
        return []

    findings: List[UrlFinding] = []
    seen: Set[Tuple[str, str]] = set()  # (cleaned_url, source)

    candidates = _find_urls_in_string(text)

    # If HTML-ish, also pull href/src attribute values
    if "html" in source.lower() or "href=" in text.lower() or "<a" in text.lower():
        for m in _HTML_ATTR_REGEX.finditer(text):
            raw = m.group("dq") or m.group("sq") or m.group("bare")
            if raw:
                candidates.append((raw, m.start(), m.end()))

    for raw, start, end in candidates:
        cleaned = _clean_url(raw)
        if not cleaned:
            continue

        key = (cleaned, source)
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            UrlFinding(
                url=cleaned,
                source=source,
                context=_context_snippet(text, start, end),
            )
        )

    return findings


def extract_domains(url_findings: List[UrlFinding]) -> List[DomainCount]:
    """
    Extract and count unique domains from URL findings.

    Requirements:
    - Use urlparse(url).hostname to handle credentials, ports, and IPv6
    - Normalize domains using tldextract
    - Keep IP addresses and localhost as-is (don't normalize)
    - Count occurrences per domain
    """
    counts: Dict[str, int] = {}

    for finding in url_findings:
        url = finding.url
        try:
            parsed = urlparse(url)
            host = parsed.hostname  # strips creds/port; handles IPv6
            if not host:
                continue

            host = host.strip().lower().strip("[]")

            # Preserve IPs + localhost
            if host == "localhost":
                domain = host
            else:
                try:
                    ipaddress.ip_address(host)
                    domain = host
                except ValueError:
                    ext = tldextract.extract(host)
                    if ext.domain and ext.suffix:
                        domain = f"{ext.domain}.{ext.suffix}"
                    else:
                        domain = host

            counts[domain] = counts.get(domain, 0) + 1

        except Exception:
            continue

    result = [DomainCount(domain=d, count=c) for d, c in counts.items()]
    result.sort(key=lambda x: (-x.count, x.domain))
    return result
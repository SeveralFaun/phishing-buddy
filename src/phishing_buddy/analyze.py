"""Analysis functions for detecting phishing indicators.

This module contains TODO stubs that must be implemented.
All functions should raise NotImplementedError until implemented.
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import tldextract

from .models import AuthSummary, DomainCount, Flag, UrlFinding


# -----------------------------
# Helpers
# -----------------------------

# Normalize common status values into the allowed vocabulary
_ALLOWED_SPF = {"pass", "fail", "none", "permerror", "temperror", "neutral", "softfail", "unknown"}
_ALLOWED_DKIM_DMARC = {"pass", "fail", "none", "permerror", "temperror", "neutral", "unknown"}

_STATUS_RE = {
    "spf": re.compile(r"(?i)\bspf\s*=\s*(pass|fail|none|permerror|temperror|neutral|softfail)\b"),
    "dkim": re.compile(r"(?i)\bdkim\s*=\s*(pass|fail|none|permerror|temperror|neutral)\b"),
    "dmarc": re.compile(r"(?i)\bdmarc\s*=\s*(pass|fail|none|permerror|temperror|neutral)\b"),
}

# Very lightweight defang normalization for URLs we parse in analysis
_DEFANG_FIXES = [
    (re.compile(r"(?i)\bhxxps://"), "https://"),
    (re.compile(r"(?i)\bhxxp://"), "http://"),
    (re.compile(r"(?i)\bwww\[\.\]"), "www."),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
]


def _normalize_url_for_parsing(raw: str) -> Optional[str]:
    """Convert common defanged/relative URL forms into something urlparse can handle."""
    if not raw:
        return None

    s = raw.strip().strip("<>\"'")

    for pat, repl in _DEFANG_FIXES:
        s = pat.sub(repl, s)

    # protocol-relative URLs: //example.com/path
    if s.startswith("//"):
        s = "http:" + s

    # www.example.com -> http://www.example.com
    if s.lower().startswith("www."):
        s = "http://" + s

    parsed = urlparse(s)
    if parsed.scheme and parsed.netloc:
        return s
    return None


def _registrable_domain(host: str) -> str:
    """
    Return eTLD+1 (registrable domain) when possible; otherwise host.
    Example: login.mail.example.co.uk -> example.co.uk
    """
    host = (host or "").strip().lower().strip("[]")
    if not host:
        return ""

    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def _looks_like_domain_token(token: str) -> bool:
    """Heuristic: does token look like a domain (not a full URL)?"""
    token = token.strip().lower().strip("()[]{}<>\"'.,;:!")
    if not token or len(token) < 4:
        return False
    if " " in token:
        return False
    # must have at least one dot and a plausible label
    if "." not in token:
        return False
    # avoid matching things like "1.2.3" by requiring alpha somewhere
    if not re.search(r"[a-z]", token):
        return False
    return True


# -----------------------------
# 1) Authentication-Results parsing
# -----------------------------

def parse_authentication_results(headers: Dict[str, List[str]]) -> AuthSummary:
    """
    Parse Authentication-Results headers to extract SPF, DKIM, and DMARC statuses.

    Note: Many emails contain multiple Authentication-Results headers as the message
    passes through hops. Typically the newest result is closest to the top of the
    header block. Our headers extraction preserves order; we choose the first
    recognized status we see for each of SPF/DKIM/DMARC.
    """
    # headers in your parser are lower-cased keys; handle both just in case
    values = headers.get("authentication-results") or headers.get("Authentication-Results") or []

    spf = "unknown"
    dkim = "unknown"
    dmarc = "unknown"

    raw = list(values)

    def set_if_unknown(current: str, new: str, allowed: set[str]) -> str:
        if current != "unknown":
            return current
        new = new.lower()
        return new if new in allowed else current

    for v in values:
        if not v:
            continue

        m = _STATUS_RE["spf"].search(v)
        if m:
            spf = set_if_unknown(spf, m.group(1), _ALLOWED_SPF)

        m = _STATUS_RE["dkim"].search(v)
        if m:
            dkim = set_if_unknown(dkim, m.group(1), _ALLOWED_DKIM_DMARC)

        m = _STATUS_RE["dmarc"].search(v)
        if m:
            dmarc = set_if_unknown(dmarc, m.group(1), _ALLOWED_DKIM_DMARC)

        # If we have all, stop early
        if spf != "unknown" and dkim != "unknown" and dmarc != "unknown":
            break

    return AuthSummary(spf=spf, dkim=dkim, dmarc=dmarc, raw=raw)


# -----------------------------
# 2) Link mismatch detection
# -----------------------------

# Extract anchors: href + visible text
_ANCHOR_RE = re.compile(
    r'(?is)<a\b[^>]*\bhref\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([^\s>]+))[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)

# Strip tags from visible text
_TAG_RE = re.compile(r"(?is)<[^>]+>")


def detect_link_mismatch(html_text: str) -> List[Flag]:
    """
    Detect when visible anchor text domain differs from href domain.

    We flag when:
    - href points to a URL with a hostname
    - visible text contains something that looks like a domain or URL
    - registrable domains differ (eTLD+1 mismatch)
    """
    if not html_text:
        return []

    flags: List[Flag] = []

    for m in _ANCHOR_RE.finditer(html_text):
        href_raw = m.group(1) or m.group(2) or m.group(3) or ""
        visible_raw = m.group(4) or ""

        href_norm = _normalize_url_for_parsing(href_raw) or href_raw.strip()

        parsed = urlparse(href_norm)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            continue
        href_reg = _registrable_domain(parsed.hostname)

        # Visible text: remove tags, collapse whitespace
        visible = _TAG_RE.sub(" ", visible_raw)
        visible = re.sub(r"\s+", " ", visible).strip()

        if not visible:
            continue

        # Try to find a domain-like token inside visible text
        visible_token = ""
        # First: visible might be a full URL
        vurl = _normalize_url_for_parsing(visible) or visible.strip()
        if vurl:
            vparsed = urlparse(vurl)
            if vparsed.scheme.lower() in {"http", "https"} and vparsed.hostname:
                visible_token = _registrable_domain(vparsed.hostname)
        else:
            # Otherwise scan tokens for domain-looking values
            for tok in re.split(r"\s+", visible):
                if _looks_like_domain_token(tok):
                    # normalize defang in token too
                    t = tok
                    for pat, repl in _DEFANG_FIXES:
                        t = pat.sub(repl, t)
                    t = t.strip().strip("<>\"'").strip(".,;:!?)\"])'}")
                    # If it's still URL-ish, parse; else treat token as hostname
                    turl = _normalize_url_for_parsing(t)
                    if turl:
                        tp = urlparse(turl)
                        if tp.hostname:
                            visible_token = _registrable_domain(tp.hostname)
                            break
                    else:
                        # treat token as host
                        visible_token = _registrable_domain(t)
                        break

        if not visible_token:
            continue

        if visible_token and href_reg and visible_token != href_reg:
            flags.append(
                Flag(
                    id="LINK_MISMATCH",
                    severity="high",
                    message="Visible link text domain differs from actual href domain",
                    evidence={
                        "visible_domain": visible_token,
                        "href_domain": href_reg,
                        "href": href_norm,
                        "visible_text": visible[:200],
                    },
                )
            )

    return flags


# -----------------------------
# 3) Risk scoring
# -----------------------------

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd", "cutt.ly",
    "rebrand.ly", "lnkd.in",
}


def compute_risk_score(
    urls: List[UrlFinding],
    domains: List[DomainCount],
    auth_summary: AuthSummary,
    flags: List[Flag],
) -> tuple[int, List[Flag]]:
    """
    Compute a simple rule-based risk score (0-100) with explainable flags.
    This is NOT a definitive verdict; it's a triage prioritization score.
    """
    score = 0
    added: List[Flag] = []

    def add(points: int, fid: str, severity: str, message: str, evidence: dict) -> None:
        nonlocal score
        if points <= 0:
            return
        score += points
        added.append(
            Flag(
                id=fid,
                severity=severity,
                message=message,
                evidence={"points": points, **evidence},
            )
        )

    # --- Auth results weighting ---
    # DMARC failure is generally strongest signal, then SPF/DKIM.
    if auth_summary.dmarc == "fail":
        add(25, "AUTH_DMARC_FAIL", "high", "DMARC reported as fail", {"dmarc": auth_summary.dmarc})
    elif auth_summary.dmarc in {"none", "unknown"}:
        add(5, "AUTH_DMARC_MISSING", "low", "DMARC result missing/unknown", {"dmarc": auth_summary.dmarc})

    if auth_summary.spf == "fail":
        add(15, "AUTH_SPF_FAIL", "med", "SPF reported as fail", {"spf": auth_summary.spf})
    elif auth_summary.spf in {"softfail", "neutral", "none", "unknown"}:
        add(5, "AUTH_SPF_WEAK", "low", "SPF result weak/missing/unknown", {"spf": auth_summary.spf})

    if auth_summary.dkim == "fail":
        add(15, "AUTH_DKIM_FAIL", "med", "DKIM reported as fail", {"dkim": auth_summary.dkim})
    elif auth_summary.dkim in {"none", "unknown"}:
        add(5, "AUTH_DKIM_MISSING", "low", "DKIM result missing/unknown", {"dkim": auth_summary.dkim})

    # --- Existing detection flags weighting ---
    # If you already have LINK_MISMATCH etc., amplify the score.
    for f in flags:
        if f.id == "LINK_MISMATCH":
            add(30, "SCORE_LINK_MISMATCH", "high", "Link mismatch detected", {"evidence": f.evidence})
            break  # one is enough to bump significantly

    # --- URL / domain heuristics ---
    url_count = len(urls)
    unique_domains = len({d.domain for d in domains})

    if url_count >= 6:
        add(10, "MANY_URLS", "med", "Email contains many URLs", {"url_count": url_count})
    elif url_count >= 3:
        add(5, "MULTIPLE_URLS", "low", "Email contains multiple URLs", {"url_count": url_count})

    if unique_domains >= 4:
        add(10, "MANY_DOMAINS", "med", "Email contains many unique domains", {"unique_domains": unique_domains})
    elif unique_domains >= 2:
        add(5, "MULTIPLE_DOMAINS", "low", "Email contains multiple domains", {"unique_domains": unique_domains})

    # Check for IP-host URLs or URL shorteners
    for u in urls:
        norm = _normalize_url_for_parsing(u.url) or u.url
        p = urlparse(norm)
        host = (p.hostname or "").lower().strip("[]")
        if not host:
            continue

        # IP in URL host
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            add(20, "IP_IN_URL", "high", "URL uses an IP address instead of a domain", {"url": u.url})
            break

        # Common shorteners
        if _registrable_domain(host) in _SHORTENERS or host in _SHORTENERS:
            add(10, "URL_SHORTENER", "med", "URL uses a common shortener", {"url": u.url, "host": host})
            break

        # Suspicious userinfo "user:pass@" pattern (rare but used in obfuscation)
        # urlparse doesn't expose userinfo directly; check raw netloc for '@'
        if p.netloc and "@" in p.netloc:
            add(10, "URL_USERINFO", "med", "URL contains userinfo (user:pass@host) which can be used to obfuscate", {"url": u.url})
            break

        # Punycode / IDN indicator
        if "xn--" in host:
            add(10, "PUNYCODE_DOMAIN", "med", "Punycode domain detected (possible lookalike)", {"host": host, "url": u.url})
            break

    # Clamp score
    score = max(0, min(100, score))
    return score, added



"""Analysis functions for detecting phishing indicators.

This module contains TODO stubs that must be implemented.
All functions should raise NotImplementedError until implemented.
"""

from typing import Dict, List

from .models import AuthSummary, DomainCount, Flag, UrlFinding


def parse_authentication_results(headers: Dict[str, List[str]]) -> AuthSummary:
    """
    Parse Authentication-Results headers to extract SPF, DKIM, and DMARC statuses.

    The Authentication-Results header format is complex and may appear multiple times.
    This function should parse all occurrences and extract the final statuses.

    Expected status values:
    - SPF: pass|fail|none|permerror|temperror|neutral|softfail|unknown
    - DKIM: pass|fail|none|permerror|temperror|neutral|unknown
    - DMARC: pass|fail|none|permerror|temperror|neutral|unknown

    Args:
        headers: Dictionary mapping header names to lists of values

    Returns:
        AuthSummary with parsed statuses and raw header values

    Raises:
        NotImplementedError: This function must be implemented
    """
    raise NotImplementedError(
        "parse_authentication_results must be implemented. "
        "Parse Authentication-Results headers to extract SPF, DKIM, and DMARC statuses."
    )


def detect_link_mismatch(html_text: str) -> List[Flag]:
    """
    Detect when visible anchor text domain differs from href domain.

    This is a common phishing technique where the visible link text shows
    a legitimate domain (e.g., "bank.com") but the href points to a malicious
    domain (e.g., "evil.com").

    Args:
        html_text: The HTML content of the email body

    Returns:
        List of Flag objects indicating link mismatches

    Raises:
        NotImplementedError: This function must be implemented
    """
    raise NotImplementedError(
        "detect_link_mismatch must be implemented. "
        "Compare visible anchor text domains with href domains and flag mismatches."
    )


def compute_risk_score(
    urls: List[UrlFinding],
    domains: List[DomainCount],
    auth_summary: AuthSummary,
    flags: List[Flag],
) -> tuple[int, List[Flag]]:
    """
    Compute a risk score (0-100) based on various indicators.

    This should be a rule-based scoring system that considers:
    - Number and types of URLs
    - Domain reputation/patterns
    - Authentication results (SPF/DKIM/DMARC failures)
    - Detection flags (link mismatches, defanged URLs, etc.)

    The scoring should be explainable - each contributing factor should
    generate a Flag explaining why the score increased.

    Args:
        urls: List of extracted URLs
        domains: List of domain counts
        auth_summary: Authentication results
        flags: Existing detection flags

    Returns:
        Tuple of (risk_score: int, additional_flags: List[Flag])
        The additional_flags should explain the scoring decisions

    Raises:
        NotImplementedError: This function must be implemented
    """
    raise NotImplementedError(
        "compute_risk_score must be implemented. "
        "Implement rule-based scoring (0-100) considering URLs, domains, "
        "authentication results, and flags. Return explainable flags for scoring decisions."
    )



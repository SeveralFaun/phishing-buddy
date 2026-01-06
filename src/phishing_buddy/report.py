"""Report generation orchestrator."""

import warnings
from datetime import datetime, timezone
from typing import Dict, Optional

from .analyze import (
    compute_risk_score,
    detect_link_mismatch,
    parse_authentication_results,
)
from .eml_parser import extract_body_parts, extract_headers, get_key_headers, parse_eml_file
from .extract import extract_domains, extract_urls_from_headers, extract_urls_from_text
from .models import AuthSummary, Flag, Report, UrlFinding


def build_report(
    file_path: str, include_raw_preview: bool = False, raw_preview_length: int = 200
) -> Report:
    """
    Build a complete triage report from an EML file.

    This orchestrates the parsing, extraction, and analysis pipeline.
    If any TODO functions raise NotImplementedError, the report will still
    be generated with partial data and warning flags.

    Args:
        file_path: Path to the .eml file
        include_raw_preview: Whether to include raw text/html previews
        raw_preview_length: Maximum length of raw preview snippets

    Returns:
        Complete Report object
    """
    # Parse the EML file
    msg, _ = parse_eml_file(file_path)

    # Extract headers
    headers = extract_headers(msg)
    key_headers = get_key_headers(msg)

    # Extract body parts
    text_plain, text_html = extract_body_parts(msg)

    # Initialize collections
    urls: list[UrlFinding] = []
    domains: list = []
    flags: list[Flag] = []
    auth_summary = AuthSummary(spf="unknown", dkim="unknown", dmarc="unknown", raw=[])

    # Extract URLs from headers
    try:
        header_urls = extract_urls_from_headers(headers)
        urls.extend(header_urls)
    except NotImplementedError:
        flags.append(
            Flag(
                id="MISSING_EXTRACTION",
                severity="low",
                message="URL extraction from headers not implemented",
                evidence={"component": "extract_urls_from_headers"},
            )
        )

    # Extract URLs from body text
    if text_plain:
        try:
            plain_urls = extract_urls_from_text(text_plain, "body:text/plain")
            urls.extend(plain_urls)
        except NotImplementedError:
            flags.append(
                Flag(
                    id="MISSING_EXTRACTION",
                    severity="low",
                    message="URL extraction from plain text not implemented",
                    evidence={"component": "extract_urls_from_text"},
                )
            )

    if text_html:
        try:
            html_urls = extract_urls_from_text(text_html, "body:text/html")
            urls.extend(html_urls)
        except NotImplementedError:
            flags.append(
                Flag(
                    id="MISSING_EXTRACTION",
                    severity="low",
                    message="URL extraction from HTML not implemented",
                    evidence={"component": "extract_urls_from_text"},
                )
            )

    # Extract domains
    try:
        domains = extract_domains(urls)
    except NotImplementedError:
        flags.append(
            Flag(
                id="MISSING_EXTRACTION",
                severity="low",
                message="Domain extraction not implemented",
                evidence={"component": "extract_domains"},
            )
        )

    # Parse authentication results
    try:
        auth_summary = parse_authentication_results(headers)
    except NotImplementedError:
        flags.append(
            Flag(
                id="MISSING_ANALYSIS",
                severity="low",
                message="Authentication results parsing not implemented",
                evidence={"component": "parse_authentication_results"},
            )
        )

    # Detect link mismatches
    if text_html:
        try:
            mismatch_flags = detect_link_mismatch(text_html)
            flags.extend(mismatch_flags)
        except NotImplementedError:
            flags.append(
                Flag(
                    id="MISSING_ANALYSIS",
                    severity="low",
                    message="Link mismatch detection not implemented",
                    evidence={"component": "detect_link_mismatch"},
                )
            )

    # Compute risk score
    risk_score = 0
    try:
        score, score_flags = compute_risk_score(urls, domains, auth_summary, flags)
        risk_score = score
        flags.extend(score_flags)
    except NotImplementedError:
        flags.append(
            Flag(
                id="MISSING_ANALYSIS",
                severity="low",
                message="Risk scoring not implemented",
                evidence={"component": "compute_risk_score"},
            )
        )

    # Build raw preview if requested
    raw_preview: Optional[Dict[str, str]] = None
    if include_raw_preview:
        raw_preview = {}
        if text_plain:
            raw_preview["text/plain"] = text_plain[:raw_preview_length]
        if text_html:
            raw_preview["text/html"] = text_html[:raw_preview_length]

    # Generate timestamp
    timestamp_utc = datetime.now(timezone.utc).isoformat()

    return Report(
        source_file=file_path,
        timestamp_utc=timestamp_utc,
        headers=headers,
        key_headers=key_headers,
        auth_summary=auth_summary,
        urls=urls,
        domains=domains,
        flags=flags,
        risk_score=risk_score,
        raw_preview=raw_preview,
    )



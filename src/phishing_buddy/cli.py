"""Command-line interface for phishing-buddy."""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .report import build_report


def format_summary(report, max_urls: int = 20) -> str:
    """
    Format a human-friendly summary of the report.

    Args:
        report: Report object
        max_urls: Maximum number of URLs to display

    Returns:
        Formatted summary string
    """
    lines = []
    lines.append("=" * 70)
    lines.append("PHISHING EMAIL TRIAGE REPORT")
    lines.append("=" * 70)
    lines.append(f"Source: {report.source_file}")
    lines.append(f"Timestamp: {report.timestamp_utc}")
    lines.append("")

    # Key headers
    lines.append("KEY HEADERS:")
    for key, value in report.key_headers.items():
        if value:
            lines.append(f"  {key}: {value}")
    lines.append("")

    # Authentication summary
    lines.append("AUTHENTICATION:")
    lines.append(f"  SPF:   {report.auth_summary.spf}")
    lines.append(f"  DKIM:  {report.auth_summary.dkim}")
    lines.append(f"  DMARC: {report.auth_summary.dmarc}")
    lines.append("")

    # URLs
    lines.append(f"URLS ({len(report.urls)} found):")
    for i, url_finding in enumerate(report.urls[:max_urls], 1):
        lines.append(f"  {i}. {url_finding.url}")
        lines.append(f"     Source: {url_finding.source}")
        if url_finding.context:
            lines.append(f"     Context: {url_finding.context[:100]}...")
    if len(report.urls) > max_urls:
        lines.append(f"  ... and {len(report.urls) - max_urls} more")
    lines.append("")

    # Domains
    lines.append(f"DOMAINS ({len(report.domains)} unique):")
    for domain_count in report.domains[:10]:
        lines.append(f"  {domain_count.domain}: {domain_count.count} occurrence(s)")
    if len(report.domains) > 10:
        lines.append(f"  ... and {len(report.domains) - 10} more")
    lines.append("")

    # Flags
    if report.flags:
        lines.append(f"FLAGS ({len(report.flags)} detected):")
        for flag in report.flags:
            lines.append(f"  [{flag.severity.upper()}] {flag.id}: {flag.message}")
    else:
        lines.append("FLAGS: None detected")
    lines.append("")

    # Risk score
    lines.append(f"RISK SCORE: {report.risk_score}/100")
    lines.append("=" * 70)

    return "\n".join(lines)


def report_to_dict(report) -> dict:
    """
    Convert Report object to dictionary for JSON serialization.

    Args:
        report: Report object

    Returns:
        Dictionary representation
    """
    return {
        "source_file": report.source_file,
        "timestamp_utc": report.timestamp_utc,
        "headers": report.headers,
        "key_headers": report.key_headers,
        "auth_summary": {
            "spf": report.auth_summary.spf,
            "dkim": report.auth_summary.dkim,
            "dmarc": report.auth_summary.dmarc,
            "raw": report.auth_summary.raw,
        },
        "urls": [
            {
                "url": u.url,
                "source": u.source,
                "context": u.context,
            }
            for u in report.urls
        ],
        "domains": [{"domain": d.domain, "count": d.count} for d in report.domains],
        "flags": [
            {
                "id": f.id,
                "severity": f.severity,
                "message": f.message,
                "evidence": f.evidence,
            }
            for f in report.flags
        ],
        "risk_score": report.risk_score,
        "raw_preview": report.raw_preview,
    }


def main() -> int:
    """
    Main CLI entry point.

    Returns:
        Exit code: 0 for success, 2 for file not found/invalid input, 3 for parse error
    """
    parser = argparse.ArgumentParser(
        description="Phishing email triage tool",
        prog="phishing-buddy",
    )
    parser.add_argument(
        "eml_file",
        type=str,
        help="Path to the .eml file to analyze",
    )
    parser.add_argument(
        "--out",
        type=str,
        help="Write JSON output to file (default: stdout)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a human-friendly summary to stdout",
    )
    parser.add_argument(
        "--max-urls",
        type=int,
        default=20,
        help="Cap displayed URLs in summary mode (default: 20)",
    )
    parser.add_argument(
        "--include-raw",
        action="store_true",
        help="Include a small raw preview of text/plain and text/html (first N chars)",
    )

    args = parser.parse_args()

    # Validate input file
    eml_path = Path(args.eml_file)
    if not eml_path.exists():
        print(f"Error: File not found: {args.eml_file}", file=sys.stderr)
        return 2

    if not eml_path.is_file():
        print(f"Error: Not a file: {args.eml_file}", file=sys.stderr)
        return 2

    # Build report
    try:
        report = build_report(
            str(eml_path),
            include_raw_preview=args.include_raw,
            raw_preview_length=200,
        )
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"Error: Parse error - {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"Error: Unexpected error - {e}", file=sys.stderr)
        return 3

    # Generate JSON output
    json_data = report_to_dict(report)
    json_output = json.dumps(json_data, indent=2 if args.pretty else None)

    # Output handling
    if args.out:
        # Write to file
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(json_output)
        except Exception as e:
            print(f"Error: Failed to write output file: {e}", file=sys.stderr)
            return 3
    else:
        # Write to stdout
        print(json_output)

    # Print summary if requested
    if args.summary:
        summary = format_summary(report, max_urls=args.max_urls)
        print("\n" + summary, file=sys.stderr if args.out else sys.stdout)

    return 0


if __name__ == "__main__":
    sys.exit(main())



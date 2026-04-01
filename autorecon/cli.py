"""AutoReconAI command-line interface.

Usage:
    autorecon <scan.xml> [options]
    autorecon --help

Examples:
    # Analyse an Nmap XML file and print results to the console
    autorecon scan.xml

    # Output results as JSON
    autorecon scan.xml --format json

    # Analyse a specific file and save results
    autorecon scan.xml --format json --output results.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from autorecon.ai.analyzer import AIAnalyzer
from autorecon.parser.nmap_parser import NmapParser
from autorecon.recommender.exploit_mapper import ExploitMapper

# ---------------------------------------------------------------------------
# Severity colour codes (ANSI)
# ---------------------------------------------------------------------------
_RESET = "\033[0m"
_BOLD = "\033[1m"
_COLOURS = {
    "critical": "\033[91m",  # bright red
    "high": "\033[93m",      # yellow
    "medium": "\033[94m",    # blue
    "low": "\033[92m",       # green
}


def _colour(text: str, severity: str, use_colour: bool = True) -> str:
    if not use_colour:
        return text
    code = _COLOURS.get(severity.lower(), "")
    return f"{code}{text}{_RESET}" if code else text


def _print_report_text(report, use_colour: bool = True) -> None:  # type: ignore[no-untyped-def]
    """Print the analysis report in human-readable text format."""
    bold = _BOLD if use_colour else ""
    reset = _RESET if use_colour else ""

    print(f"\n{bold}{'=' * 60}{reset}")
    print(f"{bold}  AutoReconAI – Scan Analysis Report{reset}")
    print(f"{bold}{'=' * 60}{reset}\n")

    # Hosts overview
    print(f"{bold}Discovered Hosts:{reset}")
    for host in report.hosts:
        hostname_part = f" ({host.hostname})" if host.hostname else ""
        os_part = f" [{host.os_matches[0]}]" if host.os_matches else ""
        print(f"  • {host.ip}{hostname_part}{os_part}")
        for svc in host.open_services:
            print(f"      {svc.port}/{svc.protocol}  {svc.name:<15}  {svc.version_string}")
    print()

    # Priority findings
    if report.priority_findings:
        print(f"{bold}Priority Findings:{reset}")
        for finding in report.priority_findings:
            # Extract severity from the finding string "[SEVERITY]"
            sev = "high"
            if finding.startswith("[CRITICAL]"):
                sev = "critical"
            elif finding.startswith("[HIGH]"):
                sev = "high"
            elif finding.startswith("[MEDIUM]"):
                sev = "medium"
            elif finding.startswith("[LOW]"):
                sev = "low"
            print(f"  {_colour(finding, sev, use_colour)}")
        print()

    # All vulnerability matches
    if report.matches:
        print(f"{bold}All Vulnerability Matches ({len(report.matches)}):{reset}")
        for match in report.matches:
            sev = match.vuln.severity.lower()
            label = _colour(f"[{match.vuln.severity.upper()}]", sev, use_colour)
            print(
                f"  {label} {match.host_ip}:{match.port}  {match.vuln.cve}  {match.vuln.description[:70]}"
            )
            if match.vuln.exploit_refs:
                for ref in match.vuln.exploit_refs[:2]:
                    print(f"         → {ref}")
        print()
    else:
        print("  No vulnerability matches found.\n")

    # Remediation
    if report.remediation_suggestions:
        print(f"{bold}Remediation Suggestions:{reset}")
        for i, suggestion in enumerate(report.remediation_suggestions, start=1):
            print(f"  {i}. {suggestion}")
        print()

    # Summary
    print(f"{bold}Summary:{reset}")
    risk_colour = _colour(report.risk_level.upper(), report.risk_level, use_colour)
    print(f"  Risk level : {risk_colour}")
    print(f"  Score      : {report.attack_surface_score}")
    print(f"  {report.summary}")
    print()


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    p = argparse.ArgumentParser(
        prog="autorecon",
        description="AutoReconAI – AI-powered reconnaissance and exploit suggestion tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("scan_file", help="Path to Nmap XML scan output file")
    p.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--output",
        metavar="FILE",
        help="Write results to FILE instead of stdout",
    )
    p.add_argument(
        "--no-colour",
        action="store_true",
        default=False,
        help="Disable ANSI colour output",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose output",
    )
    return p


def run(args: argparse.Namespace | None = None) -> int:
    """Main entry point for the CLI.

    Returns:
        Exit code (0 = success, 1 = error).
    """
    parser = build_parser()
    ns = parser.parse_args(args)  # type: ignore[arg-type]

    scan_path = Path(ns.scan_file)
    use_colour = not ns.no_colour and sys.stdout.isatty()

    # Parse
    try:
        hosts = NmapParser().parse_file(scan_path)
    except FileNotFoundError:
        print(f"Error: file not found – {scan_path}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not hosts:
        print("No hosts found in scan output.", file=sys.stderr)
        return 0

    # Recommend exploits
    matches = ExploitMapper().map_hosts(hosts)

    # AI analysis
    report = AIAnalyzer(verbose=ns.verbose).analyze(hosts, matches)

    # Output
    if ns.format == "json":
        output_text = json.dumps(report.to_dict(), indent=2)
    else:
        if ns.output:
            # When writing to a file, disable colour
            use_colour = False
        import io
        buf = io.StringIO()
        _orig_stdout = sys.stdout
        sys.stdout = buf
        _print_report_text(report, use_colour=use_colour)
        sys.stdout = _orig_stdout
        output_text = buf.getvalue()

    if ns.output:
        output_path = Path(ns.output)
        output_path.write_text(output_text, encoding="utf-8")
        print(f"Results written to {output_path}")
    else:
        print(output_text, end="")

    return 0


def main() -> None:  # pragma: no cover
    """Console script entry point."""
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()

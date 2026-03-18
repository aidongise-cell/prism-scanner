"""Prism Scanner CLI — colored terminal output with rich."""
import argparse
import json
import sys
import time
from pathlib import Path

from .models import ScanTarget, ScanResult, Severity
from .scanner import PrismScanner
from .fetcher import fetch_target, cleanup_temp
from .report import generate_html_report

VERSION = "0.1.1"

# Severity colors/symbols for terminal
SEVERITY_STYLE = {
    Severity.CRITICAL: ("bold red", "\u2717"),
    Severity.HIGH: ("red", "\u2717"),
    Severity.MEDIUM: ("yellow", "\u26a0"),
    Severity.LOW: ("dim", "\u00b7"),
    Severity.INFO: ("dim", "\u2139"),
}


def main():
    parser = argparse.ArgumentParser(
        prog="prism",
        description="Prism Scanner \u2014 Agent security scanner for Skills, Plugins, and MCP Servers",
    )
    parser.add_argument("--version", action="version", version=f"Prism Scanner v{VERSION}")

    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a skill/plugin for security risks")
    scan_parser.add_argument("target", help="Path or URL to scan")
    scan_parser.add_argument("--platform", choices=["clawhub", "mcp", "npm", "pip"], help="Target platform")
    scan_parser.add_argument("--format", dest="output_format", choices=["cli", "json", "sarif", "html"],
                             default="cli", help="Output format")
    scan_parser.add_argument("-o", "--output", dest="output_file", help="Write report to file instead of stdout")
    scan_parser.add_argument("--fail-on", dest="fail_on", choices=["critical", "high", "medium"],
                             help="Exit with code 1 if findings at this level or above")
    scan_parser.add_argument("--engine", help="Comma-separated engines to run (ast,pattern,manifest)")
    scan_parser.add_argument("--show-trace", action="store_true", help="Show data flow evidence")
    scan_parser.add_argument("--summary", action="store_true", help="Show only summary")
    scan_parser.add_argument("--verbose", action="store_true", help="Show all severity levels including INFO")
    scan_parser.add_argument("--offline", action="store_true", help="Skip external lookups")

    # clean command
    clean_parser = subparsers.add_parser("clean", help="Scan/clean system for agent residue")
    clean_parser.add_argument("--scan", action="store_true", help="Only report residue")
    clean_parser.add_argument("--plan", action="store_true", help="Generate cleanup plan without executing")
    clean_parser.add_argument("--apply", action="store_true", help="Execute cleanup plan with backups")
    clean_parser.add_argument("--rollback", metavar="ID", help="Rollback a previous cleanup by backup ID")
    clean_parser.add_argument("--yes", action="store_true", help="Skip interactive confirmation (use with --apply)")
    clean_parser.add_argument("--format", dest="output_format", choices=["cli", "json"], default="cli")

    args = parser.parse_args()

    if args.command == "scan":
        _run_scan(args)
    elif args.command == "clean":
        _run_clean(args)
    else:
        parser.print_help()
        sys.exit(0)


def _run_scan(args):
    try:
        fetch_result = fetch_target(args.target)
    except (ValueError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        target = ScanTarget(
            path=fetch_result.local_path,
            platform=args.platform or fetch_result.platform,
            url=fetch_result.url,
        )

        engines = args.engine.split(",") if args.engine else None
        scanner = PrismScanner(engines=engines, offline=args.offline)
        result = scanner.scan(target)

        if args.output_format == "json":
            output = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
        elif args.output_format == "sarif":
            output = json.dumps(_to_sarif(result), indent=2)
        elif args.output_format == "html":
            output = generate_html_report(result)
        else:
            output = None
            _print_cli_report(result, show_trace=args.show_trace,
                              summary_only=args.summary, verbose=args.verbose)

        if output is not None:
            if args.output_file:
                Path(args.output_file).write_text(output, encoding="utf-8")
                print(f"Report written to {args.output_file}", file=sys.stderr)
            else:
                print(output)

        # Exit code
        if args.fail_on:
            threshold = {"critical": 0, "high": 1, "medium": 2}
            severity_rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}
            threshold_val = threshold[args.fail_on]
            for f in result.active_findings:
                rank = severity_rank.get(f.severity, 99)
                if rank <= threshold_val:
                    sys.exit(1)
    finally:
        cleanup_temp(fetch_result)


def _run_clean(args):
    from .engines.residue_engine import ResidueEngine
    from .cleaner import generate_plan, print_plan, execute_plan, rollback

    # Handle --rollback separately (no scan needed)
    if args.rollback:
        _print_header()
        rollback(args.rollback)
        return

    engine = ResidueEngine()
    findings = engine.scan_system()

    if args.output_format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False))
        return

    # CLI output
    _print_header()
    print(f"  Scanning system for agent residue...\n")

    if not findings:
        print("  No residue found. System is clean.\n")
        return

    print(f"  Found {len(findings)} items:\n")
    for f in findings:
        style, symbol = SEVERITY_STYLE.get(f.severity, ("", "?"))
        severity_str = f.severity.value.upper().ljust(8)
        location = f.file_path or ""
        print(f"  {symbol} {severity_str}  [{f.rule_id}]  {f.title}")
        if location:
            print(f"    {location}")
        if f.remediation:
            print(f"    Fix: {f.remediation}")
        print()

    if args.plan:
        plan = generate_plan(findings)
        print_plan(plan)
        print("  To execute this plan, run: prism clean --apply")

    elif args.apply:
        plan = generate_plan(findings)
        print_plan(plan)
        print()
        execute_plan(plan, interactive=not args.yes)


def _print_header():
    print()
    print("\u2501" * 50)
    print(f"  Prism Scanner v{VERSION}")
    print("\u2501" * 50)
    print()


def _print_cli_report(result: ScanResult, show_trace: bool = False,
                       summary_only: bool = False, verbose: bool = False):
    """Print colored CLI report."""
    _print_header()

    target_name = Path(result.target.path).name
    print(f"  Target: {target_name}")
    if result.target.platform:
        print(f"  Platform: {result.target.platform}")
    print(f"  Duration: {result.scan_duration_ms}ms")
    print()

    findings = result.active_findings
    if not verbose:
        findings = [f for f in findings if f.severity != Severity.INFO]

    # Group by layer
    behavior = [f for f in findings if f.layer.value == "behavior"]
    metadata = [f for f in findings if f.layer.value == "metadata"]
    residue = [f for f in findings if f.layer.value == "residue"]

    if not summary_only:
        if behavior:
            print("[1/3] Behavior Analysis")
            for f in sorted(behavior, key=lambda x: x.severity_score, reverse=True):
                _print_finding(f, show_trace)
            print()

        if metadata:
            print("[2/3] Metadata Analysis")
            for f in sorted(metadata, key=lambda x: x.severity_score, reverse=True):
                _print_finding(f, show_trace)
            print()

        if residue:
            print("[3/3] Residue Scan")
            for f in sorted(residue, key=lambda x: x.severity_score, reverse=True):
                _print_finding(f, show_trace)
            print()

    # Summary
    from .scoring import GRADE_INFO
    print("\u2501" * 50)
    grade_label = GRADE_INFO.get(result.grade, {}).get("label", result.grade)
    recommendation = GRADE_INFO.get(result.grade, {}).get("recommendation", "")
    print(f"  Grade: {result.grade} ({grade_label})")
    print()

    if result.key_risks:
        print("  Key Risks:")
        for r in result.key_risks:
            print(f"    \u25b8 {r}")
        print()

    if result.behavior_tags:
        print("  Behavior Profile:")
        print(f"    {', '.join(result.behavior_tags)}")
        print()

    print(f"  Recommendation: {recommendation}")

    # Counts
    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    if counts:
        parts = [f"{v} {k}" for k, v in sorted(counts.items())]
        print(f"\n  Findings: {', '.join(parts)}")

    print()
    if not show_trace:
        print("  Use --show-trace for data flow evidence")
    print("  Use --format json for machine-readable output")
    print("\u2501" * 50)
    print()


def _print_finding(f, show_trace: bool = False):
    """Print a single finding."""
    symbol = SEVERITY_STYLE.get(f.severity, ("", "?"))[1]
    sev = f.severity.value.upper().ljust(8)
    location = ""
    if f.file_path:
        location = f"  {f.file_path}"
        if f.line:
            location += f":{f.line}"

    print(f"  {symbol} {sev}  {f.rule_id.ljust(4)}  {f.title}{location}")

    if show_trace and f.evidence:
        print(f"           Evidence: {f.evidence}")


def _to_sarif(result: ScanResult) -> dict:
    """Convert scan results to SARIF format."""
    runs = []
    rules = {}
    results_list = []

    for f in result.active_findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"},
            }

        sarif_result = {
            "ruleId": f.rule_id,
            "level": "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
            "message": {"text": f.description},
        }
        if f.file_path:
            sarif_result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.line or 1},
                }
            }]
        results_list.append(sarif_result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Prism Scanner",
                    "version": VERSION,
                    "rules": list(rules.values()),
                }
            },
            "results": results_list,
        }],
    }

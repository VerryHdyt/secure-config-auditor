"""Command line interface."""
import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .auditor import run_audit

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-config-auditor",
        description="Read-only Linux filesystem and SSH configuration auditor."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    audit = sub.add_parser("audit", help="run security checks")
    audit.add_argument("--paths", nargs="+", default=None, help="additional filesystem roots to scan")
    audit.add_argument("--format", choices=("text", "json"), default="text")
    audit.add_argument("--output", help="write report to a file instead of stdout")
    audit.add_argument("--min-severity", choices=("HIGH", "MEDIUM", "LOW", "INFO"), default="INFO")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "audit":
        parser.print_help()
        return 0

    findings = run_audit(args.paths)
    threshold = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 99) <= threshold]

    if args.format == "json":
        rendered = json.dumps({
            "tool": "secure-config-auditor",
            "version": __version__,
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }, indent=2)
    else:
        lines = [f"Secure Config Auditor v{__version__}", f"Findings: {len(findings)}", ""]
        for item in findings:
            lines.extend([
                f"[{item.severity}] {item.check_id} - {item.title}",
                f"  Path: {item.path}",
                f"  Detail: {item.detail}",
                f"  Fix: {item.recommendation}", ""
            ])
        rendered = "\n".join(lines)

    if args.output:
        try:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write report: {exc}", file=sys.stderr)
            return 2
    else:
        print(rendered)
    return 1 if any(f.severity == "HIGH" for f in findings) else 0

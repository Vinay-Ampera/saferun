"""SafeRun command line: `saferun scan PATH`. A thin front end over `saferun.engine.validate_project`.

Exit codes (deterministic, documented in docs/cli.md):
  0   PASS      all applicable checks completed with no findings above informational
  1   FAIL      at least one high or critical finding
  2   WARNING   lower-severity findings, or the project was not fully checked (never reported as PASS)
  64  usage     invalid command line, or the path is missing / not a directory
  70  fatal     the project could not be validated at all (e.g. the safe copy failed) or an internal error
  130 interrupted
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

from .engine import ValidationOptions, ValidationReport, Verdict, validate_project
from .engine.model import CheckResult, clean_text
from .sandbox import SandboxError

EXIT_PASS, EXIT_FAIL, EXIT_WARNING, EXIT_USAGE, EXIT_FATAL, EXIT_INTERRUPTED = 0, 1, 2, 64, 70, 130
VERDICT_EXIT = {Verdict.PASS: EXIT_PASS, Verdict.FAIL: EXIT_FAIL, Verdict.WARNING: EXIT_WARNING}
MAX_TIMEOUT_S = 3600.0

OSV_NOTICE = ("note: the dependency scan sends package names and versions found in lockfiles to OSV.dev "
              "(api.osv.dev). Use --osv-offline (needs locally cached databases) or --no-dependency-scan to avoid this.")

EPILOG = """\
examples:
  saferun scan ./my-project                 human-readable report
  saferun scan ./my-project --format json   machine-readable report (schema_version 1)
  saferun scan ./my-project --osv-offline   do not contact OSV.dev
  saferun scan . --no-javascript-check --timeout 60

exit codes:
  0 PASS   1 FAIL (high/critical finding)   2 WARNING (lower-severity findings or incomplete scan)
  64 invalid usage / bad path   70 fatal error (no verdict possible)   130 interrupted

PASS means the checks that exist found nothing; it does not prove the code is safe. The project is copied
by the sandbox sanitizer first; project code is never executed on the host and dependencies are never installed.
"""


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse exits 2 by default, which here means WARNING
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _timeout(value: str) -> float:
    try:
        t = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {value!r}") from None
    if not math.isfinite(t) or not 0 < t <= MAX_TIMEOUT_S:
        raise argparse.ArgumentTypeError(f"must be greater than 0 and at most {MAX_TIMEOUT_S:g} seconds")
    return t


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="saferun", description="SafeRun: static validation of a local project, without running it.",
                epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", metavar="COMMAND", parser_class=_Parser)
    v = sub.add_parser("scan", help="validate a local project directory", description=(
        "Validate a local project directory with the SafeRun engine and print the verdict."),
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    v.add_argument("path", help="project directory to validate")
    v.add_argument("--format", choices=("text", "json"), default="text", help="output format (default: text)")
    v.add_argument("--timeout", type=_timeout, default=120.0, metavar="SECONDS",
                   help="time limit per external tool / sandbox run (default: 120)")
    v.add_argument("--osv-offline", action="store_true",
                   help="run OSV-Scanner offline: nothing is sent to OSV.dev, but cached databases are required")
    v.add_argument("--no-python-syntax", action="store_true", help="skip the sandboxed Python syntax check")
    v.add_argument("--no-python-analysis", action="store_true", help="skip Semgrep analysis of Python files")
    v.add_argument("--no-dependency-scan", action="store_true", help="skip the OSV dependency scan (no network use)")
    v.add_argument("--no-javascript-check", action="store_true", help="skip the sandboxed `node --check`")
    return p


def _s(value) -> str:
    return clean_text(value, 300)


def _location(f) -> str:
    if f.path is None:
        return "-"
    loc = _s(f.path)
    if f.line is not None:
        loc += f":{f.line}"
    return loc


def render_text(report: ValidationReport, path: str) -> str:
    out = [f"SafeRun validation of {_s(path)}", "",
           f"Verdict: {report.verdict.value}    Scan complete: {'yes' if report.complete else 'NO - see coverage gaps'}",
           "Reasons:"]
    out += [f"  - {_s(r)}" for r in report.reasons]
    out += ["", "Checks:"]
    for c in report.checks:
        extra = f" - {_s(c.detail)}" if c.detail else ""
        out.append(f"  {c.status.value:<14} {_s(c.name)}  ({len(c.findings)} finding(s)){extra}")
    findings = sorted(report.findings, key=lambda f: (-f.severity.rank, f.check, f.path or "", f.line or 0, f.rule_id))
    out += ["", f"Findings ({len(findings)}):" if findings else "Findings: none"]
    for f in findings:
        out.append(f"  [{f.severity.value.upper()}] {_s(f.rule_id)}  {_location(f)}")
        out.append(f"      {_s(f.message)}")
        if f.package:
            out.append(f"      package: {_s(f.package.name)} {_s(f.package.version)} ({_s(f.package.ecosystem)})")
        if f.fixed_versions:
            out.append(f"      fixed in: {', '.join(_s(v) for v in f.fixed_versions)}")
    gaps = _gaps(report)
    if gaps:
        out += ["", "Coverage gaps and operational problems:"] + [f"  - {g}" for g in gaps]
    out += ["", "PASS means the existing checks found nothing; it is not a proof that the code is safe."]
    return "\n".join(out) + "\n"


def _gaps(report: ValidationReport) -> list[str]:
    gaps = []
    for c in report.checks:
        if c.status.operational_problem or c.errors or c.truncated_findings:
            head = f"{_s(c.name)}: {c.status.value}" + (f" - {_s(c.detail)}" if c.detail else "")
            gaps.append(head)
            gaps += [f"    error: {_s(e)}" for e in c.errors]
            if c.truncated_findings:
                gaps.append(f"    {c.truncated_findings} further finding(s) not listed (cap reached)")
            gaps += [f"    note: {_s(n)}" for n in c.notes]
    for s in report.workspace.get("skipped", []):
        gaps.append(f"not analysed (skipped): {_s(s['path'])} ({_s(s['reason'])})")
    for w in report.workspace.get("withheld", []):
        gaps.append(f"not analysed (withheld): {_s(w['path'])} ({_s(w['reason'])})")
    return gaps


def _fail(message: str, code: int) -> int:
    print(f"saferun: error: {clean_text(message, 1000)}", file=sys.stderr)
    return code


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:  # --help -> 0; usage errors -> 64 (see _Parser.error)
        return e.code if isinstance(e.code, int) else EXIT_USAGE
    if args.command != "scan":
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    project = Path(args.path)
    if not project.exists():
        return _fail(f"path does not exist: {args.path}", EXIT_USAGE)
    if not project.is_dir():
        return _fail(f"not a directory: {args.path}", EXIT_USAGE)
    options = ValidationOptions(
        python_analysis=not args.no_python_analysis, python_syntax=not args.no_python_syntax,
        dependency_scan=not args.no_dependency_scan, javascript_check=not args.no_javascript_check,
        tool_timeout_s=args.timeout, osv_offline=args.osv_offline)
    notice = options.dependency_scan and not options.osv_offline
    if notice:
        print(OSV_NOTICE, file=sys.stderr)
    try:
        report = validate_project(project, options)
    except KeyboardInterrupt:
        return _fail("interrupted", EXIT_INTERRUPTED)
    except SandboxError as e:
        return _fail(f"cannot validate (no verdict): {e}", EXIT_FATAL)
    except Exception as e:  # noqa: BLE001 - never crash with a traceback or a misleading success code
        return _fail(f"internal error (no verdict): {type(e).__name__}: {e}", EXIT_FATAL)
    if args.format == "json":
        sys.stdout.write(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_text(report, args.path))
    return VERDICT_EXIT[report.verdict]


if __name__ == "__main__":
    sys.exit(main())

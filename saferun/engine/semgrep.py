"""Python static security analysis with Semgrep.

Invocation (argv, no shell), run on the sanitized project copy:
    semgrep scan --json --quiet --metrics=off --disable-version-check --no-git-ignore --disable-nosem --no-rewrite-rule-ids
           --config <saferun/engine/rules/python.yml> --timeout 10 --max-target-bytes 1000000
           --exclude node_modules --exclude .venv --exclude venv --exclude site-packages .
Only the bundled local rule file is used (no registry, no network, no auto config); project-supplied Semgrep
configuration is not read. `--disable-nosem` stops `# nosem` comments in untrusted code from hiding findings.
Exit codes: 0 = scan done (findings do not change it); anything else = operational error.

Coverage is verified, not assumed: Semgrep silently skips files (over --max-target-bytes, or matched by a
project-supplied .semgrepignore) without reporting an error, so every targeted Python file must appear in the
`paths.scanned` list of its JSON output; otherwise the check is INCOMPLETE. `.semgrepignore` files are also removed
from SafeRun's private copy before the scan (Semgrep has no flag to disable them), so an untrusted project cannot
use one to hide code.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .context import CheckContext
from .model import CheckResult, CheckStatus, Finding, Severity, clean_text
from .paths import rel_path
from .tools import ToolUnavailable, build_env, find_tool

NAME = "python-static-analysis"
RULES_FILE = Path(__file__).parent / "rules" / "python.yml"
EXCLUDES = ("node_modules", ".venv", "venv", "site-packages")
_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
        "info": Severity.INFO}
_SEMGREP_SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


def python_files(files: list[str]) -> list[str]:
    return [f for f in files if f.endswith((".py", ".pyi")) and not _vendored(f)]


def _vendored(rel: str) -> bool:
    return any(p in EXCLUDES for p in rel.split("/")[:-1])


def build_argv(exe: str, rules: Path = RULES_FILE) -> list[str]:
    argv = [exe, "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check", "--no-git-ignore",
            "--disable-nosem", "--no-rewrite-rule-ids", "--config", str(rules), "--timeout", "10", "--max-target-bytes", "1000000"]
    for e in EXCLUDES:
        argv += ["--exclude", e]
    return argv + ["."]


def _as_int(v) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def parse_output(text: str, root: Path) -> tuple[list[Finding], list[str], set[str] | None]:
    """Return (findings, tool-reported errors, scanned paths or None if not reported).
    Raises ValueError on anything that is not Semgrep JSON."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as e:
        raise ValueError(f"output is not valid JSON: {e}") from None
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("JSON has no 'results' list")
    findings: list[Finding] = []
    for r in data["results"]:
        if not isinstance(r, dict) or not isinstance(r.get("extra"), dict):
            raise ValueError("malformed entry in 'results'")
        extra = r["extra"]
        meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        sev = _SEV.get(str(meta.get("saferun_severity", "")).lower()) \
            or _SEMGREP_SEV.get(str(extra.get("severity", "")).upper(), Severity.UNKNOWN)
        cwe = meta.get("cwe", [])
        cwe = [cwe] if isinstance(cwe, str) else cwe if isinstance(cwe, list) else []
        start, end = r.get("start"), r.get("end")
        findings.append(Finding(
            check=NAME, rule_id=clean_text(r.get("check_id", "unknown"), 200), severity=sev,
            message=clean_text(extra.get("message", "")), category="code",
            path=rel_path(r.get("path"), root),
            line=_as_int(start.get("line")) if isinstance(start, dict) else None,
            end_line=_as_int(end.get("line")) if isinstance(end, dict) else None,
            cwe=tuple(clean_text(c, 40) for c in cwe if isinstance(c, str)),
        ))
    errs = []
    for e in data.get("errors") or []:
        if isinstance(e, dict):
            where = rel_path(e.get("path"), root) or ""
            errs.append(clean_text(f"{e.get('type', 'error')} {where}: {e.get('message') or e.get('long_msg') or ''}".strip(), 300))
        else:
            errs.append(clean_text(e, 300))
    paths = data.get("paths")
    raw = paths.get("scanned") if isinstance(paths, dict) else None
    scanned = {p for p in (rel_path(x, root) for x in raw) if p} if isinstance(raw, list) else None
    return findings, errs, scanned


def remove_ignore_files(ctx: CheckContext) -> int:
    """Delete .semgrepignore files from the private analysis copy. Returns how many were removed."""
    n = 0
    for f in ctx.files:
        if f.rsplit("/", 1)[-1] == ".semgrepignore":
            try:
                os.unlink(ctx.project / f)
                n += 1
            except OSError:
                pass   # the coverage cross-check below still catches anything Semgrep then skips
    return n


def run_check(ctx: CheckContext) -> CheckResult:
    targets = python_files(ctx.files)
    if not targets:
        return CheckResult(NAME, CheckStatus.NOT_APPLICABLE, detail="no Python files")
    exe = find_tool("semgrep")
    if not exe:
        return CheckResult(NAME, CheckStatus.UNAVAILABLE, detail="semgrep is not installed (pip install semgrep)",
                           tool="semgrep")
    if not RULES_FILE.is_file():
        return CheckResult(NAME, CheckStatus.ERROR, detail=f"bundled rule file missing: {RULES_FILE.name}", tool="semgrep")
    removed = remove_ignore_files(ctx)
    t0 = time.monotonic()
    env = build_env(ctx.home, extra={"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
                                    "SEMGREP_SETTINGS_FILE": str(ctx.home / "semgrep-settings.yml")})
    try:
        run = ctx.run(build_argv(exe), cwd=ctx.project, env=env, timeout_s=ctx.timeout_s, max_output=ctx.max_output)
    except ToolUnavailable as e:
        return CheckResult(NAME, CheckStatus.UNAVAILABLE, detail=clean_text(e), tool="semgrep")
    res = CheckResult(NAME, CheckStatus.ERROR, tool="semgrep", duration_s=time.monotonic() - t0)
    if run.timed_out:
        res.status, res.detail = CheckStatus.TIMEOUT, f"semgrep exceeded {ctx.timeout_s:g}s and was killed"
        return res
    if run.output_truncated:
        res.detail = "semgrep output exceeded the size limit and the run was killed"
        return res
    if run.exit_code != 0:
        res.detail = clean_text(f"semgrep exited with code {run.exit_code}: {run.stderr.strip()[:300]}")
        return res
    try:
        findings, errs, scanned = parse_output(run.stdout, ctx.project)
    except ValueError as e:
        res.detail = clean_text(f"semgrep output unusable: {e}")
        return res
    res.findings = findings[: ctx.max_findings]
    res.truncated_findings = max(0, len(findings) - ctx.max_findings)
    res.errors = errs
    res.notes = [f"{len(targets)} Python file(s) targeted", "rules: bundled local set (saferun/engine/rules/python.yml)"]
    if removed:
        res.notes.append(f"{removed} .semgrepignore file(s) removed from the analysis copy")
    problems = []
    if errs:
        problems.append(f"semgrep reported {len(errs)} error(s); some files were not fully analysed")
    if scanned is None:
        problems.append("semgrep did not report which files it scanned; coverage cannot be verified")
    else:
        missing = sorted(set(targets) - scanned)
        if missing:
            shown = ", ".join(clean_text(m, 80) for m in missing[:5]) + (f" and {len(missing) - 5} more" if len(missing) > 5 else "")
            problems.append(f"{len(missing)} targeted Python file(s) were not scanned by semgrep (e.g. too large): {shown}")
            res.errors = errs + [f"not scanned: {clean_text(m, 200)}" for m in missing[:50]]
    if problems:
        res.status, res.detail = CheckStatus.INCOMPLETE, "; ".join(problems)
    else:
        res.status = CheckStatus.FINDINGS if res.findings else CheckStatus.PASSED
    return res

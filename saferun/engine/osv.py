"""Dependency vulnerability scanning with OSV-Scanner (v2 CLI).

Invocation (argv, no shell), run on the sanitized project copy, one process for all files:
    osv-scanner scan source --format json --no-resolve [--offline] --lockfile=./<lockfile> ...
SafeRun never installs or fetches dependencies and never runs install scripts: OSV-Scanner only *reads* files.
It does contact the OSV.dev API (sending package names/versions, no source code) unless `osv_offline=True`
(requires locally cached databases; otherwise the tool errors and that is reported as an ERROR, not as clean).
Exit codes: 0 = no vulnerabilities, 1 = vulnerabilities found (JSON on stdout), 128 = no packages found,
anything else = error.

Terminology (verified against osv-scanner 2.7.0): a *lockfile* records resolved, exact versions; a *manifest* /
requirements file declares wanted versions. Scanned, by exact file name:
  lockfiles    - Python: poetry.lock, Pipfile.lock, pdm.lock, uv.lock; npm: package-lock.json, yarn.lock, pnpm-lock.yaml
  requirements - Python: requirements.txt ONLY. It is a manifest, not a lockfile: OSV-Scanner (which labels every
                 input "lockfile" in its JSON) reads it, but an unpinned entry such as `flask>=1.0` is evaluated as
                 the exact version 1.0 - results for it are unreliable (a note is added), and transitive
                 dependencies are not covered (--no-resolve).
Other manifests (package.json, Pipfile, pyproject.toml) and other names (requirements-dev.txt, ...) are NOT scanned;
a manifest with no scannable file beside it is reported as a coverage gap (INCOMPLETE/SKIPPED), never as clean.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from .context import CheckContext
from .model import CheckResult, CheckStatus, Finding, PackageRef, Severity, clean_text
from .paths import rel_path
from .tools import ToolUnavailable, build_env, find_tool

NAME = "dependency-vulnerabilities"
PY_LOCKFILES = ("poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock")
PY_REQUIREMENTS = ("requirements.txt",)   # a manifest, not a lockfile
NPM_LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
SUPPORTED = frozenset(PY_LOCKFILES + PY_REQUIREMENTS + NPM_LOCKFILES)
VENDORED = frozenset({"node_modules", ".venv", "venv", "site-packages", ".git"})
MAX_LOCKFILES = 50
MAX_MANIFEST_BYTES = 1024 * 1024
_NAME_OK = re.compile(r"^[A-Za-z0-9._@/+~-][A-Za-z0-9._@/ +~-]*$")


def _basename(p: str) -> str:
    return p.rsplit("/", 1)[-1]


def _dir(p: str) -> str:
    return p.rsplit("/", 1)[0] if "/" in p else ""


def discover(files: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Return (files to scan, unsafe-to-pass paths, coverage gaps). "Files to scan" are lockfiles plus requirements.txt."""
    own = [f for f in files if not any(p in VENDORED for p in f.split("/")[:-1])]
    locks = sorted(f for f in own if _basename(f) in SUPPORTED)
    unsafe = [f for f in locks if not _NAME_OK.match(f) or ":" in f]
    locks = [f for f in locks if f not in unsafe]
    present = set(own)
    gaps = []
    for f in own:
        d, b = _dir(f), _basename(f)
        sib = lambda n: (f"{d}/{n}" if d else n)  # noqa: E731
        if b == "package.json" and not any(sib(n) in present for n in NPM_LOCKFILES):
            gaps.append(f"{f}: no npm lockfile (package-lock.json/yarn.lock/pnpm-lock.yaml); dependencies not scanned")
        elif b not in SUPPORTED and re.fullmatch(r"(?i).*requirements.*\.txt", b):
            gaps.append(f"{f}: requirements-file variants are not scanned (only a file named exactly requirements.txt is)")
        elif b == "Pipfile" and sib("Pipfile.lock") not in present:
            gaps.append(f"{f}: no Pipfile.lock; dependencies not scanned")
        elif b == "pyproject.toml" and not any(sib(n) in present for n in PY_LOCKFILES):
            gaps.append(f"{f}: no Python lockfile (poetry.lock/uv.lock/pdm.lock/Pipfile.lock); dependencies declared there are not scanned"
                        + (" (a requirements.txt beside it is scanned separately)" if sib("requirements.txt") in present else ""))
    return locks, unsafe, sorted(gaps)


def build_argv(exe: str, lockfiles: list[str], offline: bool = False) -> list[str]:
    argv = [exe, "scan", "source", "--format", "json", "--no-resolve"]
    if offline:
        argv.append("--offline")
    return argv + [f"--lockfile=./{lf}" for lf in lockfiles]


def _severity(vuln: dict, score_by_id: dict[str, str]) -> Severity:
    for i in [vuln.get("id"), *(vuln.get("aliases") or [])]:
        try:
            score = float(score_by_id.get(i, ""))
        except (TypeError, ValueError):
            continue
        return (Severity.CRITICAL if score >= 9 else Severity.HIGH if score >= 7 else
                Severity.MEDIUM if score >= 4 else Severity.LOW if score > 0 else Severity.UNKNOWN)
    ds = vuln.get("database_specific")
    label = str(ds.get("severity", "")).upper() if isinstance(ds, dict) else ""
    return {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}.get(label, Severity.UNKNOWN)


def _fixed(vuln: dict, name: str) -> tuple[str, ...]:
    out: list[str] = []
    for a in vuln.get("affected") or []:
        if not isinstance(a, dict) or (isinstance(a.get("package"), dict) and a["package"].get("name") not in (None, name)):
            continue
        for r in a.get("ranges") or []:
            for ev in (r.get("events") or []) if isinstance(r, dict) else []:
                if isinstance(ev, dict) and isinstance(ev.get("fixed"), str):
                    out.append(clean_text(ev["fixed"], 60))
    return tuple(dict.fromkeys(out))


def parse_output(text: str, root: Path) -> list[Finding]:
    """Raises ValueError on anything that is not OSV-Scanner JSON."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as e:
        raise ValueError(f"output is not valid JSON: {e}") from None
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("JSON has no 'results' list")
    findings: list[Finding] = []
    for res in data["results"]:
        if not isinstance(res, dict) or not isinstance(res.get("packages", []), list):
            raise ValueError("malformed entry in 'results'")
        src = res.get("source")
        path = rel_path(src.get("path"), root) if isinstance(src, dict) else None
        for pk in res.get("packages") or []:
            info = pk.get("package") if isinstance(pk, dict) else None
            if not isinstance(info, dict) or not isinstance(info.get("name"), str) or not isinstance(pk.get("vulnerabilities", []), list):
                raise ValueError("malformed package entry")
            ref = PackageRef(clean_text(info["name"], 200), clean_text(info.get("version", ""), 100),
                             clean_text(info.get("ecosystem", ""), 50))
            score_by_id: dict[str, str] = {}
            for g in pk.get("groups") or []:
                if isinstance(g, dict) and g.get("max_severity") not in (None, ""):
                    for i in g.get("ids") or []:
                        score_by_id[str(i)] = str(g["max_severity"])
            seen: set[str] = set()
            for v in pk.get("vulnerabilities") or []:
                if not isinstance(v, dict) or not isinstance(v.get("id"), str):
                    raise ValueError("malformed vulnerability entry")
                aliases = [a for a in (v.get("aliases") or []) if isinstance(a, str)]
                ids = [v["id"], *aliases]
                if seen & set(ids):      # same vulnerability under another id: report once
                    continue
                seen.update(ids)
                summary = v.get("summary") or v.get("details") or ""
                findings.append(Finding(
                    check=NAME, rule_id=clean_text(v["id"], 100), severity=_severity(v, score_by_id),
                    message=clean_text(f"{ref.name} {ref.version}: {summary}".strip()), category="dependency",
                    path=path, package=ref, vulnerability_ids=tuple(clean_text(i, 100) for i in ids),
                    fixed_versions=_fixed(v, ref.name),
                ))
    return findings


def npm_unmatched(path: Path) -> int | None:
    """Number of package-lock.json entries OSV-Scanner counts but cannot match (verified with 2.7.0: an entry with no
    registry `resolved` URL, or one resolved from git, yields no vulnerability results and exit 0). Local `link`
    entries are ignored. None if the file cannot be read as a lockfile (OSV-Scanner then reports it)."""
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES * 20:
            return None
        data = json.loads(path.read_text("utf-8", "replace"))
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(data, dict):
        return None
    n = 0

    def bad(e) -> bool:
        return (isinstance(e, dict) and isinstance(e.get("version"), str) and not e.get("link")
                and not (isinstance(e.get("resolved"), str) and e["resolved"].startswith(("https://", "http://"))))

    pk = data.get("packages")
    if isinstance(pk, dict):
        n += sum(1 for k, e in pk.items() if k and bad(e))
    else:
        stack = [data.get("dependencies")]
        while stack:
            d = stack.pop()
            for e in (d.values() if isinstance(d, dict) else []):
                n += bad(e)
                if isinstance(e, dict):
                    stack.append(e.get("dependencies"))
    return n


_PROGRESS = ("Starting filesystem walk", "Scanned ", "End status")


def _error_lines(stderr: str) -> str:
    """The tool's progress lines hide its error; prefer the non-progress lines."""
    lines = [ln.strip() for ln in stderr.splitlines() if ln.strip() and not ln.startswith(_PROGRESS)]
    return " | ".join(lines or [stderr.strip()])[-300:]


def _unpinned_notes(ctx: CheckContext, locks: list[str]) -> list[str]:
    notes = []
    for lf in locks:
        if _basename(lf) != "requirements.txt":
            continue
        try:
            p = ctx.project / lf
            if p.stat().st_size > MAX_MANIFEST_BYTES:
                continue
            lines = [ln.split("#")[0].strip() for ln in p.read_text("utf-8", "replace").splitlines()]
        except OSError:
            continue
        loose = [ln for ln in lines if ln and not ln.startswith("-") and "==" not in ln]
        if loose:
            notes.append(f"{lf}: {len(loose)} requirement(s) not pinned with '==' (a manifest is not a lockfile): they are evaluated at their stated lower bound and results for them are unreliable")
    return notes


def run_check(ctx: CheckContext) -> CheckResult:
    locks, unsafe, gaps = discover(ctx.files)
    gaps = gaps + [f"{f}: unsupported file name for scanning; skipped" for f in unsafe]
    if not locks and not gaps:
        return CheckResult(NAME, CheckStatus.NOT_APPLICABLE, detail="no dependency files")
    if not locks:
        return CheckResult(NAME, CheckStatus.SKIPPED, tool="osv-scanner", notes=gaps,
                           detail="dependency manifests found but no scannable lockfile or requirements.txt; dependencies not scanned")
    if len(locks) > MAX_LOCKFILES:
        gaps.append(f"{len(locks) - MAX_LOCKFILES} lockfile(s) beyond the limit of {MAX_LOCKFILES} not scanned")
        locks = locks[:MAX_LOCKFILES]
    exe = find_tool("osv-scanner")
    if not exe:
        return CheckResult(NAME, CheckStatus.UNAVAILABLE, tool="osv-scanner", notes=gaps,
                           detail="osv-scanner is not installed (https://google.github.io/osv-scanner/)")
    t0 = time.monotonic()
    env = build_env(ctx.home, network=not ctx.options.get("osv_offline", False))
    try:
        run = ctx.run(build_argv(exe, locks, bool(ctx.options.get("osv_offline", False))), cwd=ctx.project, env=env,
                      timeout_s=ctx.timeout_s, max_output=ctx.max_output)
    except ToolUnavailable as e:
        return CheckResult(NAME, CheckStatus.UNAVAILABLE, detail=clean_text(e), tool="osv-scanner", notes=gaps)
    res = CheckResult(NAME, CheckStatus.ERROR, tool="osv-scanner", duration_s=time.monotonic() - t0, notes=list(gaps))
    if run.timed_out:
        res.status, res.detail = CheckStatus.TIMEOUT, f"osv-scanner exceeded {ctx.timeout_s:g}s and was killed"
        return res
    if run.output_truncated:
        res.detail = "osv-scanner output exceeded the size limit and the run was killed"
        return res
    if run.exit_code == 128:
        res.status, res.detail = CheckStatus.INCOMPLETE, "osv-scanner found no packages in the scanned file(s); nothing was scanned"
        return res
    if run.exit_code not in (0, 1):
        res.detail = clean_text(f"osv-scanner exited with code {run.exit_code}: {_error_lines(run.stderr)}")
        return res
    try:
        findings = parse_output(run.stdout, ctx.project)
    except ValueError as e:
        res.detail = clean_text(f"osv-scanner output unusable: {e}")
        return res
    if run.exit_code == 1 and not findings:
        res.detail = "osv-scanner reported vulnerabilities (exit 1) but none could be read from its output"
        return res
    res.findings = findings[: ctx.max_findings]
    res.truncated_findings = max(0, len(findings) - ctx.max_findings)
    for lf in locks:
        if _basename(lf) == "package-lock.json" and (n := npm_unmatched(ctx.project / lf)):
            gaps.append(f"{lf}: {n} package(s) without a registry URL (or from git) cannot be matched by osv-scanner")
            res.notes.append(gaps[-1])
    res.notes += [f"scanned file(s): {', '.join(locks)}", *_unpinned_notes(ctx, locks)]
    if gaps:
        res.status = CheckStatus.INCOMPLETE
        res.detail = f"{len(gaps)} dependency file(s) not scanned: " + "; ".join(gaps)[:400]
    else:
        res.status = CheckStatus.FINDINGS if res.findings else CheckStatus.PASSED
    return res

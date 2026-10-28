# Command-line reference (Phase 3)

## Install
```bash
.venv/bin/pip install -e '.[dev,analysis]'    # installs the `saferun` command; `python -m saferun` also works
```
Semgrep (`analysis` extra) and [OSV-Scanner](https://google.github.io/osv-scanner/) are optional; a missing tool makes that check `unavailable` (verdict at best WARNING).
Docker and the runtime images are required for the sandboxed syntax checks (see the README prerequisites).

## Usage
```bash
saferun scan ./my-project                 # human-readable report
saferun scan ./my-project --format json   # the Phase 2 report schema (schema_version 1), nothing else on stdout
saferun scan ./my-project --osv-offline   # nothing sent to OSV.dev (needs cached OSV databases)
saferun scan . --no-javascript-check --timeout 60
saferun --help
```
`saferun scan PATH` is a thin front end over `validate_project`: same sanitized copy, same sandbox, same checks and verdict
rules; the CLI adds no validation logic, runs no project code and installs no dependencies. Options: `--format text|json`,
`--timeout SECONDS` (per tool/sandbox run, default 120, max 3600), `--osv-offline`, `--no-python-syntax`, `--no-python-analysis`,
`--no-dependency-scan`, `--no-javascript-check`. A disabled check is reported as `skipped`, which makes the verdict at best WARNING.

**Network disclosure.** By default the dependency scan sends package names and versions from lockfiles / `requirements.txt` to
OSV.dev (`api.osv.dev`); the CLI prints a notice to stderr whenever it will do so. Use `--osv-offline` or `--no-dependency-scan` to avoid it.

| Exit code | Meaning |
|---|---|
| 0 | **PASS**: all applicable checks completed, no findings above informational |
| 1 | **FAIL**: at least one high or critical finding |
| 2 | **WARNING**: lower-severity findings, *or* the project was not fully checked (tool missing/timed out/errored, check skipped, partial copy) |
| 64 | invalid usage: bad option or value, path missing or not a directory |
| 70 | fatal: no verdict possible (e.g. the sandbox could not copy the project, internal error) |
| 130 | interrupted |

Incomplete scans never exit 0. Text output example:
```
Verdict: WARNING    Scan complete: NO - see coverage gaps
Reasons:
  - dependency-vulnerabilities: unavailable - osv-scanner not found
Checks:
  passed         python-syntax  (0 finding(s))
  unavailable    dependency-vulnerabilities  (0 finding(s)) - osv-scanner not found
Findings: none
Coverage gaps and operational problems:
  - dependency-vulnerabilities: unavailable - osv-scanner not found
```
Findings are listed most severe first as `[HIGH] rule-id  path:line`. The CLI inherits all Phase 2 limitations (host-side analyzers,
unsupported/unverified lockfile formats, no transitive resolution); PASS is not a proof that code is safe.


See [engine.md](engine.md) for the checks, statuses and verdict rules, and [PROJECT.md](../PROJECT.md) for limitations.

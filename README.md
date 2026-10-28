# SafeRun

Checks AI-generated code before you run or trust it. Executing untrusted code in a sandbox **limits the impact** of that
code; it does **not** prove the code is safe, and a passing scan does not guarantee security.
Status: **Phase 4 of 5**. Phase 1 (sandbox), Phase 2 (engine) and Phase 3 (CLI) are committed baselines, not independently certified. Phase 4 (local web dashboard) is implemented and awaiting owner review (uncommitted). **The CLI is the primary product**; the dashboard is a secondary, loopback-only demonstration interface.

## Key features
- **Restricted Docker sandbox** (Phase 1): read-only sanitized project copy, no network, non-root, no capabilities, resource limits, verified at run time.
- **Validation engine** (Phase 2): Python syntax check and `node --check` in the sandbox; Semgrep (Python) and OSV-Scanner dependency scan on the host; one normalized report and a PASS / WARNING / FAIL verdict.
- **CLI** (Phase 3): `saferun scan PATH`, text or JSON output, deterministic exit codes. Incomplete scans never report PASS.
- **Local web dashboard** (Phase 4, optional `web` extra): upload a ZIP, see verdict, check coverage and findings. Runs the same CLI as a subprocess (no separate validation code), refuses non-loopback access in code, treats archives as hostile. **Not for exposure beyond your own machine** — see [docs/api.md](docs/api.md).

## Prerequisites
Linux, Python 3.12+, a **local** Docker Engine reachable by your user (remote endpoints are refused), cgroup limits
(memory, swap, pids, CPU) and seccomp enabled in the daemon, and the runtime images pulled locally. SafeRun never pulls:
```bash
docker pull python:3.12-slim     # Python profile (required)
docker pull node:22-slim         # Node.js profile (JavaScript checks and tests)
```
Images must provide `timeout` and `sh`, and must not declare `VOLUME`.

## Install and test
```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev,analysis]'   # needs python3-venv/pip; OSV-Scanner is installed separately
.venv/bin/pytest -q                        # Docker tests skip (loudly) if Docker is missing
SAFERUN_REQUIRE_DOCKER=1 .venv/bin/pytest  # ...or fail instead of skipping (use this to prove a full run)
```

## Quick start
```bash
saferun scan ./my-project                 # human-readable report
saferun scan ./my-project --format json   # machine-readable report (schema_version 1)
saferun scan ./my-project --osv-offline   # do not contact OSV.dev
```
Exit codes: **0** PASS · **1** FAIL · **2** WARNING (including any incomplete scan) · **64** invalid usage/path · **70** fatal · **130** interrupted.

> **Privacy:** by default the dependency scan sends package names and versions from lockfiles / `requirements.txt` to OSV.dev; the CLI prints a notice on stderr when it does. Use `--osv-offline` or `--no-dependency-scan` to avoid it.

## Web dashboard (optional, local only)
```bash
.venv/bin/pip install -e '.[dev,web,analysis]' && (cd web && npm ci --ignore-scripts && npm run build)
.venv/bin/saferun-web            # http://127.0.0.1:8765/  — loopback only, refuses any other bind address
```
Host-side Semgrep/OSV-Scanner still parse uploaded files with your user's privileges; read [docs/api.md](docs/api.md) before using it.

## Supported runtimes
| Runtime | Image | Status |
|---|---|---|
| Python | `python:3.12-slim` | sandbox, syntax check and Semgrep implemented |
| JavaScript / Node.js | `node:22-slim` | sandbox, `node --check` and npm lockfile scan implemented; **dependency installation, test runners and JS Semgrep rules are not implemented** |

## Documentation
- [docs/cli.md](docs/cli.md) — CLI options, exit codes, output examples
- [docs/engine.md](docs/engine.md) — validation engine: checks, dependency coverage, statuses, verdict rules
- [docs/sandbox.md](docs/sandbox.md) — sandbox library usage and guarantees
- [docs/api.md](docs/api.md) — local web dashboard: API, ZIP handling, limits, worker environment, security notes
- [PROJECT.md](PROJECT.md) — goals, architecture, threat model, known exposures (**read before relying on the sandbox**), phases
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — status, test evidence, limitations, technical notes

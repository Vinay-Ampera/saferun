# SafeRun

Checks AI-generated code before you run or trust it. Executing untrusted code in a sandbox **limits the impact** of that
code; it does **not** prove the code is safe, and a passing scan does not guarantee security. Status: **Phase 2 of 5**
(validation engine, implemented, awaiting owner review; Phase 1 sandbox approved as the baseline, not independently certified).
No CLI or dashboard yet.
See PROJECT.md (design, threat model, OpenSandbox reuse assessment) and IMPLEMENTATION.md (status, evidence, limitations).

## Prerequisites
Linux, Python 3.12+, a **local** Docker Engine reachable by your user (remote endpoints are refused), cgroup limits
(memory, swap, pids, CPU) and seccomp enabled in the daemon, and the runtime images pulled locally. SafeRun never pulls:
```bash
docker pull python:3.12-slim     # Python profile (required)
docker pull node:22-slim         # Node.js profile (only needed for the JavaScript tests/runs)
```
Images must provide `timeout` and `sh`, and must not declare `VOLUME`.

## Setup and tests (dev)
```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'   # needs python3-venv/pip
.venv/bin/pytest -q                       # Docker tests skip (loudly) if Docker is missing
SAFERUN_REQUIRE_DOCKER=1 .venv/bin/pytest # ...or abort / fail instead of skipping (use this to prove a full run)
```
Without `node:22-slim`, the Node tests skip with a message (and fail under `SAFERUN_REQUIRE_DOCKER=1`).

## Sandbox usage (library, Phase 1)
```python
from saferun.sandbox import run_sandboxed, SandboxLimits
from saferun.sandbox.profiles import PYTHON, NODE
r = run_sandboxed("./proj", ["python", "-I", "main.py"], SandboxLimits(timeout_s=10, memory_mb=128), image=PYTHON.image)
r = run_sandboxed("./js",   ["node", "main.js"], image=NODE.image)            # same restrictions, Node image
print(r.exit_code, r.stdout, r.timed_out, r.oom_killed)
print([(c.name, c.state) for c in r.controls])   # verified / violated / unavailable / unverified, per run

from saferun.sandbox.attestation import attest
print(attest(NODE.image).ok)                      # kernel-view check from inside a sandbox (one short container run)
```
- The project is copied (symlinks and special files dropped, external hard links skipped, credential-like files withheld,
  concurrent modification detected) and mounted read-only; no network; non-root; all capabilities dropped; read-only root.
- Before any code starts, Docker's *applied* configuration is verified and the run is refused on any deviation; the daemon
  must support the required controls (seccomp, memory/swap/pids/CPU limits) unless you explicitly pass `allow_degraded`.
- `SandboxResult` reports `controls`, `image_id`, `skipped`, `withheld`, `redactions`, and honest accounting:
  `entries_scanned == copied_files + copied_dirs + len(skipped) + len(withheld)`. A non-empty `skipped`/`withheld` means
  a partial scan. `reap_orphans()` removes containers/workspaces abandoned by a crashed run.

## Validation engine (library, Phase 2)
```python
from saferun.engine import validate_project, ValidationOptions
report = validate_project("./proj", ValidationOptions(tool_timeout_s=120, osv_offline=False))
print(report.verdict.value, report.complete, report.reasons)
for c in report.checks: print(c.name, c.status.value, c.detail)
data = report.to_dict()          # stable JSON-serializable structure (schema_version 1)
```
`validate_project` copies the project with the Phase 1 sanitizer (symlinks/special files dropped, credential files withheld),
runs the checks on the **copy** (never the original directory, never project code), deletes the copy, and returns a report.

| Check | Tool | Runs where | Scope |
|---|---|---|---|
| `python-static-analysis` | Semgrep, bundled local rules ([python.yml](saferun/engine/rules/python.yml): 11 rules) | host, read-only analysis of the copy | `.py`/`.pyi` outside `node_modules`, `.venv`, `venv`, `site-packages` |
| `dependency-vulnerabilities` | OSV-Scanner v2 (`scan source --format json --no-resolve`; verified with 2.7.0) | host, reads dependency files of the copy; contacts OSV.dev unless `osv_offline=True` (then needs cached databases, else `error`) | **Lockfiles:** `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`. **Requirements file (a manifest, not a lockfile):** `requirements.txt` only |
| `python-syntax` | `compile()` (parse only, nothing imported or run) | **inside the sandbox** (`python:3.12-slim`), one run, fixed driver script | `.py`/`.pyi` (Semgrep does *not* report syntax errors, so this is separate) |
| `javascript-syntax` | `node --check` | **inside the sandbox** (`node:22-slim`), one run, fixed driver script | `.js`/`.mjs`/`.cjs` outside `node_modules` |
| `workspace-sensitive-files` | Phase 1 copy | host | withheld credential-like files become findings |

Tools are optional at install time: `pip install semgrep` (or `pip install -e '.[analysis]'`) and install
[OSV-Scanner](https://google.github.io/osv-scanner/) separately. A missing tool gives status `unavailable`, never a clean result.

**Dependency coverage, precisely.** A *lockfile* records exact resolved versions; `requirements.txt` is a *manifest*: only `==` pins are
matched reliably (`flask>=1.0` is evaluated as exactly 1.0), transitive dependencies are not covered, and `requirements-dev.txt` and other variants are not scanned.
`package.json`, `Pipfile` and `pyproject.toml` are never scanned themselves; without a scannable file beside them they are reported as a coverage gap
(`skipped`/`incomplete`, never clean). npm lockfile entries with no registry URL (or from git) cannot be matched by OSV-Scanner and make the check `incomplete`.
`yarn.lock`/`pnpm-lock.yaml` are passed to OSV-Scanner but were **not** tested with the real tool.

**Statuses** per check: `passed`, `findings`, `incomplete`, `error`, `timeout`, `unavailable`, `skipped`, `not_applicable`.
Findings are security/validity signals; `error`/`timeout`/`unavailable`/`skipped`/`incomplete` are operational and carry no findings.

**Verdict rules** (`saferun/engine/verdict.py`):
- `FAIL` — any finding of severity `critical` or `high`.
- `WARNING` — otherwise, if any finding is `medium`/`low`/`unknown`, **or** any check is `incomplete`/`error`/`timeout`/`unavailable`/`skipped`,
  **or** the copy skipped/withheld entries (partial scan), **or** no analysis check completed.
- `PASS` — at least one analysis check completed and none of the above applies. `report.complete` says whether everything applicable was fully checked.
`PASS` means "the implemented checks found nothing", not "the code is safe".

**Not implemented (deferred):** npm/pip dependency *installation* and test execution (needs a separate network-enabled step),
JavaScript test runners, Semgrep rules for JavaScript, Python syntax check, transitive resolution (requirements.txt and manifests without lockfiles),
in-sandbox execution of Semgrep/OSV-Scanner (they run on the host against the sanitized copy — see PROJECT.md), CLI, dashboard.

## Supported runtimes
| Runtime | Image | Status |
|---|---|---|
| Python | `python:3.12-slim` | sandbox implemented and tested |
| JavaScript / Node.js | `node:22-slim` | a JS file runs in the same sandbox, tested; syntax check (`node --check`, sandboxed) and npm lockfile vulnerability scan implemented (Phase 2); **dependency installation, test runners and JS Semgrep rules are not implemented** |

Read *Operational assumptions and known exposures* in PROJECT.md before relying on the sandbox (shared kernel, trusted
local Docker daemon, `/proc` exposure, no atomic snapshot of a live source tree, best-effort redaction).

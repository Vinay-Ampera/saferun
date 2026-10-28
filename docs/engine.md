# Validation engine (Phase 2) — library reference

Design and host-side analyzer risk: [PROJECT.md](../PROJECT.md#validation-engine-phase-2-saferunengine). Evidence: [IMPLEMENTATION.md](../IMPLEMENTATION.md). The command-line front end is documented in [cli.md](cli.md).

## Usage
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
JavaScript test runners, Semgrep rules for JavaScript, transitive resolution (requirements.txt and manifests without lockfiles),
in-sandbox execution of Semgrep/OSV-Scanner (they run on the host against the sanitized copy — see PROJECT.md), web dashboard.


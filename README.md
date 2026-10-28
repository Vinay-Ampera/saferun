# SafeRun

Checks AI-generated code before you run or trust it. Executing untrusted code in a sandbox **limits the impact** of that
code; it does **not** prove the code is safe, and a passing scan does not guarantee security. Status: **Phase 1 of 5**
(sandbox, implemented, awaiting owner approval). No validation engine, CLI or dashboard yet.
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

## Supported runtimes
| Runtime | Image | Status |
|---|---|---|
| Python | `python:3.12-slim` | sandbox implemented and tested |
| JavaScript / Node.js | `node:22-slim` | a JS file runs in the same sandbox, tested; **npm/dependencies, test runners and JS analysis are not implemented** (Phase 2) |

Read *Operational assumptions and known exposures* in PROJECT.md before relying on the sandbox (shared kernel, trusted
local Docker daemon, `/proc` exposure, no atomic snapshot of a live source tree, best-effort redaction).

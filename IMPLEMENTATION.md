# SafeRun — Implementation Status

## Environment (inspected 2026-10-28)
Ubuntu 24.04 host, kernel 7.0.0-38, 12 CPU / 15 GiB, ext4 `/tmp`. Python 3.12.3 (no pip/venv module: project-local `.venv`
created with `--without-pip` + official `get-pip.py`). Docker 29.8.0 (runc, cgroup v2, AppArmor + builtin seccomp reported by the
daemon, no userns remap), user in the `docker` group, default context `unix:///var/run/docker.sock`.
Phase 2 tooling status on this host: `semgrep` and `osv-scanner` were **not installed** at the start of Phase 2. Semgrep 1.182.1 was then installed
**into the project-local `.venv` only** (`pip install semgrep`, binary wheel, no project code involved; `.venv` is git-ignored) so the rules and parser could be checked
against the real tool. `osv-scanner` 2.7.0 was installed during the final review (see *Final review*). (node 22/npm exist on the host but SafeRun never runs them on the host.)
Images used by SafeRun: `python:3.12-slim` (present from the start) and `node:22-slim` (digest `sha256:4b150b48…`, pulled explicitly
during the completion pass for the JavaScript tests; remove with `docker rmi node:22-slim` if unwanted). Not installed: semgrep,
osv-scanner (Phase 2). The Docker host also holds unrelated images/containers — never touched.

## Phase 1 — Environment and Sandbox
**Acceptance status: every documented Phase 1 criterion is met on the evidence below (236 tests, 0 skipped; limits listed).
APPROVED by the owner as a project milestone and the baseline for Phase 2 — not a claim of perfect security or independent certification.
Phase 1 may be changed later only for a concrete reason, with regression tests. Passing tests do not prove the sandbox secure; see *Limitations*.**

### Requirements checklist
| Requirement (Phase 1 brief + review hardening list) | Status | Evidence |
|---|---|---|
| Inspect repository and environment; verify Docker availability/permissions | done | environment above; preflight at every run |
| Threat model and security boundaries | done | PROJECT.md |
| Safe workspace creation/copy: paths, symlinks, hard links, concurrent changes | done | `copy.py`; test_workspace 11, test_races 43, test_hardlinks 8 |
| Workspace cleanup incl. failure paths and abandoned workspaces | done | test_cleanup (8), reaper, hardening (daemon-down cases) |
| Docker: non-root, read-only root, no network, caps dropped, no-new-privileges, seccomp/AppArmor | done | applied-config verification (28 checks) + kernel-view attestation, both images |
| CPU, memory, swap, PID, fd, tmp, file-size, output, wall-time limits | done | test_sandbox, attestation (cgroup values), verification |
| Safe subprocess/Docker invocation, timeouts, errors, container cleanup | done | argv only, absolute docker path, `SandboxError` for odd Docker output, hung CLI, kill failure, daemon down |
| Sensitive-file detection, warnings, redaction | done | test_sensitive (27) |
| Seccomp/AppArmor availability checks; honest reporting of unverifiable controls | done | `daemon_controls`, `SandboxResult.controls`, `attest()` |
| Malformed inputs, unexpected Docker responses, daemon failures | done | test_hardening (102) |
| Python sandbox preserved and verified | done | all existing tests green; attestation on `python:3.12-slim` |
| JavaScript/Node.js | **partial by design** | the sandbox runs a JS file in `node:22-slim` under identical controls (11 tests); dependency handling/test runners/analysis are Phase 2 |
| OpenSandbox reuse assessment | done | PROJECT.md (nothing copied; ideas adapted; no new dependency) |

### History (nothing hidden)
1. Initial PoC: 18 tests (first run 17/1 — an over-broad test filter caught Docker's own `--init` mount; test narrowed, no control changed).
2. Independent review → 8 fixes (cleanup, orphan recovery, copy limits, seccomp/AppArmor/swap tests, `skipped`, race-safe copy, test quality, docs): 45 tests.
3. ZIP-review follow-ups: sensitive files, hard links: 80. 4. Result metrics (`copied_*` vs `entries_scanned`): 81.
5. Copy-race fix (replacement after pre-scan): 99. 6. Directory-mutation race (final validation pass): 120.
7. **Phase 1 completion pass (this document's latest update): 120 → 236 tests.** Test-code bugs found along the way (a network
   mutation that also rewrote `--log-driver none`; a fake-`docker` script whose restricted `PATH` hid `sleep`; earlier: self-copying temp dir,
   misplaced failure injection, miscounted expectation, token padding, wrong-file hook) were fixed in the *tests*; no control was weakened.
   One process slip: a presence check used `docker run`, which attempted an implicit pull of `node:22-slim` (it failed on a network
   reset; nothing was created). An earlier `IMPLEMENTATION.md` edit of mine had duplicated sections; the file was rewritten.

### Completion pass: what changed and why
Inspection of the then-current code against the hardening list found these real gaps (all fixed, each with regression tests):
| # | Gap found | Fix |
|---|---|---|
| H1 | Docker's *applied* config was verified only in tests, not at run time | After `create`, before `start`: `docker inspect` is checked against 28 policy properties (`controls.verify_applied_config`); any deviation raises and the code never runs. Each property is shown to flip on the opposite value (28 mutation tests) and the fail-closed path is tested for 5 weakened-create scenarios |
| H2 | Daemon capability not checked; unverifiable controls not reported | `preflight()` refuses a run when seccomp is missing/unconfined or memory/swap/pids/CPU limits are unsupported (explicit `allow_degraded` opt-out, still reported); AppArmor reported, not required; `SandboxResult.controls` lists every control as verified / violated / unavailable / unverified; `attest(image)` reads the kernel's view from inside a sandbox |
| H3 | `force_remove` counted *any* `inspect` failure as "container gone" (daemon down ⇒ false success) | distinguishes "No such object" from daemon errors (regression test; reaper likewise reports a `docker ps` failure instead of an empty success) |
| H4 | Odd Docker output raised raw exceptions or produced `exit_code=None`; a kill that did not stop the container leaked `TimeoutExpired` | wrapped in `SandboxError`; unreadable final state is an error ("outcome unknown") |
| H5 | `create` could pull a missing image or follow a re-pointed tag; image/args unvalidated; image `ENTRYPOINT` could reinterpret argv; remote endpoint only documented | `--pull never`; created from the resolved image ID (`image_id` recorded and verified); image/command validation; `--entrypoint ""`; non-`unix://` endpoints refused |
| H6 | `/dev/shm` unbounded; images with `VOLUME` would get writable, unbounded anonymous volumes | `--shm-size` (`shm_mb`) verified and tested; images declaring `VOLUME` refused (unit-tested on the inspect data; no VOLUME image was built) |
| H7 | Untested: concurrent runs, hung CLI, non-UTF-8 output, malformed paths, removal/truncation windows | tests added (6 parallel runs; fake hung/garbled `docker`; NUL path; entry/dir removed between stat and open; truncation mid-read) |

### Test results (actual, final run of this pass)
Relevant tests were run incrementally while building (e.g. hardening 98/98 at the time, Node 11/11, races 43/43). Final, once:
`SAFERUN_REQUIRE_DOCKER=1 .venv/bin/pytest -v -rs` → **236 passed, 0 failed, 0 skipped** in 35 s
(test_hardening 102, test_races 43, test_sensitive 27, test_sandbox 24, test_workspace 11, test_node_profile 11, test_hardlinks 8,
test_cleanup 8, test_require_docker 2). The AppArmor-dependent checks ran (daemon reports AppArmor); the Node tests ran (image present).
After the run: 0 containers labelled `saferun.sandbox=1`, 0 `saferun-*`/test containers, 0 `/tmp/saferun-ws-*`, 0 `saferun-attest-*`,
no non-symlink workspace directory under pytest's temp area. Unrelated containers/images were not modified.
In-memory mutation checks (not part of the suite), each making the intended tests fail: pre-start verification disabled (5 tests);
old `force_remove` (1); `--pull never` removed (1); old reaper ignoring a `docker ps` failure (1). Earlier passes added: private-mode
check disabled, hard-link check disabled, chunk overlap shrunk, `copied_files = entries_scanned`, `O_NOFOLLOW` removed, and old-code
comparisons for both race fixes.
Not run / could not run: rootless Docker, Podman, a host without AppArmor, a host with `docker`'s seccomp disabled, an actually
hung Docker daemon (simulated with fakes), disk-full, kernels < 6.13.

### Verified security controls and how each is evidenced
*Per run*, a control is reported `verified` only from Docker's own applied config (pre-start) or the daemon's own capability report.
*On demand*, `attest()` adds what the kernel reports inside a sandbox. † = also shown to fail when disabled (mutation, not in suite).
- **Isolation flags as applied** (28 properties, †): not privileged, `network none`, read-only root, `CapDrop=ALL`/no `CapAdd`,
  `no-new-privileges`, no `unconfined` profile, empty entrypoint, uid 65534, memory = memory-swap, CPU quota, pids, nofile/fsize/core ulimits,
  `/tmp` tmpfs `noexec,nosuid,nodev` + size, shm size, one read-only `/workspace` bind (no binds/extra mounts), no image `VOLUME`,
  no devices, no published ports, private PID/IPC/user/UTS, `--init`, log driver none, OOM kill enabled, no restart, resolved image ID, label.
- **Daemon** (†): seccomp present and not unconfined; memory/swap/pids/CPU cgroup support (else refused unless `allow_degraded`); AppArmor reported.
- **Kernel view** (`attest`, both images): `Seccomp: 2`, `NoNewPrivs: 1`, `CapEff/CapBnd/CapAmb = 0`, uid 65534, only `lo`, `memory.max`,
  `memory.swap.max = 0`, `pids.max`, `cpu.max`, workspace and root not writable, `/tmp` writable, AppArmor `docker-default (enforce)` (this host).
- **Behavioural evidence** (Python and, for the subset listed in test_node_profile, Node): no network and no DNS; read-only filesystem except `/tmp`;
  `/tmp` noexec and size-limited; `/dev/shm` size-limited; no host env/socket/home; OOM kill; exact PID limit (Python); CPU quota in cgroup;
  file-size ulimit is the cause of `EFBIG`; output cap without blocking; host timeout and container-side `timeout -s KILL` (parent SIGKILLed); kernel view above.
- **Workspace copy:** † pre-scan signatures of every entry/listing, verified lstat + opened fd, listings, post-read check and final validation pass
  (see *Concurrent modification*); fd-relative `O_NOFOLLOW`; limits enforced before and during the copy; lazy, bounded directory listing.
- **Sensitive data:** † mode-based and content-signature withholding, `allow_paths`/`honor_private_modes`, output redaction with truncated-tail dropping.
- **Hard links:** † copied only if every name of the inode was seen inside the tree.
- **Cleanup and recovery:** independent container/workspace cleanup, original exception preserved, failure paths tested; `reap_orphans()`
  (deadline label, flock-guarded workspaces, daemon failure reported); concurrent runs isolated.
- **Invocation hygiene:** argv only, absolute docker path, validated image/command, `--pull never`, local endpoints only, odd Docker output → `SandboxError`.

### Concurrent modification — what is and is not claimed
Mechanism: pre-scan records a signature (mode/type, dev, ino, size, mtime_ns, ctime_ns) of every entry and each directory's names; the copy
pass requires lstat and the opened fd to match, listings to match, and files to be unchanged after reading; a final pass re-validates every
directory (identity, metadata, listing) and entry. Any difference aborts with `WorkspaceChangedError` and nothing is kept. This is
**detection on a live filesystem, not an atomic snapshot** (that needs LVM/btrfs/ZFS/overlay snapshots). Not detected: changes after the final
validation (they cannot alter already-copied files), changes leaving every recorded field identical (possible within one coarse timestamp tick
on kernels < 6.13 — this host runs 7.0; untested elsewhere), content already present at scan time, cross-file inconsistency that predates the scan.
A concurrent writer can force repeated aborts. The top-level path is resolved once by the caller; the destination is private (0700) until done.

### Result accounting
`copied_files`/`copied_dirs`/`copied_bytes` = what was written and kept; `entries_scanned == copied_files + copied_dirs + len(skipped) + len(withheld)`;
plus `skipped`, `withheld`, `redactions`, `controls`, `image_id`. Size limits count bytes *read* (conservative).

### JavaScript / Node.js status
- **Done:** a JavaScript file runs in `node:22-slim` through the same `run_sandboxed`, with identical, verified restrictions (11 tests: attestation, run/exit/output,
  uid and clean env, no network incl. DNS, read-only fs except `/tmp`, `/tmp` noexec, OOM kill at 96 MB, timeout, output cap, symlink/secret handling).
  The architecture needed no change beyond the image-agnostic hardening above and an entrypoint reset (the Node image sets an `ENTRYPOINT`).
- **Not done (Phase 2, and why):** dependency acquisition needs a *separate* network-enabled, allowlisted sandbox (`npm ci --ignore-scripts`) and offline
  execution afterwards; `package.json`/lockfile handling; test-runner integration (`node --test`, jest) and result parsing; `node --check`; Semgrep JS
  rules; OSV for npm; Node version selection; digest pinning; behaviour on Alpine/distroless (`timeout`/`sh` required, verified only on the two Debian-slim
  images); V8 heap vs cgroup tuning. A JavaScript SDK that merely controls a sandbox does not run JavaScript; this status concerns SafeRun's own Docker sandbox.

### OpenSandbox reuse — decisions (full table in PROJECT.md)
Nothing was copied, installed, run or deployed; reviewed read-only over the web. Reuse: **none of the platform** (server, execd, egress sidecar, SDKs, code
interpreter, isolation sessions — avoided: extra infrastructure, in-sandbox daemon, weaker defaults, privileges the sandbox must not have). **Adapted as ideas,
re-implemented in our own code:** explicit-acknowledgement fail-fast (`startup_guard.py` → `preflight` + `allow_degraded`); input hygiene (`validators.py` →
`validate_command`, `validate_image`, mount-path check); argv-only command semantics. **Built our own:** orphan labels/reaper, resource limits, runtime
profiles. **Deferred:** stronger runtimes (gVisor/Kata) as a possible future backend; cosign/digest practices for Phase 5. Licence: all reviewed code is
Apache-2.0; no code copied ⇒ no §4 obligations; no new SafeRun dependency. Limits of the review: only the files listed in PROJECT.md were read (not
`volumes.py`, `networking.py`, `runtime.py`, execd Go sources); decisions are confined to that evidence.

### Limitations and unverified claims
- **Not proven secure.** The container shares the host kernel; kernel/runc escapes are neither mitigated nor assessed. No userns remap, gVisor or Kata.
  The `docker` group is root-equivalent; the invoking user, `PATH` and the local daemon are trusted. Seccomp *rules* and the AppArmor profile *contents*
  are not audited — only that they are active. A sandbox limits the impact of running untrusted code; it does not make the code safe.
- AppArmor is verified only on this host; the no-AppArmor and `allow_degraded` paths are unit-tested with fakes, not on such a host. Rootless Docker, Podman
  and non-default contexts are untested. Per-run `controls` come from Docker's config/daemon report; the kernel view requires calling `attest()` (not run automatically per scan).
- Preflight → create is not atomic, but the container is created from the *resolved image ID* and that is verified; an image's *contents* are not audited.
- Redaction is best-effort (code can encode a secret first; a test documents base64 passing through). A world-readable secret in an unrecognised format is readable
  by sandboxed code; the signature list is not exhaustive; withheld files are not analysed.
- `/proc`/`/sys` expose host details (kernel, CPU, host workspace path in `mountinfo`); file modes are flattened to 0644/0755 (exec bits lost).
- Behaviour under a truly hung daemon, a full disk and extreme load is untested; the host timeout excludes `docker create` time; Docker/`timeout` failures after start look
  like exit 125–127 (stderr untrusted). CPU throttling accuracy is not measured (only the quota). Hard-link detection relies on `st_nlink` (verified on ext4).
- Images must provide `timeout` and `sh`; verified on two images. Output is not sanitized for terminals (Phase 3). `reap_orphans()` is not called automatically.
- The remote-endpoint refusal is exercised through `DOCKER_HOST` only (the context-based branch runs on every real run for the default context, but a remote *context* was not tested).
- Secret values live in host memory during a run. Submounts inside a scanned directory are not handled specially.

### Steps requiring the owner's approval
1. **Phase 1 acceptance** (not self-approved). 2. **`node:22-slim` was pulled** (≈326 MB, official image) to test JavaScript; keep, or remove with `docker rmi node:22-slim`.
3. Whether the **Phase 2** plan below may start. 4. A **licence for SafeRun itself** is undecided (no copied code constrains it). 5. Whether the default policy
(`allow_degraded` empty ⇒ refuse hosts without swap/pids/memory/CPU cgroup support) should stay strict.

### Hand-offs to later phases
Phase 2 must report any non-empty `skipped`/`withheld`/`redactions` as a **partial scan**, surface withheld credential files as findings, run analyzers inside the
sandbox, keep dependency acquisition a separate network-enabled step, and add the JavaScript items above. Phase 4: refuse hard-link/symlink/device archive members,
enforce upload limits, extract into a private directory. Phase 5: pin images by digest, decide whether a second backend is real before extracting an interface.

## Git
The directory was not a repository. `git init` + one local commit `Add restricted Docker sandbox foundation` (Phase 1 baseline, 27 files; `.gitignore` extended with
`artifacts/` (a generated review zip), env/key patterns). No remote configured, nothing pushed.

## Phase 2 — Validation Engine (implemented; awaiting owner review)

### Requirements checklist
| Requirement | Status | Evidence / notes |
|---|---|---|
| A. Semgrep integration (controlled subprocess, rules, parsing, missing tool/malformed/timeout/non-zero) | done; verified against real Semgrep 1.182.1 (`--validate` of the rules, real scan, `# nosem` ignored) | `engine/semgrep.py`, `rules/python.yml` (11 rules), `tools.py`; 22 mocked-output tests + 2 tests that run the real binary when installed |
| B. OSV-Scanner integration (ecosystems, normalization, unavailable/timeout/invalid/error, never silently clean) | done; **verified against real osv-scanner 2.7.0** (see *Final review*) | `engine/osv.py`; mocked-output tests plus real-binary tests in `tests/test_engine_real_tools.py` |
| C. JavaScript: `node --check`, npm lockfile scan, deferred list | done (plus a sandboxed Python syntax check, added after real-Semgrep testing) | `engine/node.py` runs in the sandbox; real-sandbox tests (2); npm scan via OSV (mocked). Deferred: installation, test runners, JS Semgrep rules |
| D. Normalized model + verdicts | done | `engine/model.py`, `verdict.py`; 17 verdict tests; rules in README |
| E. Integration without breaking the sandbox API | done | `engine/engine.py` uses `create_workspace`/`run_sandboxed`; no sandbox file modified; all 236 Phase 1 tests unchanged and green |
| F. Tests and docs | done | below; README/PROJECT/IMPLEMENTATION updated |

### Issues found by running the real tools (fixed in Phase 2 code)
1. Semgrep prefixed rule ids with the rule file's directory path (`home.user….saferun.python.…`); fixed with `--no-rewrite-rule-ids` (mocked tests could not catch this).
2. Semgrep does **not** report Python syntax errors (a file with `def f(:` is "scanned", no error), so a broken file looked clean. Added the sandboxed `python-syntax` check.

### Design decisions worth reviewing
1. **Semgrep and OSV-Scanner run on the host, against the sanitized copy** (see PROJECT.md *Validation engine* for the reasoning and mitigations). This is a
   conscious deviation from the Phase 1 hand-off note "run analyzers inside the sandbox": no analyzer image exists locally, SafeRun does not pull images, and OSV needs network.
   `node --check` does run in the sandbox. Decision needed from the owner: build/approve an analyzer image later, or accept host-side analyzers.
2. Operational failures yield `WARNING`, not `FAIL`; `FAIL` is reserved for findings. `PASS` requires at least one completed analysis check and no partial scan.
3. A non-empty `skipped`/`withheld` workspace is a partial scan (WARNING at least); withheld credential files are HIGH findings (as the Phase 1 hand-off asked).
4. JavaScript syntax errors are MEDIUM (WARNING), not HIGH.

### Phase 1 changes
**None.** No file under `saferun/sandbox/` was modified in Phase 2. No Phase 1 defect was found.

### Test results
See the completion report in the conversation for exact commands/output; summary: final-review runs (see *Final review*): with both real tools on PATH
`PATH="$S/osv:$PWD/.venv/bin:$PATH" SAFERUN_REQUIRE_DOCKER=1 .venv/bin/pytest -q -rs` → **396 passed, 0 skipped** (77 s); with neither on PATH
`SAFERUN_REQUIRE_DOCKER=1 .venv/bin/pytest -q -rs` → **382 passed, 14 skipped** (all skips are real-tool tests, each reporting why) (39 s).
Phase 1 = 236, Phase 2 = 160. Afterwards: 0 containers labelled `saferun.sandbox=1`, 0 `/tmp/saferun-ws-*`.

### Unavailable / not verified in this environment
- `osv-scanner`: not on the system PATH; a checksum-verified 2.7.0 binary lives in the session scratchpad only (see *Final review*). Real-binary tests skip visibly without it.
- `semgrep`: available only via the project `.venv` (not on the system PATH); real-tool tests run when it is on PATH, otherwise skip visibly.
- No network-dependent test exists; ordinary tests need neither network nor either tool.

### Limitations and deferred work
See PROJECT.md *Validation engine → Limitations*. Additionally: rule quality is unmeasured (no false-positive/negative evaluation); the verdict thresholds are policy
choices, not validated; host-side analyzers are part of the trusted base; OSV online mode discloses dependency names/versions to OSV.dev.

## Final review of Phase 2 (verification pass)
No commit, no push, no Phase 3. No file under `saferun/sandbox/` changed.

### Environment changes made in this pass
- **osv-scanner v2.7.0** (`osv-scanner_linux_amd64` from the official GitHub release; SHA-256 checked against the release's `osv-scanner_SHA256SUMS`: OK) placed in the session
  scratchpad `…/scratchpad/osv/` only. Not on the system PATH, nothing installed system-wide, no Docker resources touched. Test inputs were hand-written lockfiles; **no dependency was installed or built**.
- Semgrep 1.182.1 remains in the project `.venv` (from the previous pass). The scanner contacted `api.osv.dev` (package names/versions only) during the real-tool tests.

### Verified with the REAL osv-scanner 2.7.0
| Item | Result |
|---|---|
| CLI flags used (`scan source`, `--format json`, `--no-resolve`, `--offline`, `--lockfile=`) | all exist in 2.7.0 (`--help` read) |
| `--offline` | does **not** merely skip the network: it switches to local databases and fails (exit 127, "no offline version of the OSV database is available") when none are cached → reported `error`; the doc claim was right, my earlier reading of the flag was incomplete |
| JSON shape (`results[].source.path`, `packages[].package`, `vulnerabilities[]`, `groups[].max_severity`, `aliases`, `database_specific.severity`, `affected[].ranges[].events[].fixed`) | matches the parser; real output parsed into findings with correct package/ecosystem/path, alias de-duplication, fixed versions |
| Known vulnerable dependency | `django==2.2.0` → 43 findings (PyPI) incl. critical; `lodash 4.17.15` in `package-lock.json` → GHSA-35jh-r3h4-6jhm / CVE-2021-23337, high, fixed in 4.17.21 |
| Clean result | `six==1.17.0` → exit 0, `{"results": []}` → `passed` |
| Exit codes | 0 clean, 1 findings, 127 error, 128 no packages (empty lockfile → `incomplete`) |
| Failure modes | malformed lockfile (127), missing file (127), unreachable network, `--offline` without DB, timeout, missing tool → `error`/`error`/`error`/`error`/`timeout`/`unavailable`; verdict `WARNING`, never PASS |
| Exit 127 **with a clean-looking** `{"results": []}` (network down) | the engine checks the exit code before parsing → `error` (regression-tested against the real binary) |
| Python/npm support | `requirements.txt` and `package-lock.json` verified. `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock`, `yarn.lock`, `pnpm-lock.yaml` are passed to the tool by name but were **not** exercised with it |

### Defects found in Phase 2 code and fixed (each with regression tests, mostly against the real binaries)
1. **Semgrep skipped files silently.** A project `.semgrepignore` hid a file containing `eval(x)` (result still `findings`/complete), and a 1.8 MB file was skipped without any error. Fix: `.semgrepignore`
   files are removed from the analysis copy only, and every targeted Python file must appear in Semgrep's `paths.scanned`, else the check is `incomplete`.
2. **OSV-Scanner silently skips npm lockfile entries it cannot match** (no registry `resolved` URL, or git): "found 1 package", exit 0, no results — a vulnerable package then looked clean.
   Fix: `package-lock.json` is cross-checked (`npm_unmatched`); such entries make the check `incomplete`. Not done for yarn.lock/pnpm-lock.yaml (unverified).
3. **Requirements variants** (`requirements-dev.txt`, …) were silently ignored → now a reported coverage gap.
4. **Misleading error detail:** OSV-Scanner's progress lines hid its error text in `detail` → error lines are preferred.
5. **Documentation:** `requirements.txt` had been grouped with lockfiles. Fixed everywhere: it is a *manifest/requirements file*; unpinned entries (`flask>=1.0`, verified: evaluated as exactly 1.0) are unreliable and no transitive resolution happens.

### Code review notes (no defect found unless listed above)
Subprocess: argv only, absolute exe, minimal env, own process group killed on timeout/output cap, stdin closed. Paths: tool paths accepted only as relative paths inside the copy; lockfile names
restricted before use in `--lockfile=./…` (`:` and control characters refused). Symlinks: the Phase 1 copy contains none; `os.walk(followlinks=False)`. Cleanup: workspace deleted in `finally`; tests assert an empty workspace root;
no leftover containers/workspaces after the full run. Verdict: no status other than `passed`/`findings` counts as completed; operational problems force `WARNING`; nothing-ran is `WARNING`.
Residual: a cleanup failure raises instead of returning the computed report (fail loud); `yarn.lock`/`pnpm-lock.yaml` may have analogous unmatched-entry gaps; Semgrep's tolerant parser can hide
partially-unparseable regions (syntax errors are caught separately by `python-syntax`).

### Host-side analyzer risk (decision required — nothing changed)
Semgrep and OSV-Scanner run **as the invoking user on the host** and parse files from the sanitized copy. The copy removes symlinks, special files and credential files and nothing is executed from the project,
but a parser/memory-safety or logic bug in either tool (or a crafted file triggering excessive resource use) would run with that user's full privileges: home directory, SSH keys, the `docker` group. Limits in place:
minimal environment, private HOME, process-group kill, 8 MiB output cap, wall-clock timeout. **Not** in place: memory/CPU/pids limits, filesystem or network confinement for the host process.
Both tools are widely used, but "widely used" is not a security guarantee, and nothing here was assessed for exploitability.

| | 1. Documented temporary host-side limitation | 2. Analyzers in a restricted container |
|---|---|---|
| Security | weakest: analyzer bug ⇒ user-level compromise | strong: same verified controls as the sandbox (non-root, no caps, no-new-privileges, read-only, limits, no network, no socket) |
| Work | none (already documented) | an analyzer image (semgrep + osv-scanner, pinned by digest, built on a networked step then used offline); `run_sandboxed` today mounts only the project, so Semgrep (needs a writable cache in tmpfs) fits, but OSV needs vulnerability data |
| OSV network | works online | the sandbox has no network by design; use `--offline` with databases downloaded by a trusted host step that never sees project input (`--download-offline-databases`), mounted read-only — needs a new read-only extra mount in the sandbox (a Phase 1 change, reviewed) |
| Risk of the change itself | none | a new mount and image add surface; must not weaken any existing control; database freshness/size policy needed |
| Verified here | — | **not built or tested** (no image exists; building one is a Docker change not authorised in this pass) |

**Recommendation:** keep option 1 as the explicit, documented interim state for Phase 2 review, and adopt option 2 as the target before SafeRun scans genuinely untrusted uploads (Phase 4) —
a hardened analyzer image run through the existing sandbox, with OSV databases refreshed by a separate trusted step. **Needs your decision:** (a) accept option 1 for now; (b) approve building a digest-pinned
analyzer image and a read-only extra mount (a reviewed Phase 1 change); (c) the offline-database refresh policy; (d) whether OSV online mode (disclosing dependency names/versions to OSV.dev) is acceptable in the interim.

## Remaining
- Phase 3 (CLI), 4 (dashboard), 5 (integration/security testing/release) per PROJECT.md. Nothing beyond Phase 2 has been started. Not started until the owner approves.

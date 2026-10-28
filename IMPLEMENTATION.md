# SafeRun — Implementation Status

## Environment (inspected 2026-10-28)
Ubuntu 24.04 host, kernel 7.0.0-38, 12 CPU / 15 GiB, ext4 `/tmp`. Python 3.12.3 (no pip/venv module: project-local `.venv`
created with `--without-pip` + official `get-pip.py`). Docker 29.8.0 (runc, cgroup v2, AppArmor + builtin seccomp reported by the
daemon, no userns remap), user in the `docker` group, default context `unix:///var/run/docker.sock`.
Images used by SafeRun: `python:3.12-slim` (present from the start) and `node:22-slim` (digest `sha256:4b150b48…`, pulled explicitly
during the completion pass for the JavaScript tests; remove with `docker rmi node:22-slim` if unwanted). Not installed: semgrep,
osv-scanner (Phase 2). The Docker host also holds unrelated images/containers — never touched.

## Phase 1 — Environment and Sandbox
**Acceptance status: every documented Phase 1 criterion is met on the evidence below (236 tests, 0 skipped; limits listed). NOT
approved — awaiting the owner's review. Passing tests do not prove the sandbox secure; see *Limitations*.**

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

## Remaining
- Phase 2: validation engine. Phases 3–5 per PROJECT.md. Nothing beyond Phase 1 has been started.

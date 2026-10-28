# Web dashboard and API (Phase 4)

> **Local, loopback-only demonstration interface. The CLI remains the primary product.**
> **Do not expose this server beyond your own machine.** Uploaded archives are never *executed*, but Semgrep and OSV-Scanner
> *parse* them **on the host, as the user running the server** (who is typically in the `docker` group). A parser bug or a crafted
> file in either tool would run with that user's privileges. This host-side analyzer risk is **not solved** — it is contained by
> policy: the application refuses non-loopback binds and non-loopback peers. Running the analyzers in a hardened, network-less
> container (see IMPLEMENTATION.md *Host-side analyzer risk*) is the prerequisite for any wider use.

## Run
```bash
.venv/bin/pip install -e '.[dev,web,analysis]'     # fastapi + uvicorn are an optional extra; `pip install saferun` alone is unchanged
(cd web && npm ci --ignore-scripts && npm run build)   # builds web/dist (git-ignored); needs Node 20.19+/22.12+
.venv/bin/saferun-web                              # or: python -m saferun.api   → http://127.0.0.1:8765/
```
`saferun-web [--host 127.0.0.1|::1] [--port N]`. Anything but a loopback IP literal (`localhost` maps to `127.0.0.1`) exits with
status 64 **before** the server is created; there is no environment variable or option to override it. Additionally every request is
checked by `GuardMiddleware`, so the restriction also holds if the ASGI app is started some other way.
Development: `cd web && npm run dev` (Vite on 127.0.0.1:5173, proxying `/api` to 8765). Frontend tests: `npm test`. The frontend is plain JavaScript (React + Vite, `.jsx`); there is no TypeScript.

The dashboard needs the same things as the CLI: Docker + the runtime images, and optionally Semgrep and OSV-Scanner. `GET /api/health` and the
UI say which are missing; a missing tool means that check is `unavailable` and the verdict is at best WARNING.

## Design
```
browser (React, same origin) ── POST raw ZIP ──► streamed to a 0600 temp file (size-capped)
                                                  │ queued (1 running + 4 waiting)
                                                  ▼
                                   archive.extract_zip  (validate everything, then write; reject whole archive on any doubt)
                                                  │
                                                  ▼
          python -I -m saferun scan <dir> --format json  [--osv-offline | --no-dependency-scan]   (child process, own process group)
                                                  │ exit code must agree with report.verdict
                                                  ▼
                       report relayed UNCHANGED (schema_version 1) ──► GET /api/scans/{id}
```
There is **no validation code in the web layer**: the worker is the existing CLI, so verdict rules, exit codes, the report schema, the engine
and the sandbox are exactly those of `saferun scan`. A test runs both paths on the same archive and requires identical reports.
The UI only renders `report.verdict`; it never computes one. Nothing in the API runs code, commands or shells.

### Frontend layout (`web/src/`)
```
main.jsx, App.jsx          entry points (App renders the single page)
index.css                  global only: design tokens, reset, primitives shared by several components
pages/DashboardPage/       DashboardPage.jsx + .css (+ .test.jsx): state machine upload → poll → result
components/<Name>/         one folder per component: <Name>.jsx + matching <Name>.css (only where it has own styles)
                           Header, Footer, UploadPanel, ArchiveCard, ResultPanel, ReportView (composition),
                           VerdictCard, CheckCoverage, StatusBadge, FindingsTable, SeverityTally, GapsPanel
api/client.ts              fetch wrappers (same origin, custom CSRF header)
types/index.js             JSDoc typedefs of the report/job shapes (documentation only), mirroring saferun/engine/model.py
utils/                     report.ts (sorting, gaps, sanitising text), errors.ts (messages for stable error codes)
fixtures/report.json       golden report generated from the real engine model (pinned by tests/test_api_schema_fixture.py)
```
Tests live beside what they test. Plain global class names are used (no CSS modules), so moving a rule between files changes nothing visually as long as the import order in `main.tsx` is kept (`index.css` first).

### Endpoints
| | |
|---|---|
| `POST /api/scans?osv=online\|offline\|disabled` | body = raw ZIP, `Content-Type: application/zip`, header `X-SafeRun-Request: 1` → `202 {id,status}`. `413` too large · `415` wrong type · `429` queue full (`Retry-After`) · `408` upload too slow · `400/422` malformed |
| `GET /api/scans/{id}` | `{id,status,osv_mode,created_at,archive,error,report?}`; status ∈ `queued, running, done, failed, rejected`. HTTP 200 whatever the verdict |
| `DELETE /api/scans/{id}` | `204` (finished only; `409` if running) |
| `GET /api/health` | tool availability (booleans), queue occupancy, limits. No paths |
| `GET /`, `/assets/*` | the built dashboard (only if `web/dist` exists) |

Job states: **done** (a verdict exists), **rejected** (the archive was refused; stable `error.code` such as `unsafe-name`, no member names), **failed**
(no verdict: deadline, worker error, unusable output — *never* shown as a pass). Bad archives are rejected by the worker thread, not in the request, so at
most one extraction runs at a time.

### Limits (defaults, all tested)
Upload 25 MiB · extracted 100 MiB · 5 000 entries · 10 MiB per file · depth 32 · path 1 024 B / component 255 B · ratio cap 100:1 (above 1 MiB) ·
extraction 60 s · job deadline 10 min (process group killed) · tool timeout 120 s (CLI `--timeout`) · 1 running + 4 queued jobs · results kept 30 min, max 50 ·
worker output ≤ 8 MiB · upload read deadline 120 s · uploads still being read count against the 5 slots (a stalled client cannot hold unbounded temp files) · uvicorn `limit_concurrency` 32 connections.

## Archive handling (`saferun/api/archive.py`)
Whole-archive validation before the first byte is written (the central directory is walked and counted by SafeRun itself before `zipfile` builds any object, so a lying end record cannot make a small upload allocate hundreds of MiB; **ZIP64 archives are refused**, nothing within the limits needs them); **any** unsafe or invalid member rejects the whole archive. Rejected: absolute paths, `..`/`.`/empty
components, backslash, colon, NUL, control/bidi/format characters, non-UTF-8 names, over-long or too-deep paths; symlinks, hard-link-style special members, devices,
FIFOs, sockets, Windows reparse points; encrypted entries; compression other than STORED/DEFLATE; duplicate paths (also after case/Unicode folding) and file-vs-directory
conflicts; local headers that disagree with the central directory, overlapping entries (zip quines), junk before the first entry or after the end record, multi-disk
archives; declared *and* actual sizes beyond the limits (headers can lie, so counts are enforced on the bytes produced). `__MACOSX/` (top level) and `.DS_Store` files are
validated, then excluded and listed in the response; one top-level wrapper directory is stripped only when it is unambiguous. Extraction uses fd-relative `O_NOFOLLOW|O_EXCL`
writes into a fresh 0700 directory, files 0644 / directories 0755 regardless of the archive (the Phase 1 copier would otherwise withhold 0600 files).

## Worker environment
The worker is started with an environment built from an allow-list, never from `os.environ` as a whole, and as `python -I` (no `PYTHONPATH`, no user site, no cwd on `sys.path`).
| Variable | Preserved because |
|---|---|
| `PATH` (the server interpreter's bin dir is prepended) | the worker must find `docker`, `semgrep`, `osv-scanner` |
| `LANG`, `LC_ALL`, `TZ` | decoding of tool output; timestamps |
| `DOCKER_HOST` | the sandbox reads it and accepts only `unix://` endpoints; a different local socket must keep working |
| `DOCKER_CONTEXT` | selects the context the docker CLI talks to |
| `DOCKER_CONFIG` | only if the operator set it explicitly. The real `~/.docker` (registry credentials) is **not** exposed |
| `HTTP(S)_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `SSL_CERT_DIR` | **only for OSV online mode**, which needs the network (same rule as the engine's own tool runner) |
| `HOME`, `TMPDIR` | *set by SafeRun* to a private per-job directory (deleted with the job), not inherited |
Everything else is dropped, notably cloud/API tokens (`AWS_*`, `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`…), `SSH_AUTH_SOCK`, and the code-injection variables `PYTHON*`, `LD_*`,
`BASH_ENV`, `ENV`. Semgrep and OSV-Scanner then get the engine's own, even smaller environment. Consequence: a non-default Docker context that is defined only in `~/.docker` is not
visible to the worker — set `DOCKER_CONTEXT`/`DOCKER_CONFIG` for the server if you need that.

## Network-facing protections
Peer address must be loopback (`403`); `Host` header must be a loopback name (`400`, DNS-rebinding defence); state-changing requests need `X-SafeRun-Request: 1` and, when an
`Origin` header is present, exactly this server's own origin (`403`); CORS preflights are never answered; WebSockets are refused; no OpenAPI/docs pages; `proxy_headers` off;
security headers on every response (`Content-Security-Policy` without inline script/style, `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, CORP/COOP same-origin);
`Cache-Control: no-store` on the API. IDs are 128-bit random capabilities; there is no list endpoint. **There is no authentication** and none is claimed: anyone who can reach
the loopback port (any local user) can use the dashboard and read results by ID.

## Privacy
With OSV *online* (the default), package names and versions from lockfiles / `requirements.txt` are sent to OSV.dev by the machine running SafeRun. The UI states this next
to the selector; *offline* needs cached databases (otherwise the dependency check errors → WARNING); *disabled* skips the check (→ WARNING).

## Cleanup
The upload, the extraction directory and the worker's HOME are deleted before a job's result is published. Startup sweeps `saferun-up-*` directories and `saferun-upl-*` files older
than 40 min (owned by the current user) and calls `reap_orphans()`; a killed or timed-out job triggers `reap_orphans()` again (containers also die by their own container-side timeout).
A SIGKILLed server leaves its in-flight files until the next startup sweep. **Stopping the server (Ctrl+C) during a scan does not kill the running worker**: it lives in its own session and ends by itself within its own timeouts (the engine deletes its own workspace; the extraction directory is swept at the next start once it is 40 min old).

## Online / offline OSV
`online` (default) lets OSV-Scanner contact api.osv.dev; verified by hand with the real osv-scanner 2.7.0 through the dashboard server: `django==2.2.0` → 43 findings, FAIL. `offline` without cached databases → the dependency check ends in `error` (osv-scanner exit 127), verdict WARNING, never clean. `disabled` → `skipped`, WARNING. The flags and the environment the tool receives (proxy/cert variables only when online, none of the server's secrets) are pinned by `tests/test_api_osv_plumbing.py` with a recording fake binary. Real-network behaviour is not part of the automated suite unless osv-scanner is on PATH (`tests/test_engine_real_tools.py`).

## Limitations
No authentication, loopback only; host-side analyzers as above; in-memory results (lost on restart); one job at a time; ZIP only; the 408 timeout covers the upload only; the dashboard
inherits every engine limitation (Python-focused rules, no transitive dependency resolution, PASS ≠ safe). The UI was verified with component tests (jsdom), `curl`, and a scripted run in real Google Chrome 153 (headless, via playwright-core kept outside the repo); it was not tried in other browsers or by a human reviewer. Its styling is an original design — the reference images mentioned in the task were not available.

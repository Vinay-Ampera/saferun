"""FastAPI application for the local SafeRun dashboard (Phase 4, unit 3).

A thin HTTP layer: upload a ZIP, poll the job, read the engine's report. All validation happens in the existing
CLI/engine (see jobs.py); nothing is executed here, and there is no endpoint that runs code or commands.

  POST   /api/scans?osv=online|offline|disabled   body: raw application/zip      -> 202 {id, status}
  GET    /api/scans/{id}                                                          -> job (+ report when done)
  DELETE /api/scans/{id}                                                          -> 204 (finished jobs only)
  GET    /api/health                                                              -> tool availability, limits
  GET    /                                                                        -> built dashboard (web/dist), if built

Auth: none, deliberately no claim of it. Access control is loopback-only (guard.py + server.py). The interactive
OpenAPI pages are disabled.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from ..sandbox import reap_orphans
from .archive import MiB, UPLOAD_PREFIX, ArchiveLimits
from .guard import GuardMiddleware
from .jobs import OSV_MODES, Busy, JobLimits, JobManager, sweep_stale, worker_path

DEFAULT_STATIC_DIR = Path(__file__).resolve().parents[2] / "web" / "dist"
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
UPLOAD_TIMEOUT_S = 120.0
_CHUNK = 64 * 1024


def _error(status: int, code: str, message: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status, headers=headers)


def _safe_reap():
    return reap_orphans()


def create_app(manager: JobManager | None = None, *, archive_limits: ArchiveLimits | None = None,
               static_dir: Path | None = DEFAULT_STATIC_DIR, run_startup_cleanup: bool = True) -> FastAPI:
    limits = archive_limits or ArchiveLimits()
    mgr = manager or JobManager(JobLimits(), limits, reaper=_safe_reap)

    @asynccontextmanager
    async def lifespan(_app):
        if run_startup_cleanup:
            try:
                sweep_stale(mgr.limits.stale_after_s)
            except OSError:
                pass
            try:
                reap_orphans()
            except Exception:   # noqa: BLE001 - Docker may be down; scans will then fail visibly, not silently
                pass
        mgr.start()
        yield
        mgr.shutdown()

    inflight = [0]   # uploads currently being read; they count against capacity like queued jobs

    app = FastAPI(title="SafeRun dashboard", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.add_middleware(GuardMiddleware)

    @app.post("/api/scans", status_code=202)
    async def create_scan(request: Request, osv: str = "online"):
        if osv not in OSV_MODES:
            return _error(422, "invalid-osv-mode", f"osv must be one of: {', '.join(OSV_MODES)}")
        ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != "application/zip":
            return _error(415, "unsupported-media-type", "send the archive as the raw body with Content-Type: application/zip")
        cap = limits.max_archive_bytes
        cl = request.headers.get("content-length")
        if cl is not None:
            if not cl.isdigit():
                return _error(400, "bad-content-length", "invalid Content-Length")
            if int(cl) > cap:
                return _error(413, "archive-too-large", f"the archive exceeds {cap // MiB} MiB")
        if inflight[0] + mgr.counts()["active"] >= mgr.counts()["capacity"]:
            return _error(429, "busy", "too many scans in progress; try again shortly", {"Retry-After": "30"})
        inflight[0] += 1          # asyncio is single-threaded: no await between the check above and this increment
        try:
            fd, path = tempfile.mkstemp(prefix=UPLOAD_PREFIX, suffix=".zip")
        except BaseException:
            inflight[0] -= 1
            raise
        owned = True
        try:
            total = 0
            deadline = time.monotonic() + UPLOAD_TIMEOUT_S
            with os.fdopen(fd, "wb") as out:
                it = request.stream().__aiter__()
                while True:
                    try:
                        chunk = await asyncio.wait_for(it.__anext__(), max(0.001, deadline - time.monotonic()))
                    except StopAsyncIteration:
                        break
                    except asyncio.TimeoutError:
                        return _error(408, "upload-timeout", "the upload took too long")
                    total += len(chunk)
                    if total > cap:
                        return _error(413, "archive-too-large", f"the archive exceeds {cap // MiB} MiB")
                    out.write(chunk)
            if total == 0:
                return _error(400, "empty-body", "the request body is empty")
            try:
                job = mgr.submit(path, osv)
            except Busy:
                return _error(429, "busy", "too many scans in progress; try again shortly", {"Retry-After": "30"})
            owned = False
            return JSONResponse({"id": job.id, "status": job.status}, status_code=202)
        finally:
            inflight[0] -= 1
            if owned:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str):
        job = mgr.get(scan_id) if _ID_RE.match(scan_id) else None
        return JSONResponse(job) if job else _error(404, "not-found", "no such scan")

    @app.delete("/api/scans/{scan_id}")
    def delete_scan(scan_id: str):
        if not _ID_RE.match(scan_id) or mgr.get(scan_id) is None:
            return _error(404, "not-found", "no such scan")
        if not mgr.delete(scan_id):
            return _error(409, "not-finished", "the scan is still queued or running")
        return Response(status_code=204)

    @app.get("/api/health")
    def health():
        path = worker_path()
        have = lambda name: shutil.which(name, path=path) is not None  # noqa: E731
        return {"docker_cli": have("docker"), "semgrep": have("semgrep"), "osv_scanner": have("osv-scanner"),
                "queue": mgr.counts(),
                "limits": {"max_archive_mib": limits.max_archive_bytes // MiB, "max_uncompressed_mib": limits.max_total_bytes // MiB,
                           "max_entries": limits.max_entries, "max_file_mib": limits.max_file_bytes // MiB,
                           "job_deadline_s": mgr.limits.job_deadline_s, "result_ttl_s": mgr.limits.result_ttl_s}}

    if static_dir is not None and (Path(static_dir) / "index.html").is_file():
        static_dir = Path(static_dir)
        if (static_dir / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(static_dir / "index.html", media_type="text/html", headers={"Cache-Control": "no-store"})

    return app

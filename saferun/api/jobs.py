"""Bounded scan jobs (Phase 4, unit 2): extraction + the existing CLI as a subprocess.

There is deliberately NO validation logic here. A job extracts the uploaded ZIP with `archive.extract_zip`
and then runs `python -I -m saferun scan <dir> --format json` in a child process, whose JSON is the engine's
report, relayed unchanged. The CLI's exit code must agree with the report's verdict, otherwise the job fails.

Bounds: one running job, at most `max_queue` waiting; every job has a wall-clock deadline after which the whole
process group is killed; results expire after `result_ttl_s`; the upload, the extraction directory and the
worker's private HOME are deleted in a `finally`; stale leftovers of a crashed server are swept at startup.

Worker environment: built from scratch from an allow-list (see ALLOWED_ENV / NET_ENV), never from os.environ as
a whole. Why each preserved variable is needed is documented next to the lists and in docs/api.md.
"""
from __future__ import annotations

import json
import os
import queue
import secrets
import shutil
import stat
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..engine.model import SCHEMA_VERSION, Verdict, clean_text
from ..engine.tools import ToolRun, ToolUnavailable, run_tool
from .archive import UPLOAD_PREFIX, WORKDIR_PREFIX, ArchiveError, ArchiveLimits, ExtractResult, extract_zip

OSV_MODES = ("online", "offline", "disabled")
STATUSES = ("queued", "running", "done", "failed", "rejected")

# Environment variables the worker (the SafeRun CLI) may inherit, and why. Everything else - cloud/API tokens,
# SSH_AUTH_SOCK, GITHUB_TOKEN, PYTHON*, LD_*, BASH_ENV, ... - is dropped.
ALLOWED_ENV = (
    "PATH",            # find `docker`, `semgrep`, `osv-scanner` (the interpreter's own bin dir is prepended)
    "LANG", "LC_ALL", "TZ",   # text decoding of tool output / timestamps
    "DOCKER_HOST",     # the sandbox only accepts unix:// endpoints and checks this variable
    "DOCKER_CONTEXT",  # which docker context the CLI talks to
    "DOCKER_CONFIG",   # only if the operator set it explicitly; the real ~/.docker is NOT exposed through HOME
)
NET_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
           "SSL_CERT_FILE", "SSL_CERT_DIR")   # only for OSV online mode, same rule as saferun.engine.tools.build_env


@dataclass(frozen=True)
class JobLimits:
    job_deadline_s: float = 600.0     # whole job: extraction + scan
    tool_timeout_s: float = 120.0     # passed to the CLI as --timeout (per tool / sandbox run)
    max_queue: int = 4                # jobs waiting behind the running one
    result_ttl_s: float = 1800.0
    max_results: int = 50             # finished jobs kept
    max_output_bytes: int = 8 * 1024 * 1024
    stale_after_s: float = 1800.0 + 600.0   # startup sweep: leftovers older than this are crash debris

    def __post_init__(self):
        for k, v in vars(self).items():
            if not (isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0 and v != float("inf")):
                raise ValueError(f"JobLimits.{k} must be a positive finite number, got {v!r}")


class Busy(Exception):
    """The queue is full."""


def worker_path() -> str:
    """PATH for the worker: the server interpreter's bin dir first (so a venv's semgrep is found), then PATH."""
    return os.pathsep.join(p for p in (str(Path(sys.executable).parent), os.environ.get("PATH", "")) if p)


def worker_env(home: Path, osv_mode: str, source: dict | None = None) -> dict[str, str]:
    """The worker's environment. `source` defaults to os.environ and is only ever read through the allow-lists."""
    src = os.environ if source is None else source
    env = {k: src[k] for k in ALLOWED_ENV if k in src and "\0" not in src[k]}
    if osv_mode == "online":
        env.update({k: src[k] for k in NET_ENV if k in src and "\0" not in src[k]})
    env["PATH"] = os.pathsep.join(p for p in (str(Path(sys.executable).parent), src.get("PATH", "")) if p)
    env.update(HOME=str(home), TMPDIR=str(home), PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
    return env


def build_command(project: Path, osv_mode: str, tool_timeout_s: float) -> list[str]:
    """argv of the worker: exactly the documented CLI, nothing else. Isolated mode (-I): no PYTHONPATH, no cwd, no user site."""
    argv = [sys.executable, "-I", "-m", "saferun", "scan", str(project), "--format", "json",
            "--timeout", f"{tool_timeout_s:g}"]
    if osv_mode == "offline":
        argv.append("--osv-offline")
    elif osv_mode == "disabled":
        argv.append("--no-dependency-scan")
    return argv


_EXIT_VERDICT = {0: "PASS", 1: "FAIL", 2: "WARNING"}


def parse_report(run: ToolRun) -> dict:
    """Return the report dict or raise ValueError (reason is generic - never raw tool output)."""
    if run.exit_code not in _EXIT_VERDICT:
        raise ValueError(f"worker exit code {run.exit_code}")
    try:
        data = json.loads(run.stdout)
    except (ValueError, RecursionError):
        raise ValueError("worker output is not JSON") from None
    if (not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION
            or data.get("verdict") not in {v.value for v in Verdict}
            or not isinstance(data.get("checks"), list) or not isinstance(data.get("reasons"), list)
            or not isinstance(data.get("complete"), bool) or not isinstance(data.get("workspace"), dict)):
        raise ValueError("worker output is not a SafeRun report")
    if _EXIT_VERDICT[run.exit_code] != data["verdict"]:
        raise ValueError("exit code and verdict disagree")
    return data


@dataclass
class Job:
    id: str
    osv_mode: str
    archive_path: str
    created: float                 # monotonic (TTL arithmetic)
    created_wall: float = 0.0      # epoch seconds, what the API reports
    status: str = "queued"
    finished: float | None = None
    archive: dict | None = None
    error: dict | None = None
    report: dict | None = None

    def public(self) -> dict:
        out = {"id": self.id, "status": self.status, "osv_mode": self.osv_mode,
               "created_at": round(self.created_wall, 3), "archive": self.archive, "error": self.error}
        if self.report is not None:
            out["report"] = self.report
        return out


def sweep_stale(max_age_s: float, tmp_root: Path | None = None, now: float | None = None) -> list[str]:
    """Delete crash leftovers: `saferun-up-*` directories and `saferun-upl-*` files owned by us and older than max_age_s."""
    root = Path(tmp_root or tempfile.gettempdir())
    now = time.time() if now is None else now
    removed = []
    for entry in os.scandir(root):
        if not entry.name.startswith((WORKDIR_PREFIX, UPLOAD_PREFIX)):
            continue
        try:
            st = entry.stat(follow_symlinks=False)
            if st.st_uid != os.getuid() or now - st.st_mtime < max_age_s:
                continue
            if stat.S_ISDIR(st.st_mode):
                shutil.rmtree(entry.path)
            elif stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                os.unlink(entry.path)
            else:
                continue
            removed.append(entry.name)
        except OSError:
            continue
    return removed


@dataclass
class JobManager:
    limits: JobLimits = field(default_factory=JobLimits)
    archive_limits: ArchiveLimits = field(default_factory=ArchiveLimits)
    command_builder: Callable[[Path, str, float], list[str]] = build_command
    tool_runner: Callable[..., ToolRun] = run_tool
    extractor: Callable[..., ExtractResult] = extract_zip
    reaper: Callable[[], object] | None = None          # called after a failed/killed job; errors are swallowed
    clock: Callable[[], float] = time.monotonic
    env_source: dict | None = None                      # tests only
    _jobs: dict[str, Job] = field(default_factory=dict, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _q: queue.Queue = field(default_factory=queue.Queue, init=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="saferun-worker", daemon=True)
            self._thread.start()

    def shutdown(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._q.put(None)
        if self._thread:
            self._thread.join(timeout)
        with self._lock:   # queued jobs will never run: delete their uploads
            for j in self._jobs.values():
                if j.status == "queued":
                    self._drop_upload(j)
                    j.status, j.error, j.finished = "failed", {"code": "shutdown", "message": "the server stopped"}, self.clock()

    # ---------------------------------------------------------------- API
    def _active(self) -> int:
        return sum(1 for j in self._jobs.values() if j.status in ("queued", "running"))

    def has_capacity(self) -> bool:
        with self._lock:
            return self._active() < 1 + self.limits.max_queue

    def submit(self, archive_path: str, osv_mode: str) -> Job:
        """Take ownership of `archive_path` (deleted when the job ends). Raises Busy; the caller then deletes the file."""
        if osv_mode not in OSV_MODES:
            raise ValueError("invalid osv mode")
        with self._lock:
            self._purge()
            if self._active() >= 1 + self.limits.max_queue:
                raise Busy()
            job = Job(secrets.token_urlsafe(16), osv_mode, archive_path, self.clock(), time.time())
            self._jobs[job.id] = job
        self._q.put(job.id)
        return job

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            self._purge()
            j = self._jobs.get(job_id)
            return j.public() if j else None

    def delete(self, job_id: str) -> bool:
        """Forget a finished job. A queued/running job cannot be deleted (409 semantics): returns False."""
        with self._lock:
            j = self._jobs.get(job_id)
            if j is None or j.status in ("queued", "running"):
                return False
            del self._jobs[job_id]
            return True

    def counts(self) -> dict:
        with self._lock:
            return {"active": self._active(), "capacity": 1 + self.limits.max_queue,
                    "stored_results": sum(1 for j in self._jobs.values() if j.status not in ("queued", "running"))}

    def _purge(self) -> None:   # caller holds the lock
        now = self.clock()
        done = sorted((j for j in self._jobs.values() if j.finished is not None), key=lambda j: j.finished)
        for j in done:
            if now - j.finished > self.limits.result_ttl_s:
                del self._jobs[j.id]
        done = [j for j in done if j.id in self._jobs]
        for j in done[: max(0, len(done) - self.limits.max_results)]:
            del self._jobs[j.id]

    # ---------------------------------------------------------------- worker
    def _loop(self) -> None:
        while not self._stop.is_set():
            job_id = self._q.get()
            if job_id is None or self._stop.is_set():
                return
            with self._lock:
                job = self._jobs.get(job_id)
                if job is None or job.status != "queued":
                    continue
                job.status = "running"
            reap = False
            try:
                status, report, error, reap = self._run(job)
            except BaseException as e:   # noqa: BLE001 - a bug must end the job, never the worker thread
                status, report, error = "failed", None, ("internal-error", f"internal error ({type(e).__name__})")
            # The result is published only AFTER the extraction directory and the upload are gone, so a client that
            # sees a finished job can rely on its data having been deleted.
            self._drop_upload(job)
            self._finish(job, status, report=report, error=error)
            if reap:
                self._reap()

    def _drop_upload(self, job: Job) -> None:
        try:
            os.unlink(job.archive_path)
        except OSError:
            pass

    def _finish(self, job: Job, status: str, *, report: dict | None = None, error: tuple[str, str] | None = None) -> None:
        with self._lock:
            job.status, job.report, job.finished = status, report, self.clock()
            job.error = {"code": error[0], "message": error[1]} if error else None

    def _reap(self) -> None:
        if self.reaper:
            try:
                self.reaper()
            except Exception:   # noqa: BLE001 - daemon down etc.; the next startup sweep retries
                pass

    def _run(self, job: Job) -> tuple[str, dict | None, tuple[str, str] | None, bool]:
        """Returns (status, report, error, reap_afterwards). Extraction and the worker's HOME are deleted before returning."""
        deadline = self.clock() + self.limits.job_deadline_s
        try:
            ex = self.extractor(job.archive_path, self.archive_limits)
        except ArchiveError as e:
            return "rejected", None, (e.code, e.message), False
        try:
            with self._lock:
                job.archive = {"entries": ex.archive_entries, "files": ex.files, "dirs": ex.dirs, "bytes": ex.bytes,
                               "stripped_prefix": ex.stripped_prefix, "excluded": list(ex.excluded),
                               "excluded_total": ex.excluded_total}
            home = ex.workdir / "home"
            home.mkdir(mode=0o700)
            remaining = deadline - self.clock()
            if remaining <= 1:
                return "failed", None, ("deadline", "the job exceeded its time limit"), False
            argv = self.command_builder(ex.project, job.osv_mode, self.limits.tool_timeout_s)
            env = worker_env(home, job.osv_mode, self.env_source)
            try:
                run = self.tool_runner(argv, cwd=ex.workdir, env=env, timeout_s=remaining,
                                       max_output=self.limits.max_output_bytes)
            except ToolUnavailable:
                return "failed", None, ("worker-unavailable", "the SafeRun worker could not be started"), False
            if run.timed_out:
                return "failed", None, ("deadline", "the job exceeded its time limit and was stopped"), True
            if run.output_truncated:
                return "failed", None, ("output-too-large", "the worker produced too much output"), True
            try:
                return "done", parse_report(run), None, False
            except ValueError as e:
                if run.exit_code in (64, 70):
                    return "failed", None, ("no-verdict", "the validation could not be completed (no verdict)"), True
                return "failed", None, ("bad-worker-output", clean_text(f"unusable worker result: {e}", 120)), True
        finally:
            try:
                ex.cleanup()
            except OSError:
                shutil.rmtree(ex.workdir, ignore_errors=True)

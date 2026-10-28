"""Run a command against an untrusted project inside a locked-down container."""
from __future__ import annotations

import math
import subprocess
import threading
import time
import uuid
from pathlib import Path

from . import docker as dk
from .config import (
    CONTAINER_LABEL, DEADLINE_LABEL, DEFAULT_IMAGE, REAP_MARGIN_S, SANDBOX_UID,
    ControlStatus, SandboxError, SandboxLimits, SandboxResult, SensitivePolicy, WorkspaceLimits,
)
from .controls import verify_applied_config
from .secrets import drop_partial_tail
from .workspace import Workspace, create_workspace

MAX_ARGS, MAX_ARG_LEN = 4096, 64 * 1024


def _check_mount_path(project: Path) -> None:
    """--mount values are comma-separated key=value CSV; refuse paths that could inject options."""
    s = str(project)
    if not project.is_absolute() or any(c in s for c in ',"') or not s.isprintable():
        raise SandboxError(f"workspace path contains unsupported characters: {s!r}")


def validate_command(command) -> list[str]:
    """argv for the container: a non-empty list of strings, argv[0] non-empty, no NUL bytes.
    (Never passed through a shell.)"""
    if (not isinstance(command, (list, tuple)) or not command or len(command) > MAX_ARGS
            or not all(isinstance(a, str) and len(a) <= MAX_ARG_LEN and "\0" not in a for a in command)
            or not command[0]):
        raise SandboxError("command must be a non-empty list of strings with a non-empty first element")
    return list(command)


def build_create_args(
    name: str, project: Path, command: list[str], image: str, lim: SandboxLimits
) -> list[str]:
    """docker-create arguments. Every security control lives here."""
    _check_mount_path(project)
    mem = f"{lim.memory_mb}m"
    container_timeout = math.ceil(lim.timeout_s + lim.container_grace_s)
    deadline = int(time.time() + container_timeout + REAP_MARGIN_S)
    return [
        "create", "--name", name, "--label", CONTAINER_LABEL,
        "--label", f"{DEADLINE_LABEL}={deadline}",
        "--pull", "never",                        # never fetch an image (no host egress, no tag swap)
        "--network", "none",                      # no network at all
        "--read-only",                            # immutable root fs
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={lim.tmpfs_mb}m",
        "--shm-size", f"{lim.shm_mb}m",
        "--mount", f"type=bind,src={project},dst=/workspace,readonly",
        "--workdir", "/workspace",
        "--entrypoint", "",                       # the image's ENTRYPOINT must not reinterpret our argv
        "--user", f"{SANDBOX_UID}:{SANDBOX_UID}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",    # daemon-default seccomp + AppArmor kept, checked in preflight
        "--memory", mem, "--memory-swap", mem,    # no swap
        "--cpus", str(lim.cpus),
        "--pids-limit", str(lim.pids),
        "--ulimit", f"nofile={lim.nofile}:{lim.nofile}",
        "--ulimit", f"fsize={lim.fsize_mb * 1024 * 1024}",
        "--ulimit", "core=0",
        "--log-driver", "none",                   # no host-disk log growth
        "--init",
        "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
        image,
        # Container-side deadline: still fires if the SafeRun process dies mid-run.
        "timeout", "-s", "KILL", str(container_timeout), *command,
    ]


def _drain(stream, cap: int, buf: bytearray, flag: list[bool]) -> None:
    """Keep up to `cap` bytes; keep reading (and discarding) so the child never blocks."""
    while chunk := stream.read(65536):
        room = cap - len(buf)
        if room > 0:
            buf += chunk[:room]
        if len(chunk) > room:
            flag[0] = True


def _execute(name: str, ws: Workspace, command: list[str], image: str, image_id: str,
             daemon_statuses: list[ControlStatus], lim: SandboxLimits) -> SandboxResult:
    r = dk.docker(*build_create_args(name, ws.project, command, image_id, lim))
    if r.returncode != 0:
        raise SandboxError(f"docker create failed: {r.stderr.strip()}")

    # Fail closed: verify what Docker actually created BEFORE any untrusted code can start.
    info = dk.inspect(name)
    if not info:
        raise SandboxError("docker create succeeded but the container cannot be inspected")
    checks = verify_applied_config(info, lim, image_id)
    bad = [c for c in checks if c.state != "verified"]
    if bad:
        raise SandboxError("container was not started: applied configuration violates the sandbox policy: "
                           + "; ".join(f"{c.name} ({c.detail})" for c in bad))

    out, err, trunc = bytearray(), bytearray(), [False]
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(
            [dk.docker_bin(), "start", "-a", name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
        )
    except OSError as e:
        raise SandboxError(f"could not start the docker client: {e}") from e
    threads = [
        threading.Thread(target=_drain, args=(s, lim.max_output_bytes, b, trunc), daemon=True)
        for s, b in ((proc.stdout, out), (proc.stderr, err))
    ]
    for t in threads:
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=lim.timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        dk.docker("kill", name)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            raise SandboxError(f"container {name} did not stop within 30 s of being killed") from None
    for t in threads:
        t.join(timeout=5)
    duration = time.monotonic() - t0

    info = dk.inspect(name)
    state = info.get("State") if info else None
    if not isinstance(state, dict) or not isinstance(state.get("ExitCode"), int):
        raise SandboxError(f"could not read the final state of container {name}; outcome unknown")
    texts, redactions = [], 0
    for buf in (out, err):
        text = buf.decode("utf-8", "replace")
        if trunc[0]:
            text = drop_partial_tail(text)  # a cut-off secret prefix would evade redaction
        text, n = ws.redactor.redact(text)
        texts.append(text)
        redactions += n
    return SandboxResult(
        exit_code=state["ExitCode"],
        stdout=texts[0],
        stderr=texts[1],
        redactions=redactions,
        withheld=ws.withheld,
        timed_out=timed_out,
        oom_killed=bool(state.get("OOMKilled")),
        output_truncated=trunc[0],
        duration_s=duration,
        container_name=name,
        hardening=info.get("HostConfig", {}),
        controls=[*daemon_statuses, *checks],
        image_id=image_id,
        skipped=ws.skipped,
        entries_scanned=ws.entries_scanned,
        copied_files=ws.copied_files,
        copied_dirs=ws.copied_dirs,
        copied_bytes=ws.copied_bytes,
    )


def _cleanup(name: str, ws: Workspace) -> list[str]:
    """Run BOTH cleanup steps whatever happens to the first; return problems."""
    problems = []
    try:
        if not dk.force_remove(name):
            problems.append(f"container {name} still present")
    except Exception as e:
        problems.append(f"container {name}: {e}")
    try:
        ws.cleanup()
    except Exception as e:
        problems.append(f"workspace {ws.root}: {e}")
    return problems


def run_sandboxed(
    project_dir: Path,
    command: list[str],
    limits: SandboxLimits | None = None,
    image: str = DEFAULT_IMAGE,
    workspace_limits: WorkspaceLimits | None = None,
    sensitive_policy: SensitivePolicy | None = None,
    allow_degraded: frozenset[str] = frozenset(),
) -> SandboxResult:
    """Run `command` (argv, no shell) against a sanitized copy of `project_dir`.

    `allow_degraded` names daemon controls (see controls.REQUIRED_DAEMON) the caller accepts
    as unavailable; they are still reported in `SandboxResult.controls`.
    """
    lim = limits or SandboxLimits()
    command = validate_command(command)
    image_id, daemon_statuses = dk.preflight(image, frozenset(allow_degraded))
    ws = create_workspace(project_dir, workspace_limits, sensitive_policy)
    name = f"saferun-{uuid.uuid4().hex[:12]}"
    primary: BaseException | None = None
    try:
        return _execute(name, ws, command, image, image_id, daemon_statuses, lim)
    except BaseException as e:
        primary = e
        raise
    finally:
        problems = _cleanup(name, ws)
        if problems:
            msg = "; ".join(problems)
            if primary is not None:
                primary.add_note(f"SafeRun cleanup also failed: {msg}")  # keep the original error
            else:
                raise SandboxError(f"cleanup failed: {msg}")

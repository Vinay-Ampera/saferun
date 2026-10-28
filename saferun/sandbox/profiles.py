"""Runtime profiles: which image runs which kind of project.

A profile is only a name for an image. The sandbox itself is image-agnostic: every profile gets
exactly the same restrictions, verified the same way. A profile does NOT imply anything about
dependency installation, test runners or analyzers (those belong to Phase 2+).

Requirements for any image: Linux; `timeout` (coreutils or busybox) and `sh` on PATH; no VOLUME
declarations; a `nobody` user is not required (the uid is set numerically).
"""
from __future__ import annotations

from dataclasses import dataclass

from .config import SandboxError


@dataclass(frozen=True)
class RuntimeProfile:
    name: str
    image: str          # tag for now; pass a digest reference to pin (Phase 5)
    interpreter: str    # binary used to run a project file / self-checks
    description: str = ""


PYTHON = RuntimeProfile("python", "python:3.12-slim", "python", "CPython 3.12 (Debian slim)")
NODE = RuntimeProfile("node", "node:22-slim", "node", "Node.js 22 LTS (Debian slim)")
PROFILES: dict[str, RuntimeProfile] = {p.name: p for p in (PYTHON, NODE)}


def get_profile(name: str) -> RuntimeProfile:
    try:
        return PROFILES[name]
    except KeyError:
        raise SandboxError(f"unknown runtime profile {name!r}; known: {sorted(PROFILES)}") from None

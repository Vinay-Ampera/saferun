"""Shared inputs for checks."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..sandbox import docker as _docker
from ..sandbox import run_sandboxed
from .tools import ToolRunner, run_tool


@dataclass
class CheckContext:
    project: Path                 # sanitized copy of the project (never the user's original directory)
    home: Path                    # private scratch/HOME for analyzers
    files: list[str]              # relative posix paths of every regular file in `project`
    run: ToolRunner = run_tool    # host analyzer runner; injectable for tests
    sandbox: Callable = run_sandboxed                    # container runner; injectable for tests
    image_available: Callable[[str], None] = _docker.check_available  # raises SandboxError if unusable
    timeout_s: float = 120.0
    max_output: int = 8 * 1024 * 1024
    max_findings: int = 1000
    options: dict = field(default_factory=dict)

"""Path normalisation for untrusted tool output."""
from __future__ import annotations

import posixpath
from pathlib import Path

from .model import clean_text


def rel_path(value, root: Path) -> str | None:
    """A tool-reported path as a clean, relative, posix path inside `root`; None if it is not one."""
    if not isinstance(value, str) or not value or "\0" in value:
        return None
    p = value
    if posixpath.isabs(p):
        r = str(root.resolve()) + "/"
        if not p.startswith(r) and not p.startswith(str(root) + "/"):
            return None
        p = p[len(r):] if p.startswith(r) else p[len(str(root)) + 1:]
    p = posixpath.normpath(p)
    if p in (".", "") or p == ".." or p.startswith("../") or posixpath.isabs(p):
        return None
    return clean_text(p, 300)

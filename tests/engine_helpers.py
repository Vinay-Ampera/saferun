"""Shared helpers for engine tests (canned tool output; no network, no real tools needed)."""
import json
from pathlib import Path

from saferun.engine.context import CheckContext
from saferun.engine.tools import ToolRun


def tool_run(stdout="", exit_code=0, stderr="", timed_out=False, truncated=False):
    return ToolRun(argv=["/x"], exit_code=None if timed_out or truncated else exit_code, stdout=stdout,
                   stderr=stderr, timed_out=timed_out, output_truncated=truncated)


class FakeRunner:
    """Records calls; returns a canned ToolRun (or raises)."""
    def __init__(self, result=None, exc=None):
        self.result, self.exc, self.calls = result, exc, []

    def __call__(self, argv, *, cwd, env, timeout_s, max_output):
        self.calls.append({"argv": argv, "cwd": cwd, "env": env, "timeout_s": timeout_s})
        if self.exc:
            raise self.exc
        return self.result


def make_ctx(tmp_path: Path, files, runner=None, **kw) -> CheckContext:
    proj = tmp_path / "project"
    proj.mkdir(exist_ok=True)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for f in files:
        p = proj / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")
    args = dict(project=proj, home=home, files=list(files))
    if runner is not None:
        args["run"] = runner
    args.update(kw)
    return CheckContext(**args)


SEMGREP_JSON = json.dumps({
    "version": "1.0", "errors": [], "paths": {"scanned": ["app.py", "lib/h.py"]},
    "results": [
        {"check_id": "saferun.python.dynamic-code-execution", "path": "app.py",
         "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 12},
         "extra": {"message": "eval() is dangerous", "severity": "ERROR",
                   "metadata": {"saferun_severity": "high", "cwe": ["CWE-95"]}}},
        {"check_id": "saferun.python.weak-hash", "path": "lib/h.py", "start": {"line": 9}, "end": {"line": 9},
         "extra": {"message": "md5", "severity": "WARNING", "metadata": {"saferun_severity": "medium"}}},
    ]})

OSV_JSON = json.dumps({"results": [{
    "source": {"path": "/IGNORED/package-lock.json", "type": "lockfile"},
    "packages": [{
        "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
        "vulnerabilities": [
            {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "summary": "Command injection in lodash",
             "database_specific": {"severity": "HIGH"},
             "affected": [{"package": {"name": "lodash"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]},
            {"id": "CVE-2021-23337", "aliases": ["GHSA-35jh-r3h4-6jhm"], "summary": "dup under another id"},
            {"id": "GHSA-xxxx-low", "aliases": [], "summary": "minor", "database_specific": {"severity": "LOW"}},
        ],
        "groups": [{"ids": ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"], "max_severity": "7.2"}],
    }]}]})


def smart_sandbox(node_stdout=None):
    """Fake sandbox: answers the Python syntax driver by listing .py files (all valid), and the Node driver
    with `node_stdout` (default: all valid .js files)."""
    import json as _json

    def fake(project, command, limits=None, image=None, **_):
        from types import SimpleNamespace
        proj = Path(project)
        if command[0] == "python":
            files = sorted(str(p.relative_to(proj)) for p in proj.rglob("*") if p.suffix in (".py", ".pyi") and p.is_file())
            lines = [_json.dumps({"file": f, "ok": True}) for f in files] + [_json.dumps({"done": True, "count": len(files), "truncated": False})]
        elif node_stdout is not None:
            lines = [node_stdout]
        else:
            files = sorted(str(p.relative_to(proj)) for p in proj.rglob("*") if p.suffix in (".js", ".mjs", ".cjs") and p.is_file())
            lines = [_json.dumps({"file": f, "status": 0, "signal": None, "failed": False, "err": ""}) for f in files]
            lines.append(_json.dumps({"done": True, "count": len(files), "truncated": False}))
        return SimpleNamespace(exit_code=0, stdout="\n".join(lines) + "\n", stderr="", timed_out=False, oom_killed=False, output_truncated=False)
    return fake


def overrides(run=None, node_stdout=None):
    d = {"sandbox": smart_sandbox(node_stdout), "image_available": lambda image: None}
    if run is not None:
        d["run"] = run
    return d


def sg_json(results=(), scanned=("app.py", "lib/h.py"), errors=()):
    """Semgrep-shaped JSON; `scanned=None` omits paths entirely."""
    d = {"results": list(results), "errors": list(errors)}
    if scanned is not None:
        d["paths"] = {"scanned": list(scanned)}
    return json.dumps(d)

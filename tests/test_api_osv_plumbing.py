"""OSV mode plumbing through the REAL chain (API -> worker CLI -> engine -> tool) with a recording fake `osv-scanner`.

Proves what the tool is actually given, without network: online passes proxy/cert variables and no `--offline`;
offline passes `--offline` and no proxy variables; disabled never starts the tool; secrets never reach it.
(The real binary is exercised by tests/test_engine_real_tools.py and was run through the API by hand, see IMPLEMENTATION.md.)
No Docker needed: the project contains only a requirements.txt, so the sandboxed checks are not applicable.
"""
import io
import json
import os
import stat
import time
import zipfile

import pytest
from starlette.testclient import TestClient

from saferun.api.app import create_app
from saferun.api.jobs import JobLimits, JobManager

H = {"X-SafeRun-Request": "1", "Content-Type": "application/zip"}


@pytest.fixture
def setup(tmp_path, ws_root, monkeypatch):
    record = tmp_path / "osv-record.txt"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "osv-scanner"
    exe.write_text(f'#!/bin/sh\n{{ echo "ARGV: $*"; env; }} > {record}\necho \'{{"results": []}}\'\nexit 0\n')
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
    monkeypatch.setenv("SECRET_TOKEN_FOR_TEST", "must-never-reach-the-tool")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-never-reach-the-tool")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("requirements.txt", "six==1.17.0\n")
    c = TestClient(create_app(JobManager(JobLimits(job_deadline_s=120)), run_startup_cleanup=False, static_dir=None),
                   base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000))
    with c:
        yield c, buf.getvalue(), record


def run(c, data, mode):
    sid = c.post(f"/api/scans?osv={mode}", content=data, headers=H).json()["id"]
    end = time.monotonic() + 90
    while time.monotonic() < end:
        j = c.get(f"/api/scans/{sid}").json()
        if j["status"] not in ("queued", "running"):
            return j
        time.sleep(0.2)
    raise AssertionError("timeout")


def dep(job):
    return next(c for c in job["report"]["checks"] if c["name"] == "dependency-vulnerabilities")


def test_online_mode_gives_the_tool_network_settings_and_no_offline_flag(setup):
    c, data, record = setup
    job = run(c, data, "online")
    assert job["status"] == "done" and dep(job)["status"] == "passed" and job["report"]["verdict"] == "PASS"
    text = record.read_text()
    assert "--offline" not in text.splitlines()[0] and "--no-resolve" in text.splitlines()[0]
    assert "HTTPS_PROXY=http://proxy.invalid:3128" in text and "SSL_CERT_FILE=" in text
    assert "must-never-reach-the-tool" not in text


def test_offline_mode_passes_offline_and_no_proxy_settings(setup):
    c, data, record = setup
    job = run(c, data, "offline")
    assert job["status"] == "done" and dep(job)["status"] == "passed"
    text = record.read_text()
    assert "--offline" in text.splitlines()[0]
    assert "HTTPS_PROXY" not in text and "SSL_CERT_FILE" not in text and "must-never-reach-the-tool" not in text


def test_disabled_mode_never_starts_the_tool_and_is_never_a_plain_pass(setup):
    c, data, record = setup
    job = run(c, data, "disabled")
    assert job["status"] == "done" and dep(job)["status"] == "skipped" and not record.exists()
    assert job["report"]["verdict"] == "WARNING" and job["report"]["complete"] is False


def test_tool_environment_is_minimal(setup):
    c, data, record = setup
    run(c, data, "offline")
    names = {line.split("=", 1)[0] for line in record.read_text().splitlines()[1:] if "=" in line}
    assert not ({"SECRET_TOKEN_FOR_TEST", "AWS_SECRET_ACCESS_KEY", "PYTHONPATH", "SSH_AUTH_SOCK", "GITHUB_TOKEN"} & names)

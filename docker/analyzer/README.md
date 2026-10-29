# Analyzer image build recipe (Phase 5A)

Build recipe only. SafeRun does **not** use this image yet; running Semgrep and OSV-Scanner inside the sandbox is Phase 5B.

| Item | Pin | Verification |
|---|---|---|
| Base image | `python:3.12-slim@sha256:78387bc3…` | `FROM` by digest; `build.sh` runs `saferun verify-images` first |
| Semgrep | `1.182.1`, 66 wheels | `pip --require-hashes --only-binary=:all:` against `semgrep-requirements.txt` |
| OSV-Scanner | `2.7.0` linux/amd64 | `fetch_verified.py` compares the SHA-256 of the download and aborts the build on mismatch |

Limits: the lock covers linux/amd64 and CPython 3.12 only. The OSV-Scanner checksum was taken from the upstream release
`osv-scanner_SHA256SUMS` (same GitHub trust root as the binary; it protects against corruption and later tampering of the
download, not against a compromised upstream release) and matches the binary used by the host-side checks.

Regenerate the Semgrep lock when bumping the version (`images.py`, `Dockerfile` and this lock must agree):

    python -m pip download semgrep==<version> -d wheels/
    # one line per wheel: name==version --hash=sha256:$(sha256sum wheel)

`tests/test_image_pins.py` fails if the pins in `saferun/sandbox/images.py`, the Dockerfile and the lock drift apart.

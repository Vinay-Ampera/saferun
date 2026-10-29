# Prebuilt images: what exists, and what must exist first

`saferun init` installs three kinds of image/data. Only some can be fetched prebuilt today.

| Component | How `saferun init` gets it today | Trust anchor |
|---|---|---|
| Python / Node.js sandbox images | `docker pull python@sha256:… / node@sha256:…` (digest from `saferun/sandbox/images.py`) | The pinned manifest digest, verified again afterwards against the image's `RepoDigests` (`saferun verify-images`). Docker rejects content that does not hash to the digest. |
| Analyzer image (Semgrep, OSV-Scanner, rules) | **Built locally** with `docker/analyzer/build.sh` | Hash-locked Semgrep wheels, checksum-verified OSV-Scanner, digest-pinned base; the built image's ID is written to an owner-only lock file and re-checked, with tool-version and rules-hash labels, before every use. |
| OSV vulnerability data | `saferun osv-db update` (HTTPS, public data) | Server MD5 + a locally recorded SHA-256 manifest. Detects corruption and later changes, **not** a malicious server (see `docs/cli.md`). |

## Why the analyzer is not downloaded yet
No registry, repository or published digest for a SafeRun analyzer image exists, and none is invented here. `saferun/sandbox/images.py` therefore has
`ANALYZER_RELEASE = None`, and `saferun init` builds locally. The download code path is already in place (`Setup._install_analyzer_release`, covered by tests with a fake Docker)
and switches on when `ANALYZER_RELEASE` is set.

## What maintainers must do before a prebuilt analyzer can be offered
1. Choose and own a registry repository (for example a GitHub Container Registry package) and decide who may push to it.
2. Build the image in CI from this repository's recipe (`docker/analyzer/`, the pinned base digest, hash-locked wheels, the rules file of the release) for `linux/amd64`.
3. Record the pushed **manifest digest** in `ANALYZER_RELEASE` (repository, `sha256:…`, date) in the same commit/tag that contains the rules the image was built with; the
   image's `saferun.rules.sha256` label must equal that commit's rules hash, so image and code release together.
4. Strongly recommended: sign the image (cosign) and publish the verification identity; teach `saferun init` to verify the signature before locking. Without a signature the
   digest in the repository is the only trust anchor (anyone who can change `images.py` can point users at another image).
5. Document the update policy (when the digest changes, how users re-run `saferun init`) and keep the local build workflow for development and for auditing the published image.

What `saferun init` does with a published image (already implemented, inactive): pull `repository@digest` → confirm the pulled image carries exactly that digest → tag it
`saferun-analyzer:local` → check labels (tool versions, rules hash) → write the owner-only lock → verify with the same function every scan uses. Any failure leaves the image **untrusted** and unlocked.

## Offline machines
Prepare on a connected machine and copy: the OSV directory (`saferun osv-db update --dir DIR`, relocatable, then `SAFERUN_OSV_DB=DIR` or place it at the default location) and the
images (`docker save` / `docker load`). SafeRun trusts a loaded image only if Docker reports the pinned registry digest for it; if your Docker drops repository digests on `docker load`,
`saferun status` reports the image as invalid. That behaviour has not been tested against every Docker version.
**The analyzer cannot be installed on a machine that never has internet access yet**: its lock file is written only by a local build or by a verified published-image install, and no
supported "import a loaded analyzer image" step exists. Until a release with a published digest exists, build it once while online (`saferun init --only analyzer`), or build elsewhere and
rebuild/verify on the target. This is a known gap, not something the setup command works around.

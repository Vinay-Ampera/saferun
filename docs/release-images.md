# Prebuilt images: what exists, and how the analyzer image is released

`saferun init` installs three kinds of image/data.

| Component | How `saferun init` gets it | Trust anchor |
|---|---|---|
| Python / Node.js sandbox images | `docker pull python@sha256:… / node@sha256:…` (digest from `saferun/sandbox/images.py`) | The pinned manifest digest, verified again afterwards against the image's `RepoDigests` (`saferun verify-images`). Docker rejects content that does not hash to the digest. |
| Analyzer image (Semgrep, OSV-Scanner, rules) | **Published release** (`ghcr.io/vinay-ampera/saferun-analyzer@sha256:3b7adfc9…`, tag `analyzer-v1.0.0`, cosign-signed), recorded in `ANALYZER_RELEASE`; with `--build-local` it is **built locally** with `docker/analyzer/build.sh` instead | Release: the cosign signature (GitHub Actions identity of this repository's release workflow) **and** the pinned digest, then labels/tool versions/rules hash, then an owner-only lock file. Local build: hash-locked wheels, checksum-verified OSV-Scanner, digest-pinned base, owner-only lock file. |
| OSV vulnerability data | `saferun osv-db update` (HTTPS, public data) | Server MD5 + a locally recorded SHA-256 manifest. Detects corruption and later changes, **not** a malicious server (see `docs/cli.md`). |

**Status:** release `analyzer-v1.0.0` was built, pushed and signed by the release workflow (run for commit `f351608`, 2026-10-29) and is recorded in `ANALYZER_RELEASE`
(`sha256:3b7adfc9b5052d1c7168df8be2cf8a6f5d3da6135d67db813586e1cf43a59508`). `saferun init` therefore installs it, which requires `cosign` (below). The signature check is implemented and tested with
fakes; **the first real `cosign verify` against this image is the maintainer's step 5 below** and had not been run when this was written. Nothing is published or recorded automatically.

## How an install of the published image works
1. **Verify the signature first.** `cosign verify --certificate-identity-regexp <identity> --certificate-oidc-issuer https://token.actions.githubusercontent.com --output json <repo>@<digest>`.
   The identity must be this repository's `release-analyzer.yml` workflow run for a **tag** `analyzer-v<number>[.<number>…]` (a branch, a pull request, another workflow or another
   repository is refused). SafeRun also checks that the signed payload names exactly this repository and digest. Nothing has been pulled at this point.
2. `docker pull <repo>@<digest>`; confirm the local image carries exactly that digest in `RepoDigests`.
3. Tag it `saferun-analyzer:local`; check the labels (Semgrep and OSV-Scanner versions, rules hash equal to this checkout's `python.yml`).
4. Write the owner-only lock file. Every scan afterwards verifies lock, image ID and labels as before.

Any failure leaves the image **untrusted and unlocked**. There is no unsigned install and no automatic fallback: if `cosign` is not installed or the signature does not verify, `init` says so and
stops; building locally is an explicit choice (`saferun init --only analyzer --build-local`). `saferun verify-images --signature` repeats step 1 on demand (online).

Requirements on the user's machine: Docker, internet access to `ghcr.io`, `tuf-repo-cdn.sigstore.dev` and `rekor.sigstore.dev` during `init`, and
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 2.2 or newer on `PATH`. cosign runs on the host (argv only, minimal environment, private HOME, 120 s timeout) and parses
registry/Sigstore data there; that is why the image is not pulled until the signature has verified. Scans never use the network.

## Publishing a release (maintainer)
One-time setup on GitHub for `Vinay-Ampera/saferun`: Actions enabled; the workflow needs no secrets beyond the automatic `GITHUB_TOKEN` (it asks for `packages: write` and `id-token: write` itself).
1. Commit and push the repository, including `.github/workflows/release-analyzer.yml`, to `main`.
2. Push a tag on a `main` commit: `git tag analyzer-v1.0.0 && git push origin analyzer-v1.0.0`. The workflow refuses other tag names and commits not on `main`, builds the image from `docker/analyzer/`
   (`linux/amd64`, single manifest), pushes `ghcr.io/vinay-ampera/saferun-analyzer:analyzer-v1.0.0`, signs the **digest** (keyless), verifies the signature with the same identity expression SafeRun uses,
   and prints the digest in the run summary.
3. **First release only (done for `analyzer-v1.0.0`):** make the package public (GitHub → Packages → saferun-analyzer → Package settings → Change visibility → Public). ghcr.io creates packages private, and `saferun init` pulls anonymously.
4. In a reviewed commit, record it in `saferun/sandbox/images.py`: `ANALYZER_RELEASE = AnalyzerRelease(ANALYZER_REGISTRY_REPOSITORY, "sha256:<digest from the run>", "<date>")`. The rules
   (`saferun/engine/rules/python.yml`) in that commit must be the ones the tag was built from, otherwise the label check fails for every user (a test and `saferun status` show it).
5. Check it from a clean machine: `saferun verify-images --signature`, then `saferun init --only analyzer`.
6. Update policy: a new analyzer version (new Semgrep/OSV-Scanner pin or new rules) is a new tag, a new digest and a new commit; users re-run `saferun init` (status shows the analyzer as invalid/outdated until they do).

## What this does and does not give
* The digest pins the exact bytes; the signature says those bytes were produced by this repository's release workflow from a tag, recorded in the public Sigstore transparency log. Someone who edits
  `ANALYZER_RELEASE` to point at another image cannot also produce a signature with the expected identity.
* It does **not** prove the workflow or repository was free of compromise at release time, that the pinned tools are free of vulnerabilities, or that cosign itself is correct. If the GitHub account
  or the repository is taken over, new tags could be signed with the expected identity: protect the account (2FA) and review tags.
* Verification needs cosign and internet at install time. After installation the trust anchor is the local lock file, with the limits stated in `PROJECT.md` (*Phase 5 security status*): the same user, root or
  a member of the `docker` group can still replace the local image and lock.
* Not tested against a real cosign binary or a real ghcr.io image (none exists yet); the first release must be followed by step 5.

## Offline machines
Prepare on a connected machine and copy: the OSV directory (`saferun osv-db update --dir DIR`, relocatable, then `SAFERUN_OSV_DB=DIR` or place it at the default location) and the
images (`docker save` / `docker load`). SafeRun trusts a loaded image only if Docker reports the pinned registry digest for it; if your Docker drops repository digests on `docker load`,
`saferun status` reports the image as invalid. That behaviour has not been tested against every Docker version.
**The analyzer still cannot be installed on a machine that never has internet access**: its lock file is written only by a local build or by a verified published-image install (which needs the
registry and Sigstore), and no supported "import a loaded analyzer image" step exists. Build it once while online (`saferun init --only analyzer`, or `--build-local`) or build elsewhere and
rebuild/verify on the target. This is a known gap, not something the setup command works around.

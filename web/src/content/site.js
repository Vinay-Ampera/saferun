// Single source of truth for text shown on more than one page (website and setup guide), so the two cannot drift apart.

export const GITHUB = 'https://github.com/Vinay-Ampera/saferun'
export const DOCS = GITHUB + '/blob/main/docs/'

export const TRUST = [
  ['Your code is never run', 'Static checks only: nothing you submit is executed.'],
  ['Scans work offline', 'No network inside the analyzer container.'],
  ['Locked-down containers', 'Sandbox isolation: read-only copy, non-root, no capabilities.'],
  ['Signed analyzer image', 'Cosign signature plus a pinned digest, verified before use.'],
]

// [title, text, command]
export const STEPS = [
  ['Set up', 'Run saferun init once. It installs only what is missing.', 'saferun init'],
  ['Verify', 'Check that every part is ready and verified.', 'saferun status'],
  ['Scan', 'Scan a folder, or drop a ZIP on the dashboard.', 'saferun scan ./my-project'],
]

export const REQUIREMENTS = [
  ['Operating system', 'Linux. The analyzer image is linux/amd64 only; ARM64 is not supported yet.'],
  ['Python', '3.12 or newer, with venv and pip.'],
  ['Docker', 'A local Docker Engine that your user can reach, with memory, swap, pids and CPU limits and seccomp enabled. Remote Docker endpoints are refused. Docker Desktop is not tested.'],
  ['Cosign', '2.2 or newer, on your PATH. Needed once, to verify the signed analyzer image. SafeRun does not install it for you.'],
  ['Internet', 'Only for setup (Docker Hub, ghcr.io, sigstore.dev, the OSV download). Scans never use the network.'],
  ['Disk space', 'About 1.5 GB for images and vulnerability data.'],
]
export const requirement = (name) => REQUIREMENTS.find(([n]) => n === name)[1]

// [key, icon, label, meaning, what to do]
export const VERDICTS = [
  ['pass', '✓', 'PASS', 'Every check ran and found nothing.', 'Looks fine, but it is not a proof of safety.'],
  ['warn', '!', 'WARNING', 'Minor findings, or a check could not run (missing or outdated component).', 'Run saferun status, apply the fix, scan again.'],
  ['fail', '✕', 'FAIL', 'At least one high or critical finding.', 'Do not run the project until it is fixed.'],
]

// [title, text]
export const SAFETY = [
  ['Your project is never executed', 'It is copied read-only into a throwaway container: no network, non-root user, no Linux capabilities, memory, CPU and process limits.'],
  ['Images are pinned by digest', 'An image is trusted only if Docker reports the exact pinned digest. A tag that merely exists is not enough.'],
  ['The analyzer download is signed', 'SafeRun checks a cosign signature, tied to this project\'s release workflow and a release tag, before it pulls the image, then checks the pinned digest again. A signature does not prove the project itself was never compromised.'],
  ['The analyzer is locked', 'Its image ID, tool versions and rules hash are re-checked before every scan. The lock file must be private to your user.'],
  ['Vulnerability data has an integrity record', 'SHA-256, size, advisory count and date are re-checked before every scan. Damaged, tampered or old data cannot produce PASS.'],
  ['The dashboard stays on your machine', 'It accepts connections only from your own computer (loopback) and has no login.'],
]

export const HONEST_LIMITS = 'Honest limits: these checks detect damage and later changes, but a locally recorded hash cannot prove the original download was genuine. PASS means the existing checks found nothing, not that the code is safe. Scans send nothing anywhere and are only as current as your last saferun osv-db update.'

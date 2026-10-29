import { Footer } from '../../components/Footer/Footer'
import { Header } from '../../components/Header/Header'
import './GuidePage.css'

const INCLUDED = [
  ['SafeRun engine, CLI and local dashboard', 'This repository. Nothing else to download for the code itself.'],
  ['Restricted sandbox logic', 'Read-only copy, no network, non-root, no capabilities, resource limits.'],
  ['Python syntax check, Semgrep rules', 'Rules ship in saferun/engine/rules/python.yml.'],
  ['Semgrep (Python package)', 'Not bundled, but installed with: pip install -e ".[dev,web,analysis]".'],
]
const INSTALL = [
  ['Linux, Python 3.12+', 'Required.'],
  ['Docker Engine (local)', 'Required for the sandboxed syntax check. Your user must be able to run docker.'],
  ['docker pull python:3.12-slim', 'Required. SafeRun never pulls images itself.'],
  ['docker pull node:22-slim', 'Only for JavaScript projects.'],
  ['osv-scanner', 'Optional but recommended. A separate Go binary from google.github.io/osv-scanner; without it the dependency check is "unavailable" and the verdict is at best WARNING.'],
  ['Node.js + npm', 'Only to build or run this dashboard (web/), not to scan.'],
]
const STEPS = [
  'python3 -m venv .venv && .venv/bin/pip install -e ".[dev,web,analysis]"',
  'docker pull python:3.12-slim   (and node:22-slim for JS)',
  'Install osv-scanner and make sure it is on your PATH',
  'cd web && npm ci --ignore-scripts && npm run build',
  '.venv/bin/saferun-web   then open http://127.0.0.1:8765/   (for development: python -m saferun.api plus npm run dev, then http://localhost:5173)',
  'Zip your project (files at the top level or inside one folder), drop it on the dashboard, read the verdict. CLI alternative: saferun scan ./my-project',
]
const CHECKS = [
  ['Sensitive files', 'Built-in', 'Flags keys, tokens and .env-style files and withholds them from analysis.', 'Ready'],
  ['Python syntax', 'Python compile() in the Docker sandbox', 'Finds syntax errors without running your code.', 'Ready'],
  ['Python static analysis', 'Semgrep', 'Risky patterns: eval, shell=True, pickle, unsafe yaml, verify=False, weak hashes, hardcoded secrets, Flask debug.', 'Ready'],
  ['Dependency vulnerabilities', 'osv-scanner / OSV.dev', 'Known CVEs in requirements.txt and lockfiles.', 'Ready (needs osv-scanner)'],
  ['JavaScript syntax', 'node --check in the sandbox', 'Syntax errors in JS files.', 'Ready'],
  ['JavaScript dependency installation, test runners, JS Semgrep rules', '-', 'Running your tests and deeper JS analysis.', 'Planned'],
  ['Runtime behaviour (actually running the project)', 'Sandbox', 'Observing what the code does when executed.', 'Planned'],
]
const VERDICTS = [
  ['PASS', 'Nothing was flagged and every check completed. Looks fine to go ahead, but it is not a proof of safety.'],
  ['WARNING', 'Minor findings, or a check could not run (for example osv-scanner is missing). Review, fix, scan again.'],
  ['FAIL', 'At least one high or critical finding. Do not run the project until it is fixed.'],
]

export function GuidePage() {
  return (
    <div className="shell">
      <Header />
      <main className="guide">
        <h1>How to use SafeRun</h1>
        <p className="muted">SafeRun checks AI-generated code before you run or trust it. It never executes your project on the host, and a passing scan is not a guarantee of security.</p>

        <section className="card"><h2>Already included with the code</h2>
          <ul>{INCLUDED.map(([a, b]) => <li key={a}><strong>{a}</strong> - {b}</li>)}</ul></section>

        <section className="card"><h2>What a developer must install</h2>
          <ul>{INSTALL.map(([a, b]) => <li key={a}><strong>{a}</strong> - {b}</li>)}</ul></section>

        <section className="card"><h2>Steps</h2>
          <ol>{STEPS.map((s) => <li key={s}><code>{s}</code></li>)}</ol>
          <p className="muted">Sandbox: each scan copies your project read-only into a throwaway Docker container with no network, a non-root user, dropped capabilities and memory/CPU/process limits. It is deleted afterwards.</p></section>

        <section className="card"><h2>What the ZIP needs</h2>
          <ul>
            <li>Project files at the top level, or inside one top-level folder.</li>
            <li>Up to 25 MiB compressed, 100 MiB extracted and 5000 files.</li>
            <li>No unsafe entries (path traversal, symlinks); otherwise the whole archive is refused.</li>
            <li>Include requirements.txt or a lockfile so dependencies can be checked.</li>
          </ul></section>

        <section className="card"><h2>What is tested today and what is planned</h2>
          <table><thead><tr><th>Check</th><th>Uses</th><th>What it finds</th><th>Status</th></tr></thead>
            <tbody>{CHECKS.map((r) => <tr key={r[0]}>{r.map((c, i) => <td key={i}>{c}</td>)}</tr>)}</tbody></table></section>

        <section className="card"><h2>Reading the verdict</h2>
          <ul>{VERDICTS.map(([a, b]) => <li key={a}><strong>{a}</strong> - {b}</li>)}</ul>
          <p className="muted">Privacy: with the dependency scan set to Online, package names and versions (not source code) are sent to OSV.dev. Choose Offline or Disabled to avoid that.</p></section>
      </main>
      <Footer />
    </div>
  )
}

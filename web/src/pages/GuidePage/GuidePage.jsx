import { CommandBlock } from '../../components/CommandBlock/CommandBlock'
import { Footer } from '../../components/Footer/Footer'
import { Header } from '../../components/Header/Header'
import './GuidePage.css'

const TRUST = ['Your code is never run', 'Scans work offline', 'Locked-down containers', 'Everything is verified']

const TOC = [
  ['quick-start', 'Quick start'], ['components', 'What gets installed'], ['commands', 'Commands'], ['checks', 'Checks'],
  ['verdicts', 'Verdicts'], ['fix', 'If something is missing'], ['offline', 'Offline'], ['safety', 'How it stays safe'],
]

const STEPS = [
  ['Set up', 'Run saferun init once. It installs only what is missing.', 'saferun init'],
  ['Verify', 'Check that every part is ready and verified.', 'saferun status'],
  ['Scan', 'Scan a folder, or drop a ZIP on the dashboard.', 'saferun scan ./my-project'],
]

const COMPONENTS = [
  { key: 'python', n: 1, title: 'Python sandbox image', does: 'Runs the Python syntax check in a locked-down container.', size: '~190 MB', enables: ['Python syntax'] },
  { key: 'node', n: 2, title: 'Node.js sandbox image', does: 'Runs the JavaScript syntax check in a locked-down container.', size: '~330 MB', enables: ['JavaScript syntax'] },
  { key: 'analyzer', n: 3, title: 'Analyzer image', does: 'Holds Semgrep, its rules and OSV-Scanner. Runs the static code analysis.', size: '~740 MB, built locally', enables: ['Static analysis', 'Dependency scan'] },
  { key: 'osv-db', n: 4, title: 'OSV vulnerability database', does: 'Local vulnerability data, so dependency scans run offline.', size: '~260 MB download', enables: ['Dependency scan'] },
]

const STATES = [
  ['READY', 'ready', 'Installed and verified just now.', 'Nothing to do.'],
  ['MISSING', 'warn', 'Not installed.', 'saferun init --only <name>'],
  ['INVALID', 'fail', 'Present but failed verification (wrong digest, changed lock, damaged data).', 'saferun init --only <name>  (analyzer: add --repair)'],
  ['OUTDATED', 'warn', 'Valid but older than 30 days (OSV data).', 'saferun osv-db update'],
]

const COMMANDS = [
  ['Guided setup: pick components from a menu', 'saferun init', 'Shows what is installed and verified, asks what to install. Press Enter for everything.'],
  ['Everything, no questions (scripts, CI)', 'saferun init --all', 'Add --yes to confirm prompts automatically.'],
  ['Only some components', 'saferun init --only python,node', 'Names: python, node, analyzer, osv-db.'],
  ['Everything except some', 'saferun init --skip osv-db', 'Use this if you do not need dependency scanning.'],
  ['Rebuild a failed analyzer', 'saferun init --only analyzer --repair', 'Replaces the analyzer image and its lock. Only when status says INVALID.'],
  ['Plain output for logs and CI', 'saferun scan ./my-project --color never', 'Colours, icons and the spinner appear only on a terminal; --format json is always plain. NO_COLOR is honoured.'],
  ['See what is installed', 'saferun status', 'Exit code 0 only when everything is ready. Add --format json for scripts.'],
  ['Update the vulnerability data', 'saferun osv-db update', 'The only command that uses the network. Sends nothing about your project.'],
  ['Check the data age and integrity', 'saferun osv-db status', 'Older than 30 days makes the dependency check incomplete.'],
]

const CHECKS = [
  ['Python syntax', 'python'], ['JavaScript syntax', 'node'], ['Static analysis (Semgrep)', 'analyzer'], ['Dependency vulnerabilities', 'analyzer + osv-db'],
]

const VERDICTS = [
  ['pass', '✓', 'PASS', 'Every check ran and found nothing.', 'Looks fine, but it is not a proof of safety.'],
  ['warn', '!', 'WARNING', 'Minor findings, or a check could not run (missing or outdated component).', 'Run saferun status, apply the fix, scan again.'],
  ['fail', '✕', 'FAIL', 'At least one high or critical finding.', 'Do not run the project until it is fixed.'],
]

const FIXES = [
  ['A check says "unavailable", "error" or "incomplete"', 'Run saferun status. It names the component and prints the exact fix, for example saferun init --only osv-db. A scan also prints that fix on stderr.'],
  ['The dashboard shows "Not ready on this machine"', 'The analyzer image is not installed or failed verification. Run saferun init --only analyzer.'],
  ['A component says INVALID', 'Images are repaired by pulling the pinned digest. The analyzer is rebuilt only with --repair, because that replaces the image and its lock. Investigate first if you did not expect it.'],
  ['The dependency scan says incomplete', 'The OSV data is older than 30 days. Run saferun osv-db update. Until then findings are still shown, but the result can never be PASS.'],
  ['Nothing is skipped silently', 'A check whose component is missing is reported, never skipped, and SafeRun never falls back to tools installed on your computer.'],
]

const OFFLINE = [
  'After setup, scans never need the internet: the checks run in containers without network and read the local OSV data.',
  'Without internet, saferun init uses what is already valid, skips downloads it does not need and lists what is missing.',
  'It never reports dependency scanning ready without valid OSV data.',
]
const PRELOAD = [
  ['OSV data', 'On a connected machine: saferun osv-db update --dir DIR. Copy DIR over and set SAFERUN_OSV_DB=DIR (or place it at the default location). Check with saferun osv-db status.'],
  ['Sandbox images', 'docker pull on a connected machine, then docker save / docker load. SafeRun trusts a loaded image only if Docker still reports the pinned digest; otherwise status says INVALID.'],
  ['Analyzer image', 'Cannot be installed without internet yet. Run saferun init --only analyzer once while online.'],
]

const SAFETY = [
  ['Your project is never executed', 'It is copied read-only into a throwaway container: no network, non-root user, no Linux capabilities, memory, CPU and process limits.'],
  ['Images are pinned by digest', 'An image is trusted only if Docker reports the exact pinned digest. A tag that merely exists is not enough.'],
  ['The analyzer is locked', 'Its image ID, tool versions and rules hash are re-checked before every scan. The lock file must be private to your user.'],
  ['Vulnerability data has an integrity record', 'SHA-256, size, advisory count and date are re-checked before every scan. Damaged, tampered or old data cannot produce PASS.'],
  ['The dashboard stays on your machine', 'It accepts connections only from your own computer (loopback) and has no login.'],
]

function jump(id) {
  const el = document.getElementById(id)
  if (!el) return
  const calm = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  if (el.scrollIntoView) el.scrollIntoView({ behavior: calm ? 'auto' : 'smooth', block: 'start' })
}

function Shield() {
  return (
    <svg className="g-shield" viewBox="0 0 48 56" width="48" height="56" role="img" aria-label="Shield with a check mark">
      <path d="M24 3 5 10v15c0 13 8 22 19 28 11-6 19-15 19-28V10L24 3Z" fill="none" stroke="currentColor" strokeWidth="3" strokeLinejoin="round" />
      <path d="m15 27 7 7 12-14" fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function GuidePage() {
  return (
    <div className="shell">
      <Header />
      <main className="guide">
        <section className="g-hero">
          <Shield />
          <div>
            <h1>Set up SafeRun in three steps</h1>
            <p className="g-lead">SafeRun checks code before you run or trust it, without ever running it. Setup installs only what each check needs, and verifies it.</p>
            <ul className="g-chips" aria-label="What SafeRun guarantees">
              {TRUST.map((t) => <li key={t}><span aria-hidden="true">✓</span> {t}</li>)}
            </ul>
          </div>
        </section>

        <nav className="g-toc" aria-label="On this page">
          {TOC.map(([id, label]) => <button key={id} type="button" onClick={() => jump(id)}>{label}</button>)}
        </nav>

        <section id="quick-start" className="card g-section">
          <h2>Quick start</h2>
          <ol className="g-steps">
            {STEPS.map(([title, text, cmd], i) => (
              <li key={title}>
                <span className="g-num" aria-hidden="true">{i + 1}</span>
                <div><h3>{title}</h3><p>{text}</p><CommandBlock command={cmd} /></div>
              </li>
            ))}
          </ol>
          <p className="fine">Needs Linux, Python 3.12+ and a local Docker Engine. To use this dashboard: <code>cd web && npm ci --ignore-scripts && npm run build</code>, then <code>saferun-web</code> and open http://127.0.0.1:8765/.</p>
        </section>

        <section id="components" className="card g-section">
          <h2>What gets installed, and why</h2>
          <div className="g-grid">
            {COMPONENTS.map((c) => (
              <article key={c.key} className="g-comp">
                <header><span className="g-num small" aria-hidden="true">{c.n}</span><code className="g-key">{c.key}</code></header>
                <h3>{c.title}</h3>
                <p>{c.does}</p>
                <p className="fine">{c.size}</p>
                <p className="g-enables">{c.enables.map((e) => <span key={e} className="g-pill">{e}</span>)}</p>
              </article>
            ))}
          </div>
          <h3>What the status of each part means</h3>
          <div className="g-states">
            {STATES.map(([name, tone, meaning, fix]) => (
              <div key={name} className="g-state">
                <span className={`g-badge ${tone}`}>{name}</span>
                <span>{meaning}</span>
                <code>{fix}</code>
              </div>
            ))}
          </div>
        </section>

        <section id="commands" className="card g-section">
          <h2>Commands</h2>
          <ul className="g-cmds">
            {COMMANDS.map(([title, cmd, note]) => (
              <li key={cmd}><h3>{title}</h3><CommandBlock command={cmd} label={title} /><p className="fine">{note}</p></li>
            ))}
          </ul>
        </section>

        <section id="checks" className="card g-section">
          <h2>Which part powers which check</h2>
          <table>
            <thead><tr><th>Check</th><th>Needs</th></tr></thead>
            <tbody>{CHECKS.map(([a, b]) => <tr key={a}><td>{a}</td><td><code>{b}</code></td></tr>)}</tbody>
          </table>
          <p className="fine">Not installed on purpose: Semgrep and OSV-Scanner never run on your computer, only inside the analyzer container. Running your tests and installing dependencies are planned, not available.</p>
        </section>

        <section id="verdicts" className="card g-section">
          <h2>Reading the verdict</h2>
          <div className="g-verdicts">
            {VERDICTS.map(([tone, icon, name, meaning, action]) => (
              <article key={name} className={`g-verdict ${tone}`}>
                <span className="g-vicon" aria-hidden="true">{icon}</span>
                <h3>{name}</h3>
                <p>{meaning}</p>
                <p className="g-action">{action}</p>
              </article>
            ))}
          </div>
        </section>

        <section id="fix" className="card g-section">
          <h2>If something is missing or outdated</h2>
          <div className="g-faq">
            {FIXES.map(([q, a]) => <details key={q}><summary>{q}</summary><p>{a}</p></details>)}
          </div>
        </section>

        <section id="offline" className="card g-section">
          <h2>Working offline</h2>
          <ul className="g-list">{OFFLINE.map((t) => <li key={t}>{t}</li>)}</ul>
          <h3>Preparing a machine without internet</h3>
          <dl className="g-defs">{PRELOAD.map(([a, b]) => <div key={a}><dt>{a}</dt><dd>{b}</dd></div>)}</dl>
        </section>

        <section id="safety" className="card g-section">
          <h2>How SafeRun stays safe</h2>
          <ul className="g-safety">
            {SAFETY.map(([a, b]) => <li key={a}><span className="g-tick" aria-hidden="true">✓</span><div><strong>{a}</strong><p>{b}</p></div></li>)}
          </ul>
          <p className="notice">Honest limits: these checks detect damage and later changes, but a locally recorded hash cannot prove the original download was genuine. PASS means the existing checks found nothing, not that the code is safe. Scans send nothing anywhere and are only as current as your last <code>saferun osv-db update</code>.</p>
        </section>

        <section className="card g-section">
          <h2>What the ZIP needs (dashboard)</h2>
          <ul className="g-list">
            <li>Project files at the top level, or inside one top-level folder.</li>
            <li>Up to 25 MiB compressed, 100 MiB extracted and 5000 files.</li>
            <li>No unsafe entries (path traversal, symlinks); otherwise the whole archive is refused.</li>
            <li>Include requirements.txt or a lockfile so dependencies can be checked.</li>
          </ul>
        </section>
      </main>
      <Footer />
    </div>
  )
}

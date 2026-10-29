import './Header.css'

export function Header() {
  return (
    <header className="topbar">
      <div className="brand"><span className="logo" aria-hidden="true">◆</span> SafeRun <span className="muted">Verification dashboard</span></div>
      <nav className="muted small"><a href="#/">Dashboard</a> · <a href="#/guide">Guide</a> · Local · loopback only · the CLI is the primary interface</nav>
    </header>
  )
}

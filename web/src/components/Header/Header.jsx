import './Header.css'

export function Header() {
  return (
    <header className="topbar">
      <div className="brand"><span className="logo" aria-hidden="true">◆</span> SafeRun <span className="muted">Verification dashboard</span></div>
      <div className="muted small">Local · loopback only · the CLI is the primary interface</div>
    </header>
  )
}

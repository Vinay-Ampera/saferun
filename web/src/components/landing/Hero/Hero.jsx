import { TRUST } from '../../../content/site'
import { FlowDiagram } from '../FlowDiagram/FlowDiagram'
import { TerminalDemo } from '../TerminalDemo/TerminalDemo'
import { GITHUB } from '../../../content/site'
import './Hero.css'

export function Hero() {
  return (
    <section className="hero">
      <div className="wrap hero-grid">
        <div>
          <p className="eyebrow"><span className="dot" /> Pre-run verification for untrusted code</p>
          <h1>Check the code <em>before</em> you run it.</h1>
          <p className="lede">SafeRun inspects AI-generated and downloaded projects inside a locked-down, offline container, and gives you a PASS, WARNING or FAIL verdict, without executing the program you submitted.</p>
          <div className="hero-cta">
            <a className="btn btn-primary" href="#/quick-start">Get Started</a>
            <a className="btn btn-ghost" href={GITHUB} target="_blank" rel="noreferrer noopener">View on GitHub <span aria-hidden="true">↗</span></a>
          </div>
          <ul className="trust">
            {TRUST.map(([t, d]) => <li key={t}><strong>{t}</strong><span>{d}</span></li>)}
          </ul>
        </div>
        <div className="hero-art"><FlowDiagram /><TerminalDemo /></div>
      </div>
    </section>
  )
}

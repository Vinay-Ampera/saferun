import { useEffect, useRef, useState } from 'react'
import './IntroSplash.css'

// In memory only: the intro plays on every fresh page load or refresh, but not when you come back to the website from the guide or dashboard.
let seen = false
export const resetIntroSeen = () => { seen = false }
const FADE_AT = 5200 // ms until the screen starts to dissolve into the hero
const DONE_AT = 6000 // ms until it is removed

// A decorative 6 x 10 grid of "files". The same positions are flagged on the left and judged on the right. No real data.
const COLS = 6
const CELLS = Array.from({ length: 60 }, (_, i) => ({ i, row: Math.floor(i / COLS), kind: i % 11 === 3 ? 'fail' : i % 7 === 2 ? 'warn' : 'ok' }))

/** Plays once per page load, never with reduced motion, and never where matchMedia is missing (tests, old browsers). */
export function shouldPlayIntro() {
  if (typeof window.matchMedia !== 'function' || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return false
  return !seen
}

function Panel({ side, title, status }) {
  return (
    <div className={'sp-panel sp-' + side} aria-hidden="true">
      <div className="sp-head"><span>{title}</span><b>{status}</b></div>
      <div className="sp-grid">{CELLS.map((c) => <i key={c.i} className={`c ${c.kind} row-${c.row}`} />)}</div>
    </div>
  )
}

/** Full-screen opening: the shield draws itself, a submitted project and its verdicts slide in from either side
 *  while a scan beam passes, the tagline appears, then everything dissolves into the hero. */
export function IntroSplash({ onDone }) {
  const [out, setOut] = useState(false)
  const timers = useRef([])
  const finish = () => { timers.current.forEach(clearTimeout); onDone() }

  useEffect(() => {
    seen = true
    const scrollY = window.scrollY
    document.body.classList.add('intro-lock')
    timers.current = [setTimeout(() => setOut(true), FADE_AT), setTimeout(onDone, DONE_AT)]
    return () => { timers.current.forEach(clearTimeout); document.body.classList.remove('intro-lock'); window.scrollTo?.(0, scrollY) }
  }, [onDone])

  return (
    <div className={'splash' + (out ? ' out' : '')} data-testid="intro">
      <div className="splash-glow" />
      <div className="splash-beam" />
      <div className="splash-stage">
        <Panel side="left" title="Submitted project" status="not run" />
        <div className="splash-core">
          <svg className="splash-mark" viewBox="0 0 48 56" width="96" height="112" aria-hidden="true">
            <path className="sm-shield" pathLength="1" d="M24 3 5 10v15c0 13 8 22 19 28 11-6 19-15 19-28V10L24 3Z" />
            <path className="sm-tick" pathLength="1" d="m15 27 7 7 12-14" />
          </svg>
          <p className="splash-word">SafeRun</p>
          <p className="splash-tag"><span>Untrusted code in.</span> <span>Verified report out.</span></p>
        </div>
        <Panel side="right" title="Verified report" status="sample" />
      </div>
      <button type="button" className="splash-skip" onClick={finish}>Skip intro</button>
    </div>
  )
}

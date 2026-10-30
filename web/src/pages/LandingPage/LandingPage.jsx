import { useCallback, useEffect, useState } from 'react'
import { SiteFooter } from '../../components/SiteFooter/SiteFooter'
import { SiteNav } from '../../components/SiteNav/SiteNav'
import { CheckTicker } from '../../components/landing/CheckTicker/CheckTicker'
import { Faq } from '../../components/landing/Faq/Faq'
import { Features } from '../../components/landing/Features/Features'
import { GithubCta } from '../../components/landing/GithubCta/GithubCta'
import { Hero } from '../../components/landing/Hero/Hero'
import { HowItWorks } from '../../components/landing/HowItWorks/HowItWorks'
import { IntroSplash, shouldPlayIntro } from '../../components/landing/IntroSplash/IntroSplash'
import { ProblemSolution } from '../../components/landing/ProblemSolution/ProblemSolution'
import { QuickStart } from '../../components/landing/QuickStart/QuickStart'
import { ReportDemo } from '../../components/landing/ReportDemo/ReportDemo'
import { SecuritySection } from '../../components/landing/SecuritySection/SecuritySection'

export const LANDING_SECTIONS = ['product', 'security', 'how', 'features', 'demo', 'quick-start', 'github', 'faq']

/** The website. `section` (from the hash, e.g. #/security) is scrolled into view; without it the page starts at the top. */
export function LandingPage({ section = '' }) {
  // The opening plays only on a plain visit to the website (not for #/<section> links) and once per session.
  const [intro, setIntro] = useState(() => !section && shouldPlayIntro())
  const endIntro = useCallback(() => setIntro(false), [])
  useEffect(() => {
    const el = section && document.getElementById(section)
    if (el?.scrollIntoView) el.scrollIntoView({ block: 'start' })
    else window.scrollTo?.(0, 0)
  }, [section])
  return (
    <>
    {intro && <IntroSplash onDone={endIntro} />}
    <div className={'shell' + (intro ? ' intro-on' : '')}>
      <SiteNav current={section ? '#/' + section : ''} />
      <main>
        <Hero /><CheckTicker /><ProblemSolution /><HowItWorks /><SecuritySection /><Features /><ReportDemo /><QuickStart /><GithubCta /><Faq />
      </main>
      <SiteFooter />
    </div>
    </>
  )
}

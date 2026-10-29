import { useEffect, useState } from 'react'
import { DashboardPage } from './pages/DashboardPage/DashboardPage'
import { GuidePage } from './pages/GuidePage/GuidePage'

/** Two pages, switched by the URL hash (#/guide); no router needed. */
export function App() {
  const [hash, setHash] = useState(window.location.hash)
  useEffect(() => {
    const on = () => setHash(window.location.hash)
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return hash === '#/guide' ? <GuidePage /> : <DashboardPage />
}

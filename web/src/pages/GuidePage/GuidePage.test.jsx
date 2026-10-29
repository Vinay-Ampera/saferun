// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { GuidePage } from './GuidePage'

afterEach(() => vi.restoreAllMocks())

describe('Guide page', () => {
  it('documents the real setup commands and every component', () => {
    const text = render(<GuidePage />).container.textContent
    for (const c of ['saferun init', 'saferun init --all', '--only', '--skip', '--repair', 'saferun status', 'saferun osv-db update', 'saferun osv-db status']) {
      expect(text).toContain(c)
    }
    for (const k of ['python', 'node', 'analyzer', 'osv-db']) expect(text).toContain(k)
  })

  it('explains offline operation and missing components, and no longer mentions installing host tools or online OSV', () => {
    const text = render(<GuidePage />).container.textContent
    expect(text).toMatch(/Working offline/)
    expect(text).toMatch(/If something is missing or outdated/)
    expect(text).toMatch(/never need the internet/)
    expect(text).not.toMatch(/pip install[^.]*analysis/)
    expect(text).not.toMatch(/Install osv-scanner/)
    expect(text).not.toMatch(/Online, package names/)
  })

  it('shows the three steps, the status meanings and the three verdicts', () => {
    const { container } = render(<GuidePage />)
    expect(container.querySelectorAll('.g-steps > li')).toHaveLength(3)
    for (const s of ['READY', 'MISSING', 'INVALID', 'OUTDATED']) expect(container.querySelector('.g-states').textContent).toContain(s)
    expect([...container.querySelectorAll('.g-verdict h3')].map((n) => n.textContent)).toEqual(['PASS', 'WARNING', 'FAIL'])
    expect(container.querySelectorAll('.g-comp')).toHaveLength(4)
  })

  it('states the honest limits next to the safety claims', () => {
    const { container } = render(<GuidePage />)
    const safety = container.querySelector('#safety').textContent
    expect(safety).toMatch(/cannot prove the original download was genuine/)
    expect(safety).toMatch(/not that the code is safe/)
  })

  it('copy buttons put only the command (no prompt) on the clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue()
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    render(<GuidePage />)
    fireEvent.click(screen.getAllByRole('button', { name: 'Copy command: saferun status' })[0])
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('saferun status'))
    expect(await screen.findAllByText('Copied')).not.toHaveLength(0)
  })

  it('a failing clipboard degrades to a hint instead of an error', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: vi.fn().mockRejectedValue(new Error('denied')) }, configurable: true })
    render(<GuidePage />)
    fireEvent.click(screen.getAllByRole('button', { name: /Copy command: saferun init$/ })[0])
    expect(await screen.findAllByText('Press Ctrl+C')).not.toHaveLength(0)
  })

  it('the table of contents scrolls to real sections without changing the hash route', () => {
    const scroll = vi.fn()
    window.HTMLElement.prototype.scrollIntoView = scroll
    const before = window.location.hash
    const { container } = render(<GuidePage />)
    const ids = ['quick-start', 'components', 'commands', 'checks', 'verdicts', 'fix', 'offline', 'safety']
    const buttons = [...container.querySelectorAll('.g-toc button')]
    expect(buttons).toHaveLength(ids.length)
    for (const id of ids) expect(container.querySelector('#' + id)).not.toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Commands' }))
    expect(scroll).toHaveBeenCalledTimes(1)
    expect(window.location.hash).toBe(before)
  })

  it('uses no inline styles or scripts (the dashboard CSP forbids them)', () => {
    const { container } = render(<GuidePage />)
    expect(container.querySelectorAll('[style]')).toHaveLength(0)
    expect(container.querySelectorAll('script')).toHaveLength(0)
  })
})

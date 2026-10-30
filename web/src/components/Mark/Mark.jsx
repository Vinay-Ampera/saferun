/** The SafeRun logo mark: a shield with a check. Decorative; the brand name always sits next to it. */
export function Mark({ size = 26, className = '' }) {
  return (
    <svg className={'mark ' + className} viewBox="0 0 48 56" width={size} height={size * 56 / 48} aria-hidden="true">
      <path d="M24 3 5 10v15c0 13 8 22 19 28 11-6 19-15 19-28V10L24 3Z" fill="none" stroke="currentColor" strokeWidth="3.5" strokeLinejoin="round" />
      <path d="m15 27 7 7 12-14" fill="none" stroke="currentColor" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

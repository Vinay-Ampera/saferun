import { useRef, useState } from 'react'
import './UploadPanel.css'

const OSV_TEXT = {
  online: { label: 'Online', note: 'Package names and versions found in lockfiles / requirements.txt are sent to OSV.dev (api.osv.dev) by the machine running SafeRun. No source code is sent.' },
  offline: { label: 'Offline', note: 'Nothing is sent to OSV.dev. Requires locally cached OSV databases; without them the dependency check reports an error and the verdict is at best WARNING.' },
  disabled: { label: 'Disabled', note: 'The dependency check is skipped and nothing is sent. A skipped check means the verdict is at best WARNING.' },
}

/** @param {{busy: boolean, health: import('../../types').Health|null, osv: import('../../types').OsvMode, onOsv: (m: string) => void, onFile: (f: File) => void}} props */
export function UploadPanel({ busy, health, osv, onOsv, onFile }) {
  const input = useRef(null)
  const [drag, setDrag] = useState(false)
  const lim = health?.limits
  const pick = (f) => { if (f) onFile(f) }
  return (
    <section className="card" aria-label="New scan">
      <h2>New scan</h2>
      <div
        className={`drop${drag ? ' drag' : ''}${busy ? ' disabled' : ''}`}
        onDragOver={(e) => { e.preventDefault(); if (!busy) setDrag(true) }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); if (!busy) pick(e.dataTransfer.files[0]) }}
      >
        <p><strong>Drop a project ZIP here</strong></p>
        <p className="muted small">or</p>
        <button className="primary" disabled={busy} onClick={() => input.current?.click()}>Choose ZIP file…</button>
        <input ref={input} type="file" accept=".zip,application/zip" hidden data-testid="file-input"
               onChange={(e) => { pick(e.target.files?.[0]); e.target.value = '' }} />
        {lim && <p className="muted small">Up to {lim.max_archive_mib} MiB compressed · {lim.max_uncompressed_mib} MiB extracted · {lim.max_entries} files</p>}
      </div>
      <fieldset disabled={busy}>
        <legend>Dependency scan (OSV)</legend>
        {Object.keys(OSV_TEXT).map((m) => (
          <label key={m} className="radio"><input type="radio" name="osv" value={m} checked={osv === m} onChange={() => onOsv(m)} /> {OSV_TEXT[m].label}</label>
        ))}
        <p className="notice" data-testid="osv-note" role="note">{OSV_TEXT[osv].note}</p>
      </fieldset>
      <p className="fine">The archive is checked and never executed on this machine. Archives with unsafe members are refused entirely.</p>
      {health && (!health.docker_cli || !health.semgrep || !health.osv_scanner) && (
        <p className="notice warn" role="status">
          Not found on this machine: {[!health.docker_cli && 'docker', !health.semgrep && 'semgrep', !health.osv_scanner && 'osv-scanner'].filter(Boolean).join(', ')}.
          The matching checks will be reported as unavailable and the verdict will be at best WARNING.
        </p>
      )}
    </section>
  )
}

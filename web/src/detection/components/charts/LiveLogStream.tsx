import { useEffect, useMemo, useRef, useState } from 'react'
import type { Finding } from '../../api/contracts'

type LogRow = {
  time: string
  level: 'error' | 'warn' | 'info' | 'debug'
  source: string
  message: string
}

function levelForSeverity(severity: string): LogRow['level'] {
  if (severity === 'critical' || severity === 'high') return 'error'
  if (severity === 'medium') return 'warn'
  if (severity === 'low') return 'info'
  return 'debug'
}

function toRow(f: Finding, at?: Date): LogRow {
  const when = at ?? new Date(f.last_seen)
  return {
    time: Number.isNaN(when.getTime())
      ? '—'
      : when.toISOString().slice(11, 19),
    level: levelForSeverity(f.severity),
    source: f.model,
    message: f.title,
  }
}

/** Auto-scrolling log panel fed from findings; streams new rows periodically. */
export function LiveLogStream({ findings }: { findings: Finding[] }) {
  const initial = useMemo(
    () =>
      [...findings]
        .sort((a, b) => a.last_seen.localeCompare(b.last_seen))
        .slice(-14)
        .map((f) => toRow(f)),
    [findings],
  )
  const [rows, setRows] = useState<LogRow[]>(initial)
  const containerRef = useRef<HTMLDivElement>(null)
  const cursor = useRef(0)

  useEffect(() => {
    setRows(initial)
  }, [initial])

  useEffect(() => {
    if (findings.length === 0) return
    const id = setInterval(() => {
      const f = findings[cursor.current % findings.length]!
      cursor.current += 1
      setRows((prev) => [...prev.slice(-40), toRow(f, new Date())])
    }, 3500)
    return () => clearInterval(id)
  }, [findings])

  useEffect(() => {
    const el = containerRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [rows])

  if (rows.length === 0) {
    return <div className="empty">No log activity in the current window.</div>
  }

  return (
    <div className="log-stream" ref={containerRef} role="log" aria-label="Live finding stream">
      {rows.map((row, i) => (
        <div className="log-row" key={i}>
          <span className="log-time">{row.time}</span>
          <span className={`log-level ${row.level}`}>{row.level.toUpperCase()}</span>
          <span className="log-source">[{row.source}]</span>
          <span className="log-message">{row.message}</span>
        </div>
      ))}
    </div>
  )
}

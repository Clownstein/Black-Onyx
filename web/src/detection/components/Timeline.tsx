import type { TimelineEntry } from '../api/contracts'
import { formatTime } from '../utils/format'

type Props = {
  entries: TimelineEntry[]
}

function timelineSummary(entry: TimelineEntry): string {
  if (entry.summary?.trim()) return entry.summary.trim()
  const detail = entry.detail ?? {}
  if (typeof detail.summary === 'string' && detail.summary.trim()) {
    return detail.summary.trim()
  }
  if (typeof detail.note === 'string' && detail.note.trim()) {
    return detail.note.trim()
  }
  if (typeof detail.title === 'string' && detail.title.trim()) {
    return detail.title.trim()
  }
  if (typeof detail.disposition === 'string') {
    return `Disposition set to ${detail.disposition}`
  }
  if (typeof detail.assigned_to === 'string') {
    return `Assigned to ${detail.assigned_to}`
  }
  if (typeof detail.kind === 'string' && typeof detail.model === 'string') {
    return `${detail.kind} evidence from ${detail.model}`
  }
  return entry.event_type.replace(/_/g, ' ')
}

export function Timeline({ entries }: Props) {
  if (entries.length === 0) {
    return <div className="empty">No timeline events yet.</div>
  }

  return (
    <ul className="timeline">
      {entries.map((entry) => (
        <li key={entry.entry_id} className="timeline-item">
          <div className="timeline-time">{formatTime(entry.created_at)}</div>
          <div className="timeline-body">
            <strong>{entry.event_type}</strong>
            <div className="muted">
              {entry.actor ? `${entry.actor} · ` : ''}
              {timelineSummary(entry)}
            </div>
          </div>
        </li>
      ))}
    </ul>
  )
}

import type { TimelineEntry } from '../api/contracts'
import { formatTime } from '../utils/format'

type Props = {
  entries: TimelineEntry[]
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
              {JSON.stringify(entry.detail)}
            </div>
          </div>
        </li>
      ))}
    </ul>
  )
}

import { useMemo, useState } from 'react'
import type { EvidenceItem, EvidenceKind } from '../api/contracts'
import { CodeEvidence } from './CodeEvidence'
import { LogEvidence } from './LogEvidence'
import { MetricsEvidence } from './MetricsEvidence'
import { NetworkEvidence } from './NetworkEvidence'
import { formatTime } from '../utils/format'

const TABS: { id: EvidenceKind; label: string }[] = [
  { id: 'logs', label: 'Logs' },
  { id: 'code', label: 'Code' },
  { id: 'network', label: 'Network' },
  { id: 'metrics', label: 'Metrics' },
  { id: 'correlation', label: 'Correlation' },
]

type Props = {
  evidence: EvidenceItem[]
}

function ModalityBody({ item }: { item: EvidenceItem }) {
  switch (item.kind) {
    case 'logs':
      return <LogEvidence item={item} />
    case 'code':
      return <CodeEvidence item={item} />
    case 'network':
      return <NetworkEvidence item={item} />
    case 'metrics':
      return <MetricsEvidence item={item} />
    default:
      return null
  }
}

export function EvidenceTabs({ evidence }: Props) {
  const counts = useMemo(() => {
    const map = new Map<EvidenceKind, number>()
    for (const item of evidence) {
      map.set(item.kind, (map.get(item.kind) ?? 0) + 1)
    }
    return map
  }, [evidence])

  const [active, setActive] = useState<EvidenceKind>(
    () => TABS.find((t) => (counts.get(t.id) ?? 0) > 0)?.id ?? 'logs',
  )

  const items = evidence.filter((e) => e.kind === active)

  return (
    <div>
      <div className="tabs" role="tablist">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={active === tab.id}
            className={`tab${active === tab.id ? ' active' : ''}`}
            onClick={() => setActive(tab.id)}
          >
            {tab.label} ({counts.get(tab.id) ?? 0})
          </button>
        ))}
      </div>
      <div className="evidence-list" role="tabpanel">
        {items.length === 0 ? (
          <div className="empty">No {active} evidence for this incident.</div>
        ) : (
          items.map((item, idx) => (
            <article key={`${item.kind}-${idx}-${item.title}`} className="evidence-card">
              <div className="evidence-meta">
                <span className="mono">{item.model}</span>
                <span>{formatTime(item.timestamp)}</span>
                {item.score != null ? <span>score {item.score.toFixed(2)}</span> : null}
              </div>
              <h4>{item.title}</h4>
              <p className="muted" style={{ margin: 0 }}>
                {item.detail}
              </p>
              <ModalityBody item={item} />
              {item.raw && item.kind === 'correlation' ? (
                <pre className="mono muted" style={{ marginTop: '0.65rem', overflow: 'auto' }}>
                  {JSON.stringify(item.raw, null, 2)}
                </pre>
              ) : null}
            </article>
          ))
        )}
      </div>
    </div>
  )
}

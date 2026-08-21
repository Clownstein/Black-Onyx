import type { ReactNode } from 'react'
import type { EvidenceItem } from '../api/contracts'

/** Shared skeleton for the per-modality evidence panels. */

export function extractRawContext(item: EvidenceItem): {
  raw: Record<string, unknown>
  context: Record<string, unknown>
} {
  const raw = item.raw ?? {}
  const context =
    raw.context && typeof raw.context === 'object' ? (raw.context as Record<string, unknown>) : {}
  return { raw, context }
}

export function EvidenceSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h5>{title}</h5>
      {children}
    </section>
  )
}

export function ContributorList({
  items,
}: {
  items: Array<{ key: string; label: ReactNode; value: ReactNode }>
}) {
  return (
    <ul className="contributor-list">
      {items.map((row) => (
        <li key={row.key}>
          <span>{row.label}</span>
          <span className="mono">{row.value}</span>
        </li>
      ))}
    </ul>
  )
}

export function EvidenceEmpty({ item, message }: { item: EvidenceItem; message: string }) {
  return (
    <p className="muted" style={{ margin: 0 }}>
      {item.detail || message}
    </p>
  )
}

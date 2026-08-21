import type { EvidenceItem } from '../api/contracts'
import { ContributorList, EvidenceEmpty, EvidenceSection, extractRawContext } from './EvidencePanel'

type SequenceStep = {
  template_id?: string
  text?: string
  anomalous?: boolean
}

type Contributor = {
  name?: string
  type?: string
  template_id?: string
  summary?: string
  contribution?: number
}

type Props = {
  item: EvidenceItem
}

function asArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : []
}

export function LogEvidence({ item }: Props) {
  const { raw, context } = extractRawContext(item)
  const sequence = asArray<SequenceStep>(raw.sequence)
  const contributors = asArray<Contributor>(raw.contributors)
  const templates = asArray<string>(raw.expected_templates ?? context.expected_templates)
  const events = asArray<string>(raw.raw_events ?? context.raw_events)
  const traceId =
    typeof raw.trace_id === 'string'
      ? raw.trace_id
      : typeof context.trace_id === 'string'
        ? String(context.trace_id)
        : null

  return (
    <div className="modality-panel">
      {traceId ? (
        <p className="muted" style={{ marginTop: 0 }}>
          Trace: <span className="mono">{traceId}</span>
        </p>
      ) : null}

      {templates.length > 0 ? (
        <section>
          <h5>Expected templates</h5>
          <ul className="contributor-list">
            {templates.map((t, idx) => (
              <li key={`${t}-${idx}`}>
                <span className="mono">{t}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {events.length > 0 ? (
        <section>
          <h5>Raw events</h5>
          <ol className="sequence-list">
            {events.map((ev, idx) => (
              <li key={`ev-${idx}`}>
                <span className="mono">evt-{idx + 1}</span>
                <span>{ev}</span>
              </li>
            ))}
          </ol>
        </section>
      ) : null}

      {sequence.length > 0 ? (
        <section>
          <h5>Event sequence</h5>
          <ol className="sequence-list">
            {sequence.map((step, idx) => (
              <li
                key={`${step.template_id ?? 'step'}-${idx}`}
                className={step.anomalous ? 'sequence-anomalous' : undefined}
              >
                <span className="mono">{step.template_id ?? `step-${idx + 1}`}</span>
                <span>{step.text ?? '—'}</span>
              </li>
            ))}
          </ol>
        </section>
      ) : null}

      {contributors.length > 0 ? (
        <EvidenceSection title="Top contributors">
          <ContributorList
            items={contributors.map((c, idx) => ({
              key: `${c.template_id ?? c.name ?? 'contrib'}-${idx}`,
              label: c.template_id ?? c.name ?? c.summary ?? c.type ?? `contributor-${idx + 1}`,
              value: typeof c.contribution === 'number' ? c.contribution.toFixed(2) : '—',
            }))}
          />
        </EvidenceSection>
      ) : null}

      {sequence.length === 0 &&
      contributors.length === 0 &&
      templates.length === 0 &&
      events.length === 0 ? (
        <EvidenceEmpty item={item} message="No sequence or contributor details in evidence payload." />
      ) : null}
    </div>
  )
}

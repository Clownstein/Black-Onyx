import type { EvidenceItem } from '../api/contracts'
import { ContributorList, EvidenceEmpty, EvidenceSection, extractRawContext } from './EvidencePanel'

type SeriesPoint = {
  t?: string
  observed?: number
  expected?: number
  score?: number
}

type Props = {
  item: EvidenceItem
}

function num(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

export function MetricsEvidence({ item }: Props) {
  const { raw, context } = extractRawContext(item)
  const contributors = Array.isArray(raw.contributors)
    ? (raw.contributors as Array<Record<string, unknown>>)
    : []
  const metricFromContrib =
    contributors.find((c) => typeof c.metric === 'string')?.metric ??
    contributors.find((c) => typeof c.summary === 'string')?.summary
  const metric =
    typeof raw.metric === 'string'
      ? raw.metric
      : typeof metricFromContrib === 'string'
        ? metricFromContrib
        : item.title
  const unit = typeof raw.unit === 'string' ? raw.unit : ''
  const observed = num(raw.observed) ?? num(raw.value) ?? num(context.observed)
  const expected = num(raw.expected) ?? num(context.expected)
  const band =
    (raw.expected_band && typeof raw.expected_band === 'object'
      ? (raw.expected_band as { low?: number; high?: number })
      : null) ??
    (context.expected_band && typeof context.expected_band === 'object'
      ? (context.expected_band as { low?: number; high?: number })
      : null)
  const series = Array.isArray(raw.series)
    ? (raw.series as SeriesPoint[])
    : Array.isArray(context.series)
      ? (context.series as SeriesPoint[])
      : []
  const deployMarker =
    typeof raw.deployment_id === 'string'
      ? raw.deployment_id
      : typeof context.deployment_id === 'string'
        ? String(context.deployment_id)
        : null

  return (
    <div className="modality-panel">
      <section>
        <h5>Observed vs expected</h5>
        <dl className="kv compact-kv">
          <dt>Metric</dt>
          <dd className="mono">{metric}</dd>
          <dt>Observed</dt>
          <dd className="mono">
            {observed != null ? `${observed}${unit ? ` ${unit}` : ''}` : '—'}
          </dd>
          <dt>Expected</dt>
          <dd className="mono">
            {expected != null ? `${expected}${unit ? ` ${unit}` : ''}` : '—'}
          </dd>
          {band && (band.low != null || band.high != null) ? (
            <>
              <dt>Expected band</dt>
              <dd className="mono">
                {band.low ?? '—'} – {band.high ?? '—'}
                {unit ? ` ${unit}` : ''}
              </dd>
            </>
          ) : null}
          {deployMarker ? (
            <>
              <dt>Deployment</dt>
              <dd className="mono">{deployMarker}</dd>
            </>
          ) : null}
          <dt>Score</dt>
          <dd className="mono">
            {typeof item.score === 'number' ? item.score.toFixed(3) : '—'}
          </dd>
        </dl>
      </section>

      {series.length > 0 ? (
        <section>
          <h5>Score / series window</h5>
          <ul className="contributor-list">
            {series.map((pt, idx) => (
              <li key={`${pt.t ?? idx}`}>
                <span className="mono">{pt.t ?? `t-${idx}`}</span>
                <span className="mono">
                  obs {pt.observed ?? '—'} / exp {pt.expected ?? '—'}
                  {typeof pt.score === 'number' ? ` / score ${pt.score.toFixed(2)}` : ''}
                </span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {contributors.length > 0 ? (
        <EvidenceSection title="Contributors">
          <ContributorList
            items={contributors.map((c, idx) => ({
              key: `${String(c.metric ?? c.summary ?? idx)}`,
              label: String(c.metric ?? c.summary ?? c.type ?? `metric-${idx + 1}`),
              value:
                typeof c.contribution === 'number' ? Number(c.contribution).toFixed(2) : '—',
            }))}
          />
        </EvidenceSection>
      ) : null}

      {series.length === 0 && observed == null && contributors.length === 0 ? (
        <EvidenceEmpty item={item} message="No metrics evidence details in payload." />
      ) : null}
    </div>
  )
}

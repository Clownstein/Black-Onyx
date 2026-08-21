import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { EvidenceItem, Finding, Incident } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'
import { StackedBar } from '../../components/charts'

type MetricsRow = {
  id: string
  title: string
  service: string
  severity: string
  risk_score: number
  incident_id: string | null
  summary: string
  observed: number | null
  expected: number | null
  metric: string | null
}

function metricFields(ev: EvidenceItem | undefined): {
  observed: number | null
  expected: number | null
  metric: string | null
} {
  const raw = ev?.raw
  if (!raw) return { observed: null, expected: null, metric: null }
  const observed =
    typeof raw.observed === 'number'
      ? raw.observed
      : typeof raw.value === 'number'
        ? raw.value
        : null
  const expected = typeof raw.expected === 'number' ? raw.expected : null
  const metric = typeof raw.metric === 'string' ? raw.metric : null
  return { observed, expected, metric }
}

export function Metrics() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [incs, finds] = await Promise.all([api.listIncidents(), api.listFindings()])
        if (!cancelled) {
          setIncidents(incs)
          setFindings(finds)
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e))
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  const rows = useMemo(() => {
    const fromFindings: MetricsRow[] = findings
      .filter((f) => f.kind === 'metrics')
      .map((f) => {
        const inc = incidents.find((i) => i.incident_id === f.incident_id)
        // Match evidence to this specific finding; a lone item is unambiguous,
        // but never borrow another finding's evidence when several exist.
        const kindEvidence = inc?.evidence.filter((e) => e.kind === 'metrics') ?? []
        const ev =
          kindEvidence.find((e) => e.raw?.finding_id === f.finding_id) ??
          kindEvidence.find((e) => e.title === f.title) ??
          (kindEvidence.length === 1 ? kindEvidence[0] : undefined)
        const fields = metricFields(ev)
        return {
          id: f.finding_id,
          title: f.title,
          service: f.service,
          severity: f.severity,
          risk_score: f.risk_score,
          incident_id: f.incident_id,
          summary: f.summary,
          ...fields,
        }
      })
    if (fromFindings.length > 0) return fromFindings
    return incidents.flatMap((inc) =>
      inc.evidence
        .filter((e) => e.kind === 'metrics')
        .map((e, idx) => ({
          id: `${inc.incident_id}-met-${idx}`,
          title: e.title,
          service: inc.services[0] ?? 'unknown',
          severity: inc.severity,
          risk_score: e.score ?? inc.risk_score,
          incident_id: inc.incident_id,
          summary: e.detail,
          ...metricFields(e),
        })),
    )
  }, [findings, incidents])

  const active = rows.find((r) => r.id === selected) ?? rows[0] ?? null

  if (loading) return <div className="loading">Loading metrics findings…</div>
  if (error) return <div className="error">{error}</div>

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>Metrics</h1>
          <p>Observed versus expected metric divergences.</p>
        </div>
      </header>

      <div className="list-detail">
        <div className="panel" style={{ padding: 0 }}>
          {rows.map((row) => (
            <button
              key={row.id}
              type="button"
              className={`list-item${active?.id === row.id ? ' active' : ''}`}
              onClick={() => setSelected(row.id)}
            >
              <strong>{row.title}</strong>
              <div className="muted">
                <StatusBadge value={row.severity} kind="severity" /> {row.service}
                {row.observed != null ? ` · obs ${row.observed}` : ''}
              </div>
            </button>
          ))}
          {rows.length === 0 ? <div className="empty">No metrics findings.</div> : null}
        </div>

        <div className="panel">
          {active ? (
            <>
              <h2>{active.title}</h2>
              <dl className="kv">
                <dt>Metric</dt>
                <dd className="mono">{active.metric ?? '—'}</dd>
                <dt>Observed</dt>
                <dd className="mono">{active.observed ?? '—'}</dd>
                <dt>Expected</dt>
                <dd className="mono">{active.expected ?? '—'}</dd>
                <dt>Service</dt>
                <dd>
                  <Link to="/detection-services">{active.service}</Link>
                </dd>
                <dt>Risk</dt>
                <dd className="mono">{active.risk_score.toFixed(2)}</dd>
                <dt>Incident</dt>
                <dd>
                  {active.incident_id ? (
                    <Link to={`/incidents/${active.incident_id}`}>{active.incident_id}</Link>
                  ) : (
                    '—'
                  )}
                </dd>
              </dl>
              {active.observed != null && active.expected != null ? (
                <StackedBar
                  data={[
                    { label: 'observed', value: active.observed },
                    { label: 'expected', value: active.expected },
                  ]}
                  keys={['value']}
                  height={150}
                />
              ) : null}
              <p>{active.summary}</p>
            </>
          ) : (
            <div className="empty">Select a metrics finding.</div>
          )}
        </div>
      </div>
    </div>
  )
}

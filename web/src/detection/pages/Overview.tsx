import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { DataHealthSource, Finding, Incident, IncidentSeverity } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'
import { AttackMap } from '../components/charts/AttackMap'
import { LiveLogStream } from '../components/charts/LiveLogStream'
import { Donut, Sparkline, StackedBar, TimeSeriesArea } from '../../components/charts'

const SEVERITIES: IncidentSeverity[] = ['critical', 'high', 'medium', 'low']

const SEVERITY_COLOR: Record<IncidentSeverity, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
}

/** Bucket ISO timestamps into hourly counts over the trailing 24h. */
function hourlyBuckets(times: string[]): { label: string; value: number }[] {
  const now = Date.now()
  const buckets = Array.from({ length: 24 }, (_, i) => {
    const start = now - (23 - i) * 3_600_000
    return { label: `${new Date(start).getHours().toString().padStart(2, '0')}:00`, value: 0, start }
  })
  for (const iso of times) {
    const t = new Date(iso).getTime()
    if (Number.isNaN(t)) continue
    const age = now - t
    if (age < 0 || age >= 24 * 3_600_000) continue
    const idx = 23 - Math.floor(age / 3_600_000)
    buckets[idx]!.value += 1
  }
  return buckets.map(({ label, value }) => ({ label, value }))
}

export function Overview() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [health, setHealth] = useState<DataHealthSource[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [incs, finds, dh] = await Promise.all([
          api.listIncidents(),
          api.listFindings(),
          api.listDataHealth(),
        ])
        if (!cancelled) {
          setIncidents(incs)
          setFindings(finds)
          setHealth(dh)
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

  const openIncidents = useMemo(
    () => incidents.filter((i) => ['open', 'acknowledged', 'investigating'].includes(i.status)),
    [incidents],
  )

  const openBySeverity = useMemo(
    () =>
      Object.fromEntries(
        SEVERITIES.map((s) => [s, openIncidents.filter((i) => i.severity === s).length]),
      ) as Record<IncidentSeverity, number>,
    [openIncidents],
  )

  const activity = useMemo(() => hourlyBuckets(findings.map((f) => f.last_seen)), [findings])

  const severitySparks = useMemo(() => {
    const bySev = new Map<IncidentSeverity, string[]>()
    for (const f of findings) {
      const sev = f.severity as IncidentSeverity
      bySev.set(sev, [...(bySev.get(sev) ?? []), f.last_seen])
    }
    return Object.fromEntries(
      SEVERITIES.map((s) => [
        s,
        hourlyBuckets(bySev.get(s) ?? [])
          .map((b) => b.value)
          // Sparkline wants a modest number of points.
          .filter((_, i) => i % 2 === 0),
      ]),
    ) as Record<IncidentSeverity, number[]>
  }, [findings])

  const severitySlices = useMemo(
    () =>
      SEVERITIES.map((s) => ({
        label: s,
        value: findings.filter((f) => f.severity === s).length,
        color: SEVERITY_COLOR[s],
      })),
    [findings],
  )

  const findingsByModel = useMemo(() => {
    const map = new Map<string, number>()
    for (const f of findings) {
      map.set(f.model, (map.get(f.model) ?? 0) + 1)
    }
    return [...map.entries()].sort((a, b) => b[1] - a[1])
  }, [findings])

  const topThreats = useMemo(
    () =>
      [...openIncidents]
        .sort((a, b) => b.risk_score - a.risk_score)
        .slice(0, 6),
    [openIncidents],
  )

  if (loading) return <div className="loading">Loading overview…</div>
  if (error) return <div className="error">{error}</div>

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>SOC Overview</h1>
          <p>Open incident load, live attack telemetry, model findings, and ingestion lag.</p>
        </div>
        <Link className="btn btn-primary" to="/incidents">
          View incidents
        </Link>
      </header>

      <section className="grid grid-4" aria-label="Open incidents by severity">
        {SEVERITIES.map((sev) => (
          <div key={sev} className="panel stat-card">
            <StatusBadge value={sev} kind="severity" />
            <div className="stat-value" style={{ marginTop: '0.35rem' }}>
              {openBySeverity[sev]}
            </div>
            <div className="stat-label">open / active</div>
            <Sparkline
              data={severitySparks[sev]}
              color={SEVERITY_COLOR[sev]}
              label={`${sev} findings trend`}
            />
          </div>
        ))}
      </section>

      <section className="grid" style={{ marginTop: '1rem', gridTemplateColumns: 'minmax(0, 1.7fr) minmax(0, 1fr)' }}>
        <div className="panel">
          <h2>Live attack map</h2>
          <p className="muted" style={{ marginTop: '-0.4rem' }}>
            Active incidents and command paths converging on the highest-risk incident.
          </p>
          <AttackMap incidents={incidents} />
        </div>
        <div className="panel">
          <h2>Active threats</h2>
          {topThreats.length === 0 ? (
            <div className="empty">No active incidents.</div>
          ) : (
            <div>
              {topThreats.map((i) => (
                <Link key={i.incident_id} to={`/incidents/${i.incident_id}`} className="list-item">
                  <strong>{i.title}</strong>
                  <div className="muted">
                    <StatusBadge value={i.severity} kind="severity" /> risk{' '}
                    <span className="mono">{i.risk_score.toFixed(2)}</span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </section>

      <section className="grid grid-2" style={{ marginTop: '1rem' }}>
        <div className="panel">
          <h2>Finding activity (24h)</h2>
          <TimeSeriesArea data={activity} />
        </div>
        <div className="panel">
          <h2>Severity distribution</h2>
          <Donut
            data={severitySlices.map(({ label, value }) => ({ label, value }))}
            colors={severitySlices.map((s) => s.color)}
            showLegend
            showTotal
          />
        </div>
      </section>

      <section className="grid grid-2" style={{ marginTop: '1rem' }}>
        <div className="panel">
          <h2>Findings by model</h2>
          <StackedBar
            data={findingsByModel.map(([model, count]) => ({ label: model, value: count }))}
            keys={['value']}
          />
          {findingsByModel.length > 0 ? (
            <div className="chart-legend">
              {findingsByModel.map(([model]) => (
                <Link key={model} to={`/models/${model}`}>
                  {model}
                </Link>
              ))}
            </div>
          ) : null}
        </div>
        <div className="panel">
          <h2>Live log stream</h2>
          <LiveLogStream findings={findings} />
        </div>
      </section>

      <section className="panel" style={{ marginTop: '1rem' }}>
        <h2>Ingestion lag</h2>
        <table className="data">
          <thead>
            <tr>
              <th>Source</th>
              <th>Lag</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {health.map((row) => (
              <tr key={row.source_id}>
                <td className="mono">{row.name}</td>
                <td>
                  {row.lag_records == null
                    ? 'unavailable'
                    : `${row.lag_records.toLocaleString()} records`}
                </td>
                <td>
                  <StatusBadge value={row.status} kind="health" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {health.some((row) => row.lag_records == null) ? (
          <p className="muted" style={{ marginBottom: 0, marginTop: '0.75rem', fontSize: '0.82rem' }}>
            Broker lag is unavailable for sources without exported consumer-lag telemetry.
          </p>
        ) : null}
      </section>
    </div>
  )
}

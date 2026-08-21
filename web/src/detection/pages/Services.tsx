import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { DataHealthSource, Finding, Incident, ModelInfo } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'

type ServiceRow = {
  service: string
  open_incidents: number
  findings: number
  max_severity: string
  assets: string[]
}

function severityRank(s: string): number {
  const order = ['critical', 'high', 'medium', 'low']
  const idx = order.indexOf(s)
  return idx === -1 ? 99 : idx
}

function buildRows(incidents: Incident[], findings: Finding[]): ServiceRow[] {
  const map = new Map<string, ServiceRow>()
  for (const inc of incidents) {
    for (const service of inc.services ?? []) {
      const row = map.get(service) ?? {
        service,
        open_incidents: 0,
        findings: 0,
        max_severity: 'low',
        assets: [],
      }
      if (['open', 'acknowledged', 'investigating'].includes(inc.status)) {
        row.open_incidents += 1
      }
      if (severityRank(inc.severity) < severityRank(row.max_severity)) {
        row.max_severity = inc.severity
      }
      for (const asset of inc.assets ?? []) {
        if (!row.assets.includes(asset)) row.assets.push(asset)
      }
      map.set(service, row)
    }
  }
  for (const f of findings) {
    const row = map.get(f.service) ?? {
      service: f.service,
      open_incidents: 0,
      findings: 0,
      max_severity: f.severity,
      assets: f.asset_id ? [f.asset_id] : [],
    }
    row.findings += 1
    if (severityRank(f.severity) < severityRank(row.max_severity)) {
      row.max_severity = f.severity
    }
    map.set(f.service, row)
  }
  return [...map.values()].sort(
    (a, b) => b.open_incidents - a.open_incidents || a.service.localeCompare(b.service),
  )
}

export function Services() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [health, setHealth] = useState<DataHealthSource[]>([])
  const [models, setModels] = useState<ModelInfo[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [incs, finds, dh, mods] = await Promise.all([
          api.listIncidents(),
          api.listFindings(),
          api.listDataHealth().catch(() => [] as DataHealthSource[]),
          api.listModels().catch(() => [] as ModelInfo[]),
        ])
        if (!cancelled) {
          setIncidents(incs)
          setFindings(finds)
          setHealth(dh)
          setModels(mods)
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

  const rows = useMemo(() => buildRows(incidents, findings), [incidents, findings])
  const active = rows.find((r) => r.service === selected) ?? rows[0] ?? null
  const relatedIncidents = active
    ? incidents.filter((i) => (i.services ?? []).includes(active.service))
    : []

  if (loading) return <div className="loading">Loading services…</div>
  if (error) return <div className="error">{error}</div>

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>Services</h1>
          <p>Live platform health and services referenced by incidents.</p>
        </div>
      </header>

      <section className="panel" style={{ marginBottom: '1rem' }}>
        <h2>Platform health</h2>
        <p className="muted">
          Status from ops probes (container start/stop is managed outside the console).
        </p>
        <table className="table data">
          <thead>
            <tr>
              <th>Component</th>
              <th>Modality</th>
              <th>Status</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {health.map((row) => (
              <tr key={row.source_id}>
                <td className="mono">{row.name}</td>
                <td>{row.modality}</td>
                <td>
                  <StatusBadge value={row.status} kind="health" />
                </td>
                <td className="muted">{row.reason ?? '—'}</td>
              </tr>
            ))}
            {models.map((m) => (
              <tr key={`model-${m.model_id}`}>
                <td className="mono">{m.model_id}</td>
                <td>{m.modality}</td>
                <td>
                  <StatusBadge value={m.status} kind="health" />
                </td>
                <td className="muted">
                  v{m.version} · {m.findings_24h} findings/24h
                </td>
              </tr>
            ))}
            {health.length === 0 && models.length === 0 ? (
              <tr>
                <td colSpan={4}>
                  <div className="empty">No health telemetry yet.</div>
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </section>

      <div className="list-detail">
        <div className="panel" style={{ padding: 0 }}>
          {rows.map((row) => (
            <button
              key={row.service}
              type="button"
              className={`list-item${active?.service === row.service ? ' active' : ''}`}
              onClick={() => setSelected(row.service)}
            >
              <strong>{row.service}</strong>
              <div className="muted">
                <StatusBadge value={row.max_severity} kind="severity" /> {row.open_incidents} open ·{' '}
                {row.findings} findings
              </div>
            </button>
          ))}
          {rows.length === 0 ? <div className="empty">No services found.</div> : null}
        </div>

        <div className="panel">
          {active ? (
            <>
              <h2>{active.service}</h2>
              <dl className="kv">
                <dt>Open incidents</dt>
                <dd>{active.open_incidents}</dd>
                <dt>Findings</dt>
                <dd>{active.findings}</dd>
                <dt>Max severity</dt>
                <dd>
                  <StatusBadge value={active.max_severity} kind="severity" />
                </dd>
                <dt>Assets</dt>
                <dd>
                  {active.assets.length
                    ? active.assets.map((a, i) => (
                        <span key={a}>
                          {i > 0 ? ', ' : ''}
                          <Link to={`/assets/${a}`}>{a}</Link>
                        </span>
                      ))
                    : '—'}
                </dd>
              </dl>
              <h3>Related incidents</h3>
              <ul className="plain-list">
                {relatedIncidents.map((inc) => (
                  <li key={inc.incident_id}>
                    <Link to={`/incidents/${inc.incident_id}`}>{inc.title}</Link>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <div className="empty">Select a service.</div>
          )}
        </div>
      </div>
    </div>
  )
}

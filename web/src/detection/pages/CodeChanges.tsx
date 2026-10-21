import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { CodeEnrichmentInfo, Finding, Incident } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'

type CodeRow = {
  id: string
  title: string
  commit: string | null
  deployment_id: string | null
  service: string
  severity: string
  risk_score: number
  incident_id: string | null
  summary: string
  enrichment_status: string | null
  cwe_ids: string[]
  enrichment_link: string | null
}

export function CodeChanges() {
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
    const fromFindings: CodeRow[] = findings
      .filter((f) => f.kind === 'code')
      .map((f) => {
        const inc = incidents.find((i) => i.incident_id === f.incident_id)
        const ctxEnrich = (inc?.context?.code_enrichment || {}) as CodeEnrichmentInfo
        const enrichmentStatus =
          f.enrichment?.status ??
          (typeof ctxEnrich.status === 'string' ? ctxEnrich.status : null)
        const cweIds =
          f.cwe_ids ??
          f.enrichment?.cwe_ids ??
          (Array.isArray(ctxEnrich.cwe_ids) ? ctxEnrich.cwe_ids : []) ??
          []
        return {
          id: f.finding_id,
          title: f.title,
          commit: inc?.commit ?? null,
          deployment_id: inc?.deployment_id ?? null,
          service: f.service,
          severity: f.severity,
          risk_score: f.risk_score,
          incident_id: f.incident_id,
          summary: f.summary,
          enrichment_status: enrichmentStatus,
          cwe_ids: cweIds,
          enrichment_link: f.incident_id ? `/incidents/${f.incident_id}` : null,
        }
      })
    if (fromFindings.length > 0) return fromFindings
    return incidents
      .filter((i) => i.commit || i.evidence.some((e) => e.kind === 'code'))
      .map((i) => {
        const enrich = (i.context?.code_enrichment || {}) as CodeEnrichmentInfo
        return {
          id: i.incident_id,
          title: i.title,
          commit: i.commit,
          deployment_id: i.deployment_id,
          service: i.services[0] ?? 'unknown',
          severity: i.severity,
          risk_score: i.risk_score,
          incident_id: i.incident_id,
          summary: i.summary,
          enrichment_status: typeof enrich.status === 'string' ? enrich.status : null,
          cwe_ids: Array.isArray(enrich.cwe_ids) ? enrich.cwe_ids : [],
          enrichment_link: `/incidents/${i.incident_id}`,
        }
      })
  }, [findings, incidents])

  const active = rows.find((r) => r.id === selected) ?? rows[0] ?? null

  if (loading) return <div className="loading">Loading code changes…</div>
  if (error) return <div className="error">{error}</div>

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>Code changes</h1>
          <p>Code-model findings and deployment-linked commits (advisory).</p>
        </div>
      </header>

      <div className="callout callout-advisory" style={{ marginBottom: '1rem' }}>
        <strong>Advisory</strong>
        <p>
          Code change signals highlight correlated risk in recent commits and deployments. They are
          not vulnerability confirmations.
        </p>
      </div>

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
                {row.commit ? ` · ${row.commit}` : ''}
              </div>
            </button>
          ))}
          {rows.length === 0 ? <div className="empty">No code-change signals.</div> : null}
        </div>

        <div className="panel">
          {active ? (
            <>
              <h2>{active.title}</h2>
              <dl className="kv">
                <dt>Commit</dt>
                <dd className="mono">{active.commit ?? '—'}</dd>
                <dt>Deployment</dt>
                <dd className="mono">{active.deployment_id ?? '—'}</dd>
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
                <dt>Enrichment</dt>
                <dd>
                  {active.enrichment_status ? (
                    <>
                      <span className="mono">{active.enrichment_status}</span>
                      {active.enrichment_link ? (
                        <>
                          {' '}
                          <Link to={active.enrichment_link}>view incident</Link>
                        </>
                      ) : null}
                      <div className="muted" style={{ marginTop: '0.25rem' }}>
                        Human review required — advisory leads only.
                      </div>
                    </>
                  ) : (
                    '—'
                  )}
                </dd>
                <dt>CWEs</dt>
                <dd className="mono">
                  {active.cwe_ids.length > 0 ? active.cwe_ids.join(', ') : '—'}
                </dd>
              </dl>
              <p>{active.summary}</p>
            </>
          ) : (
            <div className="empty">Select a code change.</div>
          )}
        </div>
      </div>
    </div>
  )
}

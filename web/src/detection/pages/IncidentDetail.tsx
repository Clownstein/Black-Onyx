import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import type {
  CodeEnrichmentInfo,
  Comment,
  DeploymentEvent,
  Incident,
  IncidentDisposition,
  TimelineEntry,
} from '../api/contracts'
import { EvidenceTabs } from '../components/EvidenceTabs'
import { InvestigationAssist } from '../components/InvestigationAssist'
import { StatusBadge } from '../components/StatusBadge'
import { Timeline } from '../components/Timeline'
import { formatTime } from '../utils/format'
import { useUser } from '../../user_context'

const DISPOSITIONS: IncidentDisposition[] = [
  'true_positive',
  'false_positive',
  'expected_change',
  'maintenance',
  'benign_anomaly',
  'duplicate',
  'unknown',
]

type ThreatIntelMatch = {
  type?: string
  value?: string
  confidence?: number
  source?: string
}

type ThreatIntelBlock = {
  matched_indicators?: ThreatIntelMatch[]
  campaigns?: string[]
}

type CodeEnrichmentBlock = CodeEnrichmentInfo

function threatIntelFromIncident(incident: Incident): ThreatIntelBlock | null {
  const ctx = incident.context || {}
  const fromContext = ctx.threat_intel as ThreatIntelBlock | undefined
  if (fromContext?.matched_indicators?.length) return fromContext
  const top = (incident as Incident & { threat_intel?: ThreatIntelBlock }).threat_intel
  if (top?.matched_indicators?.length) return top
  return null
}

function codeEnrichmentFromIncident(incident: Incident): CodeEnrichmentBlock | null {
  const ctx = incident.context || {}
  const fromContext = ctx.code_enrichment as CodeEnrichmentBlock | undefined
  if (fromContext && (fromContext.status || (fromContext.cwe_ids && fromContext.cwe_ids.length))) {
    return fromContext
  }
  return null
}

export function IncidentDetail() {
  const user = useUser()
  const { id = '' } = useParams()
  const [incident, setIncident] = useState<Incident | null>(null)
  const [timeline, setTimeline] = useState<TimelineEntry[]>([])
  const [comments, setComments] = useState<Comment[]>([])
  const [related, setRelated] = useState<Incident[]>([])
  const [similar, setSimilar] = useState<
    { id: string; title: string; score: number; source: string; summary?: string }[]
  >([])
  const [runbooks, setRunbooks] = useState<{ title: string; score: number; path: string }[]>([])
  const [deployments, setDeployments] = useState<DeploymentEvent[]>([])
  const [deploymentError, setDeploymentError] = useState<string | null>(null)
  const [dependencyWarnings, setDependencyWarnings] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [assignee, setAssignee] = useState('alex.ops')
  const [commentBody, setCommentBody] = useState('')
  const [disposition, setDisposition] = useState<IncidentDisposition>('true_positive')
  const [note, setNote] = useState('')
  const [feedbackLabel, setFeedbackLabel] = useState('true_positive')
  const [feedbackNote, setFeedbackNote] = useState('')
  const [actionMsg, setActionMsg] = useState<string | null>(null)

  const reload = useCallback(async () => {
    const warnings: string[] = []
    const [inc, tl, cmts, rel, sim, books] = await Promise.all([
      api.getIncident(id),
      api.getTimeline(id),
      api.getComments(id),
      api.listRelated(id).catch(() => [] as Incident[]),
      api.listSimilarIncidents(id).catch((err) => {
        warnings.push(`similar incidents: ${err instanceof Error ? err.message : String(err)}`)
        return []
      }),
      api.getRunbookSuggestions(id).catch((err) => {
        warnings.push(`runbooks: ${err instanceof Error ? err.message : String(err)}`)
        return { items: [] }
      }),
    ])
    setIncident(inc)
    setTimeline(tl)
    setComments(cmts)
    setRelated(rel)
    setSimilar(sim)
    setRunbooks(books.items)
    setDependencyWarnings(warnings)
    if (inc.services[0]) {
      try {
        setDeployments(await api.listDeployments(inc.services[0]))
        setDeploymentError(null)
      } catch (err) {
        setDeployments([])
        setDeploymentError(err instanceof Error ? err.message : String(err))
      }
    }
    if (inc.assigned_to) setAssignee(inc.assigned_to)
    if (inc.disposition) setDisposition(inc.disposition)
  }, [id])

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      setLoading(true)
      setError(null)
      try {
        await reload()
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e))
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [reload])

  async function run(action: () => Promise<unknown>) {
    setBusy(true)
    setError(null)
    try {
      await action()
      await reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <div className="loading">Loading incident…</div>
  if (error && !incident) return <div className="error">{error}</div>
  if (!incident) return <div className="empty">Incident not found.</div>

  return (
    <div>
      <header className="page-header">
        <div>
          <p className="muted" style={{ margin: 0 }}>
            <Link to="/incidents">Incidents</Link> /{' '}
            <span className="mono">{incident.incident_id}</span>
          </p>
          <h1 style={{ marginTop: '0.35rem' }}>{incident.title}</h1>
          <p>
            <StatusBadge value={incident.severity} kind="severity" />{' '}
            <StatusBadge value={incident.status} kind="status" />{' '}
            <span className="mono muted">risk {incident.risk_score.toFixed(2)}</span>
          </p>
        </div>
      </header>

      {error ? <div className="error" style={{ marginBottom: '1rem' }}>{error}</div> : null}
      {actionMsg ? (
        <div className="muted" style={{ marginBottom: '1rem' }} role="status">
          {actionMsg}
        </div>
      ) : null}
      {dependencyWarnings.length ? (
        <div className="error" style={{ marginBottom: '1rem' }}>
          Partial dependencies unavailable: {dependencyWarnings.join('; ')}
        </div>
      ) : null}

      <div className="detail-grid">
        <div className="grid" style={{ gap: '1rem' }}>
          <section className="panel">
            <h2>Summary</h2>
            <p style={{ marginTop: 0 }}>{incident.summary}</p>
            <dl className="kv">
              <dt>Services</dt>
              <dd>{incident.services.join(', ') || '—'}</dd>
              <dt>Assets</dt>
              <dd>
                <div className="chips">
                  {incident.assets.map((a) => (
                    <Link key={a} className="chip" to={`/assets/${a}`}>
                      {a}
                    </Link>
                  ))}
                </div>
              </dd>
              <dt>Models</dt>
              <dd>
                <div className="chips">
                  {incident.models.map((m) => (
                    <Link key={m} className="chip" to={`/models/${m}`}>
                      {m}
                    </Link>
                  ))}
                </div>
              </dd>
              <dt>First seen</dt>
              <dd className="mono">{formatTime(incident.first_seen)}</dd>
              <dt>Last seen</dt>
              <dd className="mono">{formatTime(incident.last_seen)}</dd>
              <dt>Assigned</dt>
              <dd>{incident.assigned_to ?? '—'}</dd>
              <dt>Disposition</dt>
              <dd>{incident.disposition ?? '—'}</dd>
              <dt>Deploy / commit</dt>
              <dd className="mono">
                {incident.deployment_id ?? '—'} / {incident.commit ?? '—'}
              </dd>
              {(() => {
                const ti = threatIntelFromIncident(incident)
                if (!ti) return null
                const matches = ti.matched_indicators ?? []
                return (
                  <>
                    <dt>Threat intel</dt>
                    <dd>
                      <div className="chips">
                        {matches.map((m, i) => (
                          <span key={`${m.type}-${m.value}-${i}`} className="chip" title={m.source}>
                            {m.type}:{m.value}
                            {m.confidence != null ? ` (${m.confidence})` : ''}
                          </span>
                        ))}
                        {(ti.campaigns ?? []).map((c) => (
                          <span key={c} className="chip">
                            campaign:{c}
                          </span>
                        ))}
                      </div>
                    </dd>
                  </>
                )
              })()}
              {(() => {
                const enrich = codeEnrichmentFromIncident(incident)
                if (!enrich) return null
                return (
                  <>
                    <dt>Code enrichment</dt>
                    <dd>
                      <span className="mono">{enrich.status ?? 'unknown'}</span>
                      {(enrich.cwe_ids ?? []).length > 0 ? (
                        <div className="chips" style={{ marginTop: '0.35rem' }}>
                          {(enrich.cwe_ids ?? []).map((c) => (
                            <span key={c} className="chip">
                              {c}
                            </span>
                          ))}
                        </div>
                      ) : null}
                      {(enrich.file_hits ?? []).length > 0 ? (
                        <ul className="muted" style={{ marginTop: '0.35rem' }}>
                          {(enrich.file_hits ?? []).slice(0, 5).map((h, i) => (
                            <li key={`${h.path}-${i}`} className="mono">
                              {h.path ?? '—'}
                              {h.cwe_ids?.length ? ` (${h.cwe_ids.join(', ')})` : ''}
                            </li>
                          ))}
                        </ul>
                      ) : null}
                      <div className="muted" style={{ marginTop: '0.35rem' }}>
                        {enrich.advisory ??
                          'Antares file-level leads require human review; not autonomous remediation.'}
                      </div>
                    </dd>
                  </>
                )
              })()}
            </dl>
          </section>

          <section className="panel">
            <h2>Unified timeline</h2>
            <Timeline entries={timeline} />
          </section>

          <section className="panel">
            <h2>Deployment history</h2>
            {deploymentError ? <div className="error">{deploymentError}</div> : null}
            {deployments.length === 0 && !deploymentError ? (
              <div className="empty">No deployment events for this service.</div>
            ) : (
              <table className="data">
                <thead>
                  <tr>
                    <th>Deployment</th>
                    <th>Version / commit</th>
                    <th>Status</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {deployments.map((deployment) => (
                    <tr key={deployment.deployment_id}>
                      <td className="mono">{deployment.deployment_id}</td>
                      <td className="mono">
                        {deployment.version ?? '—'} / {deployment.commit_sha ?? '—'}
                      </td>
                      <td>
                        <StatusBadge value={deployment.status} kind="status" />
                      </td>
                      <td>{formatTime(deployment.deployed_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="panel">
            <h2>Evidence</h2>
            <EvidenceTabs key={incident.incident_id} evidence={incident.evidence} />
          </section>

          <InvestigationAssist
            incident={incident}
            onUseDraft={(text) => setCommentBody(text)}
          />

          <section className="panel">
            <h2>Related activity</h2>
            {related.length === 0 ? (
              <div className="empty">No related incidents on shared assets/services.</div>
            ) : (
              <ul className="contributor-list">
                {related.map((r) => (
                  <li key={r.incident_id}>
                    <Link to={`/incidents/${r.incident_id}`}>{r.title}</Link>
                    <span className="mono muted">
                      {r.severity} · {r.status}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="panel">
            <h2>Similar incidents</h2>
            {similar.length === 0 ? (
              <div className="empty">No vector neighbors (disabled or none).</div>
            ) : (
              <ul className="contributor-list">
                {similar.map((s) => (
                  <li key={s.id}>
                    <Link to={`/incidents/${s.id}`}>{s.title}</Link>
                    <span className="mono muted">
                      {s.source} · {s.score.toFixed(2)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="panel">
            <h2>Runbook suggestions</h2>
            {runbooks.length === 0 ? (
              <div className="empty">No runbook suggestions.</div>
            ) : (
              <ul className="contributor-list">
                {runbooks.map((r) => (
                  <li key={r.path}>
                    <strong>{r.title}</strong>
                    <span className="mono muted">
                      {r.path} · {r.score.toFixed(2)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="panel">
            <h2>Comments</h2>
            {comments.length === 0 ? (
              <div className="empty">No comments yet.</div>
            ) : (
              <ul className="timeline">
                {comments.map((c) => (
                  <li key={c.comment_id} className="timeline-item">
                    <div className="timeline-time">{formatTime(c.created_at)}</div>
                    <div className="timeline-body">
                      <strong>{c.author}</strong>
                      <div>{c.body}</div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        <aside className="panel action-panel">
          <h2>Actions</h2>
          <div className="actions">
            <button
              type="button"
              className="btn"
              disabled={busy || incident.status === 'acknowledged' || incident.status === 'resolved'}
              onClick={() => run(() => api.acknowledge(incident.incident_id))}
            >
              Acknowledge
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy || incident.status === 'resolved'}
              onClick={() => run(() => api.resolve(incident.incident_id))}
            >
              Resolve
            </button>
            {api.grafanaEnabled ? (
              <a
                className="btn"
                href={api.grafanaExploreUrl(incident)}
                target="_blank"
                rel="noreferrer"
              >
                Grafana Explore
              </a>
            ) : null}
            {api.integrationHubEnabled ? (
              <>
                <button
                  type="button"
                  className="btn"
                  disabled={busy}
                  onClick={() =>
                    run(async () => {
                      const result = await api.openTheHiveCase(incident)
                      setActionMsg(
                        result.dry_run
                          ? `TheHive dry-run stored (${result.case_id ?? 'ok'})`
                          : `TheHive case ${result.case_id ?? 'created'}`,
                      )
                    })
                  }
                >
                  Open TheHive case
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={busy || incident.assets.length === 0}
                  onClick={() =>
                    run(async () => {
                      const result = await api.requestVelociraptorCollect(incident)
                      setActionMsg(
                        `Velociraptor collect ${result.request_id} (${result.status})`,
                      )
                    })
                  }
                >
                  Velociraptor collect
                </button>
              </>
            ) : null}
          </div>

          <div className="field">
            <label htmlFor="assignee">Assign</label>
            <input
              id="assignee"
              value={assignee}
              onChange={(e) => setAssignee(e.target.value)}
              disabled={busy}
            />
            <button
              type="button"
              className="btn"
              disabled={busy || !assignee.trim()}
              onClick={() => run(() => api.assign(incident.incident_id, assignee.trim()))}
            >
              Assign
            </button>
          </div>

          <div className="field">
            <label htmlFor="comment">Comment</label>
            <textarea
              id="comment"
              value={commentBody}
              onChange={(e) => setCommentBody(e.target.value)}
              disabled={busy}
              placeholder="Add investigation notes…"
            />
            <button
              type="button"
              className="btn"
              disabled={busy || !commentBody.trim()}
              onClick={() =>
                run(async () => {
                  await api.comment(incident.incident_id, user.email || user.user_id || 'session', commentBody.trim())
                  setCommentBody('')
                })
              }
            >
              Comment
            </button>
          </div>

          <div className="field">
            <label htmlFor="disposition">Disposition</label>
            <select
              id="disposition"
              value={disposition}
              onChange={(e) => setDisposition(e.target.value as IncidentDisposition)}
              disabled={busy}
            >
              {DISPOSITIONS.map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </select>
            <input
              aria-label="Disposition note"
              placeholder="Optional note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              disabled={busy}
            />
            <button
              type="button"
              className="btn"
              disabled={busy}
              onClick={() =>
                run(async () => {
                  await api.disposition(incident.incident_id, disposition, note.trim() || undefined)
                  setNote('')
                })
              }
            >
              Set disposition
            </button>
          </div>

          <div className="field">
            <label htmlFor="analyst-feedback">Analyst feedback</label>
            <select
              id="analyst-feedback"
              value={feedbackLabel}
              onChange={(e) => setFeedbackLabel(e.target.value)}
              disabled={busy}
            >
              <option value="true_positive">True positive</option>
              <option value="false_positive">False positive</option>
              <option value="expected_change">Expected change</option>
              <option value="needs_review">Needs review</option>
            </select>
            <textarea
              aria-label="Analyst feedback note"
              placeholder="Feedback used for calibration and model review"
              value={feedbackNote}
              onChange={(e) => setFeedbackNote(e.target.value)}
              disabled={busy}
            />
            <button
              type="button"
              className="btn"
              disabled={busy}
              onClick={() =>
                run(async () => {
                  await api.createAnalystFeedback(incident.incident_id, {
                    label: feedbackLabel,
                    note: feedbackNote.trim() || undefined,
                  })
                  setFeedbackNote('')
                  setActionMsg('Analyst feedback saved.')
                })
              }
            >
              Save feedback
            </button>
          </div>
        </aside>
      </div>
    </div>
  )
}

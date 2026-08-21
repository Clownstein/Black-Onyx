import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api/client'
import type { Finding } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'
import { formatTime } from '../utils/format'

export function Findings() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [rows, setRows] = useState<Finding[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [modelFilter, setModelFilter] = useState('')
  const [similar, setSimilar] = useState<
    { id: string; title: string; score: number; source: string; summary?: string }[]
  >([])
  const [similarError, setSimilarError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const data = await api.listFindings()
        if (!cancelled) setRows(data)
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

  const models = useMemo(
    () => [...new Set(rows.map((r) => r.model))].sort(),
    [rows],
  )

  const filtered = useMemo(
    () => (modelFilter ? rows.filter((r) => r.model === modelFilter) : rows),
    [rows, modelFilter],
  )

  const matched = id ? (rows.find((r) => r.finding_id === id) ?? null) : null
  const notFound = Boolean(id) && !loading && !matched
  const selected = matched ?? (id ? null : (filtered[0] ?? null))

  const selectedFindingId = selected?.finding_id
  useEffect(() => {
    if (!selectedFindingId) {
      setSimilar([])
      return
    }
    let cancelled = false
    setSimilarError(null)
    void api
      .listSimilarFindings(selectedFindingId)
      .then((items) => {
        if (!cancelled) setSimilar(items)
      })
      .catch((err) => {
        if (!cancelled) {
          setSimilar([])
          setSimilarError(err instanceof Error ? err.message : String(err))
        }
      })
    return () => {
      cancelled = true
    }
  }, [selectedFindingId])

  if (loading) return <div className="loading">Loading findings…</div>
  if (error) return <div className="error">{error}</div>

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>Findings</h1>
          <p>Per-model anomaly findings linked to incidents.</p>
        </div>
      </header>

      <div className="toolbar">
        <select
          aria-label="Filter by model"
          value={modelFilter}
          onChange={(e) => setModelFilter(e.target.value)}
        >
          <option value="">All models</option>
          {models.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <span className="muted">{filtered.length} findings</span>
      </div>

      <div className="list-detail">
        <div className="panel" style={{ padding: 0 }}>
          {filtered.map((row) => (
            <Link
              key={row.finding_id}
              to={`/findings/${row.finding_id}`}
              className={`list-item${selected?.finding_id === row.finding_id ? ' active' : ''}`}
            >
              <strong>{row.title}</strong>
              <div className="muted">
                <StatusBadge value={row.severity} kind="severity" /> {row.model} ·{' '}
                {row.risk_score.toFixed(2)}
              </div>
            </Link>
          ))}
        </div>

        <div className="panel">
          {notFound ? (
            <div className="empty">
              Finding <span className="mono">{id}</span> was not found.{' '}
              <Link to="/findings">Back to all findings</Link>
            </div>
          ) : selected ? (
            <>
              <h2>{selected.title}</h2>
              <dl className="kv">
                <dt>ID</dt>
                <dd className="mono">{selected.finding_id}</dd>
                <dt>Model</dt>
                <dd>
                  <Link to={`/models/${selected.model}`}>{selected.model}</Link>
                </dd>
                <dt>Kind</dt>
                <dd>{selected.kind}</dd>
                <dt>Severity</dt>
                <dd>
                  <StatusBadge value={selected.severity} kind="severity" />
                </dd>
                <dt>Risk</dt>
                <dd className="mono">{selected.risk_score.toFixed(2)}</dd>
                <dt>Service</dt>
                <dd>{selected.service}</dd>
                <dt>Asset</dt>
                <dd>
                  <Link to={`/assets/${selected.asset_id}`}>{selected.asset_id}</Link>
                </dd>
                <dt>Incident</dt>
                <dd>
                  {selected.incident_id ? (
                    <Link to={`/incidents/${selected.incident_id}`}>{selected.incident_id}</Link>
                  ) : (
                    '—'
                  )}
                </dd>
                <dt>First seen</dt>
                <dd className="mono">{formatTime(selected.first_seen)}</dd>
                <dt>Last seen</dt>
                <dd className="mono">{formatTime(selected.last_seen)}</dd>
              </dl>
              <p>{selected.summary}</p>
              <h3>Similar findings</h3>
              {similarError ? (
                <div className="error">Similarity unavailable: {similarError}</div>
              ) : similar.length === 0 ? (
                <div className="empty">No vector neighbors (disabled or none).</div>
              ) : (
                <ul className="contributor-list">
                  {similar.map((s) => (
                    <li key={s.id}>
                      <Link to={`/findings/${s.id}`}>{s.title}</Link>
                      <span className="mono muted">
                        {s.source} · {s.score.toFixed(2)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              {!id ? (
                <button
                  type="button"
                  className="btn"
                  onClick={() => navigate(`/findings/${selected.finding_id}`)}
                >
                  Open detail route
                </button>
              ) : null}
            </>
          ) : (
            <div className="empty">Select a finding.</div>
          )}
        </div>
      </div>
    </div>
  )
}

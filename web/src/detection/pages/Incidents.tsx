import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { Incident } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'
import { formatTime } from '../utils/format'

type SortKey =
  | 'severity'
  | 'risk_score'
  | 'title'
  | 'status'
  | 'service'
  | 'first_seen'
  | 'last_seen'

const SEV_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

export function Incidents() {
  const [rows, setRows] = useState<Incident[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [q, setQ] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('risk_score')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [showCreate, setShowCreate] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newSeverity, setNewSeverity] = useState('medium')
  const [newSummary, setNewSummary] = useState('')
  const [busy, setBusy] = useState(false)

  async function refresh() {
    try {
      setRows(await api.listIncidents())
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void refresh()
     
  }, [])

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    if (!newTitle.trim()) return
    setBusy(true)
    setError(null)
    try {
      await api.createIncident({
        title: newTitle.trim(),
        severity: newSeverity,
        summary: newSummary.trim() || undefined,
      })
      setShowCreate(false)
      setNewTitle('')
      setNewSummary('')
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    let list = rows.filter((r) => {
      if (severity && r.severity !== severity) return false
      if (status && r.status !== status) return false
      if (!needle) return true
      const hay = [
        r.title,
        r.incident_id,
        r.services.join(' '),
        r.assets.join(' '),
        r.models.join(' '),
        r.status,
      ]
        .join(' ')
        .toLowerCase()
      return hay.includes(needle)
    })

    list = [...list].sort((a, b) => {
      let cmp = 0
      switch (sortKey) {
        case 'severity':
          cmp = (SEV_RANK[a.severity] ?? 0) - (SEV_RANK[b.severity] ?? 0)
          break
        case 'risk_score':
          cmp = a.risk_score - b.risk_score
          break
        case 'title':
          cmp = a.title.localeCompare(b.title)
          break
        case 'status':
          cmp = a.status.localeCompare(b.status)
          break
        case 'service':
          cmp = (a.services[0] ?? '').localeCompare(b.services[0] ?? '')
          break
        case 'first_seen':
          cmp = a.first_seen.localeCompare(b.first_seen)
          break
        case 'last_seen':
          cmp = a.last_seen.localeCompare(b.last_seen)
          break
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
    return list
  }, [rows, q, severity, status, sortKey, sortDir])

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir(key === 'title' || key === 'status' || key === 'service' ? 'asc' : 'desc')
    }
  }

  function th(key: SortKey, label: string) {
    const active = sortKey === key
    return (
      <th
        className={active ? 'sorted' : undefined}
        aria-sort={active ? (sortDir === 'asc' ? 'ascending' : 'descending') : undefined}
      >
        <button type="button" className="th-sort" onClick={() => toggleSort(key)}>
          {label}
          {active ? (sortDir === 'asc' ? ' ↑' : ' ↓') : ''}
        </button>
      </th>
    )
  }

  if (loading) return <div className="loading">Loading incidents…</div>

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>Incidents</h1>
          <p>Filter and sort correlated multi-model incidents.</p>
        </div>
        <button type="button" className="btn btn-primary" onClick={() => setShowCreate((v) => !v)}>
          {showCreate ? 'Cancel' : 'Create incident'}
        </button>
      </header>

      {error ? <div className="error">{error}</div> : null}

      {showCreate ? (
        <form className="panel toolbar" onSubmit={onCreate} style={{ marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
          <input
            required
            aria-label="Title"
            placeholder="Incident title"
            value={newTitle}
            onChange={(e) => setNewTitle(e.target.value)}
            style={{ minWidth: '16rem' }}
          />
          <select
            aria-label="Severity"
            value={newSeverity}
            onChange={(e) => setNewSeverity(e.target.value)}
          >
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select>
          <input
            aria-label="Summary"
            placeholder="Summary (optional)"
            value={newSummary}
            onChange={(e) => setNewSummary(e.target.value)}
            style={{ minWidth: '16rem' }}
          />
          <button type="submit" className="btn btn-primary" disabled={busy}>
            Create
          </button>
        </form>
      ) : null}

      <div className="toolbar">
        <input
          aria-label="Search incidents"
          placeholder="Search title, service, asset, model…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <select
          aria-label="Filter severity"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="">All severities</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
        <select aria-label="Filter status" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          <option value="open">open</option>
          <option value="acknowledged">acknowledged</option>
          <option value="investigating">investigating</option>
          <option value="resolved">resolved</option>
          <option value="closed">closed</option>
          <option value="suppressed">suppressed</option>
        </select>
        <span className="muted">{filtered.length} shown</span>
      </div>

      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              {th('severity', 'Severity')}
              {th('risk_score', 'Risk')}
              {th('title', 'Title')}
              {th('status', 'Status')}
              {th('service', 'Service')}
              <th>Assets</th>
              <th>Models</th>
              {th('first_seen', 'First seen')}
              {th('last_seen', 'Last seen')}
            </tr>
          </thead>
          <tbody>
            {filtered.map((row) => (
              <tr key={row.incident_id}>
                <td>
                  <StatusBadge value={row.severity} kind="severity" />
                </td>
                <td className="mono">{row.risk_score.toFixed(2)}</td>
                <td className="wrap">
                  <Link to={`/incidents/${row.incident_id}`}>{row.title}</Link>
                </td>
                <td>
                  <StatusBadge value={row.status} kind="status" />
                </td>
                <td>{row.services[0] ?? '—'}</td>
                <td>
                  <div className="chips">
                    {row.assets.slice(0, 2).map((a) => (
                      <span key={a} className="chip">
                        {a}
                      </span>
                    ))}
                    {row.assets.length > 2 ? (
                      <span className="chip">+{row.assets.length - 2}</span>
                    ) : null}
                  </div>
                </td>
                <td>
                  <div className="chips">
                    {(row.models.length ? row.models : ['—']).slice(0, 3).map((m) => (
                      <span key={m} className="chip">
                        {m}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="mono">{formatTime(row.first_seen)}</td>
                <td className="mono">{formatTime(row.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

import { useEffect, useState, type FormEvent } from 'react'
import { api } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import { formatTime } from '../utils/format'
import { useUser } from '../../user_context'

type PendingResponse = {
  request_id: string
  incident_id: string
  playbook_id: string
  action: string
  status: string
  dry_run?: boolean
  payload?: { response_mode?: string; auto_execute?: boolean; signals?: Record<string, unknown> }
}

type Playbook = { playbook_id: string; title?: string; description?: string }
type AuditRow = {
  id: string
  request_id: string
  action: string
  actor?: string
  created_at?: string
}

export function ResponseQueue() {
  const user = useUser()
  const [items, setItems] = useState<PendingResponse[]>([])
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [audit, setAudit] = useState<AuditRow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [incidentId, setIncidentId] = useState('')
  const [playbookId, setPlaybookId] = useState('')
  const [dryRun, setDryRun] = useState(true)

  async function refresh() {
    setError(null)
    try {
      const [rowsResult, booksResult, auditResult] = await Promise.allSettled([
        api.listPendingResponses(),
        api.listPlaybooks(),
        api.listResponseAudit(30),
      ])
      if (rowsResult.status === 'fulfilled') setItems(rowsResult.value)
      if (booksResult.status === 'fulfilled') {
        const books = booksResult.value
        setPlaybooks(books)
        setPlaybookId((prev) => prev || books[0]?.playbook_id || '')
      }
      if (auditResult.status === 'fulfilled') setAudit(auditResult.value)
      const failures = [rowsResult, booksResult, auditResult]
        .filter((r): r is PromiseRejectedResult => r.status === 'rejected')
        .map((r) => (r.reason instanceof Error ? r.reason.message : String(r.reason)))
      if (failures.length) setError(failures.join('; '))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void refresh()
     
  }, [])

  async function onApprove(id: string) {
    setBusy(true)
    try {
      await api.approveResponse(id, user.email || user.user_id)
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function onReject(id: string) {
    setBusy(true)
    try {
      await api.rejectResponse(id, user.email || user.user_id)
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    if (!incidentId.trim() || !playbookId.trim()) {
      setError('Incident ID and playbook are required')
      return
    }
    setBusy(true)
    setError(null)
    try {
      await api.createResponseRequest({
        incident_id: incidentId.trim(),
        playbook_id: playbookId.trim(),
        dry_run: dryRun,
      })
      setIncidentId('')
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="page">
      <header className="page-header">
        <h1>Response queue</h1>
        <p className="muted">Human-gated SOAR approvals. Vector-only suggestions stay dry-run.</p>
      </header>
      {error ? <div className="error">{error}</div> : null}

      <section className="panel" style={{ marginBottom: '1rem' }}>
        <h2>Create response request</h2>
        <form className="toolbar" onSubmit={onCreate} style={{ flexWrap: 'wrap', gap: '0.75rem' }}>
          <input
            aria-label="Incident ID"
            placeholder="Incident ID"
            value={incidentId}
            onChange={(e) => setIncidentId(e.target.value)}
            style={{ minWidth: '12rem' }}
          />
          <select
            aria-label="Playbook"
            value={playbookId}
            onChange={(e) => setPlaybookId(e.target.value)}
          >
            {playbooks.length === 0 ? <option value="">No playbooks</option> : null}
            {playbooks.map((p) => (
              <option key={p.playbook_id} value={p.playbook_id}>
                {p.title ?? p.playbook_id}
              </option>
            ))}
          </select>
          <label className="muted">
            <input
              type="checkbox"
              checked={dryRun}
              onChange={(e) => setDryRun(e.target.checked)}
            />{' '}
            Dry-run
          </label>
          <button type="submit" className="btn btn-primary" disabled={busy || !playbookId}>
            Queue request
          </button>
        </form>
      </section>

      <section className="panel">
        <div className="toolbar" style={{ justifyContent: 'space-between' }}>
          <h2 style={{ margin: 0 }}>Pending</h2>
          <button type="button" className="btn" onClick={() => void refresh()} disabled={busy}>
            Refresh
          </button>
        </div>
        {loading ? (
          <div className="empty">Loading response queue…</div>
        ) : items.length === 0 ? (
          <div className="empty">No pending response requests.</div>
        ) : (
          <table className="table data">
            <thead>
              <tr>
                <th>Request</th>
                <th>Incident</th>
                <th>Playbook</th>
                <th>Mode</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={row.request_id}>
                  <td className="mono">{row.request_id}</td>
                  <td className="mono">{row.incident_id}</td>
                  <td className="mono">{row.playbook_id}</td>
                  <td className="muted">
                    {row.payload?.response_mode ?? (row.dry_run ? 'suggest_only' : 'execute')}
                  </td>
                  <td>
                    <StatusBadge value={row.status} kind="status" />
                  </td>
                  <td className="toolbar">
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={busy}
                      onClick={() => void onApprove(row.request_id)}
                    >
                      Approve
                    </button>
                    <button
                      type="button"
                      className="btn"
                      disabled={busy}
                      onClick={() => void onReject(row.request_id)}
                    >
                      Reject
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel" style={{ marginTop: '1rem' }}>
        <h2>Audit</h2>
        {loading ? (
          <div className="empty">Loading audit trail…</div>
        ) : audit.length === 0 ? (
          <div className="empty">No audit events yet.</div>
        ) : (
          <table className="table data">
            <thead>
              <tr>
                <th>ID</th>
                <th>Request</th>
                <th>Action</th>
                <th>Actor</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {audit.map((row) => (
                <tr key={row.id}>
                  <td className="mono">{row.id}</td>
                  <td className="mono">{row.request_id}</td>
                  <td>{row.action}</td>
                  <td className="muted">{row.actor ?? '—'}</td>
                  <td className="mono muted">{row.created_at ? formatTime(row.created_at) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}

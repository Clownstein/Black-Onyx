import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import { formatTime } from '../utils/format'
import { useUser } from '../../user_context'
import { isAdmin, isOperational } from '../../rbac'

type PendingResponse = {
  request_id: string
  incident_id: string
  playbook_id: string
  action: string
  status: string
  dry_run?: boolean
  payload?: { response_mode?: string; auto_execute?: boolean; signals?: Record<string, unknown> }
}

type Playbook = { playbook_id: string; title?: string; description?: string; asset_scoped: boolean }
type AuditRow = {
  id: string
  request_id: string
  action: string
  actor?: string
  created_at?: string
}
type UncertainResponse = {
  request_id: string
  incident_id: string
  playbook_id: string
  status: string
  result?: { message?: string; executed?: boolean | null }
}

export function ResponseQueue() {
  const [searchParams] = useSearchParams()
  const user = useUser()
  const canMutate = isOperational(user.role)
  const canApproveLive = isAdmin(user.role)
  const [items, setItems] = useState<PendingResponse[]>([])
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [audit, setAudit] = useState<AuditRow[]>([])
  const [uncertain, setUncertain] = useState<UncertainResponse[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [incidentId, setIncidentId] = useState(() => searchParams.get('incident') || '')
  const [playbookId, setPlaybookId] = useState(() => searchParams.get('playbook') || '')
  const [dryRun, setDryRun] = useState(true)
  const [livePreview, setLivePreview] = useState<PendingResponse | null>(null)
  const [incidentAssets, setIncidentAssets] = useState<string[]>([])
  const [assetId, setAssetId] = useState('')
  const [assetsError, setAssetsError] = useState<string | null>(null)
  const assetScoped = playbooks.find((p) => p.playbook_id === playbookId)?.asset_scoped ?? false

  useEffect(() => {
    const incident = searchParams.get('incident')
    const playbook = searchParams.get('playbook')
    if (incident) setIncidentId(incident)
    if (playbook) setPlaybookId(playbook)
  }, [searchParams])

  useEffect(() => {
    setIncidentAssets([])
    setAssetId('')
    setAssetsError(null)
    const id = incidentId.trim()
    if (!assetScoped || !id) return
    let cancelled = false
    const timer = window.setTimeout(() => {
      api.getIncident(id)
        .then((incident) => {
          if (cancelled) return
          setIncidentAssets(incident.assets)
          if (incident.assets.length === 1) setAssetId(incident.assets[0])
          if (incident.assets.length === 0) setAssetsError('This incident has no assets to target')
        })
        .catch((err) => {
          if (!cancelled) setAssetsError(err instanceof Error ? err.message : String(err))
        })
    }, 400)
    return () => {
      cancelled = true
      window.clearTimeout(timer)
    }
  }, [incidentId, assetScoped])

  const refresh = useCallback(async () => {
    setError(null)
    try {
      const [rowsResult, booksResult, auditResult, reconciliationResult] = await Promise.allSettled([
        api.listPendingResponses(),
        api.listPlaybooks(),
        api.listResponseAudit(30),
        canApproveLive ? api.listResponseReconciliation() : Promise.resolve([]),
      ])
      if (rowsResult.status === 'fulfilled') setItems(rowsResult.value)
      if (booksResult.status === 'fulfilled') {
        const books = booksResult.value
        setPlaybooks(books)
        setPlaybookId((prev) => prev || books[0]?.playbook_id || '')
      }
      if (auditResult.status === 'fulfilled') setAudit(auditResult.value)
      if (reconciliationResult.status === 'fulfilled') setUncertain(reconciliationResult.value)
      const failures = [rowsResult, booksResult, auditResult, reconciliationResult]
        .filter((r): r is PromiseRejectedResult => r.status === 'rejected')
        .map((r) => (r.reason instanceof Error ? r.reason.message : String(r.reason)))
      if (failures.length) setError(failures.join('; '))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [canApproveLive])

  useEffect(() => {
    void refresh()
  }, [refresh])

  async function onApprove(id: string) {
    if (!canMutate) return
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

  async function onApproveLive() {
    if (!canApproveLive || !livePreview) return
    setBusy(true)
    try {
      await api.approveResponse(livePreview.request_id, user.email || user.user_id, true)
      setLivePreview(null)
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function onReject(id: string) {
    if (!canMutate) return
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

  async function onScanReconciliation() {
    if (!canApproveLive) return
    setBusy(true)
    try {
      await api.scanResponseReconciliation()
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    if (!canMutate) return
    if (!incidentId.trim() || !playbookId.trim()) {
      setError('Incident ID and playbook are required')
      return
    }
    if (assetScoped && !assetId) {
      setError('Choose the target asset for this playbook')
      return
    }
    setBusy(true)
    setError(null)
    try {
      await api.createResponseRequest({
        incident_id: incidentId.trim(),
        playbook_id: playbookId.trim(),
        asset_id: assetScoped ? assetId : undefined,
        dry_run: dryRun,
      })
      setIncidentId('')
      setAssetId('')
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

      {canMutate ? (
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
              {playbooks.length === 0 && !playbookId ? <option value="">No playbooks</option> : null}
              {playbookId && !playbooks.some((p) => p.playbook_id === playbookId) ? (
                <option value={playbookId}>{playbookId}</option>
              ) : null}
              {playbooks.map((p) => (
                <option key={p.playbook_id} value={p.playbook_id}>
                  {p.title ?? p.playbook_id}
                </option>
              ))}
            </select>
            {assetScoped ? (
              <select
                aria-label="Target asset"
                value={assetId}
                onChange={(e) => setAssetId(e.target.value)}
                disabled={incidentAssets.length === 0}
              >
                <option value="">
                  {incidentAssets.length === 0 ? 'Enter an incident to list its assets' : 'Choose target asset…'}
                </option>
                {incidentAssets.map((asset) => (
                  <option key={asset} value={asset}>{asset}</option>
                ))}
              </select>
            ) : null}
            {assetsError ? <span className="error">{assetsError}</span> : null}
            <label className="check">
              <input
                type="checkbox"
                checked={dryRun}
                onChange={(e) => setDryRun(e.target.checked)}
                disabled
              />
              Dry-run
            </label>
            <button type="submit" className="btn btn-primary" disabled={busy || !playbookId || (assetScoped && !assetId)}>
              Queue request
            </button>
          </form>
        </section>
      ) : null}

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
                    {canMutate ? (
                      <>
                        <button
                          type="button"
                          className="btn btn-primary"
                          disabled={busy}
                          onClick={() => void onApprove(row.request_id)}
                        >
                          Approve
                        </button>
                        {canApproveLive ? (
                          <button type="button" className="btn" disabled={busy} onClick={() => setLivePreview(row)}>
                            Review live
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="btn"
                          disabled={busy}
                          onClick={() => void onReject(row.request_id)}
                        >
                          Reject
                        </button>
                      </>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {canApproveLive ? (
        <section className="panel" aria-label="Response reconciliation" style={{ marginTop: '1rem' }}>
          <h2>Execution outcomes to verify</h2>
          <p className="muted">These actions may have reached an external system before the response service lost their result. Check the external system and audit trail before creating another request.</p>
          <button type="button" className="btn" disabled={busy} onClick={() => void onScanReconciliation()}>
            Check stale executions
          </button>
          {uncertain.length === 0 ? (
            <div className="empty">No uncertain execution outcomes.</div>
          ) : (
            <table className="table data">
              <thead><tr><th>Request</th><th>Incident</th><th>Playbook</th><th>Outcome</th></tr></thead>
              <tbody>{uncertain.map((row) => (
                <tr key={row.request_id}>
                  <td className="mono">{row.request_id}</td>
                  <td className="mono">{row.incident_id}</td>
                  <td>{row.playbook_id}</td>
                  <td>{row.result?.message ?? 'Verify external state'}</td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </section>
      ) : null}

      {livePreview && canApproveLive ? (
        <section className="panel" aria-label="Live response preview" style={{ marginTop: '1rem' }}>
          <h2>Review live response</h2>
          <p>Executing this playbook can change external systems. Verify the incident and playbook before approving.</p>
          <p><strong>Request:</strong> {livePreview.request_id}</p>
          <p><strong>Incident:</strong> {livePreview.incident_id}</p>
          <p><strong>Playbook:</strong> {livePreview.playbook_id}</p>
          <div className="toolbar">
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void onApproveLive()}>Execute live</button>
            <button type="button" className="btn" disabled={busy} onClick={() => setLivePreview(null)}>Cancel</button>
          </div>
        </section>
      ) : null}

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

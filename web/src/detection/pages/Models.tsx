import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import type { ModelDrift, ModelInfo, ModelVersionInfo } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'
import { formatTime } from '../utils/format'

export function Models() {
  const { id } = useParams()
  const [rows, setRows] = useState<ModelInfo[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [drift, setDrift] = useState<ModelDrift | null>(null)
  const [versions, setVersions] = useState<ModelVersionInfo[]>([])
  const [detailError, setDetailError] = useState<string | null>(null)
  const [promoting, setPromoting] = useState<string | null>(null)
  const [training, setTraining] = useState(false)
  const [jobMsg, setJobMsg] = useState<string | null>(null)

  async function refreshModels() {
    const data = await api.listModels()
    setRows(data)
  }

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const data = await api.listModels()
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

  // Findings link here by model name, so accept either the id or the name.
  const matched = id
    ? (rows.find((r) => r.model_id === id) ?? rows.find((r) => r.name === id) ?? null)
    : null
  const notFound = Boolean(id) && !loading && !matched
  const selected = matched ?? (id ? null : (rows[0] ?? null))

  const selectedModelId = selected?.model_id
  useEffect(() => {
    if (!selectedModelId) return
    let cancelled = false
    setDetailError(null)
    setDrift(null)
    Promise.all([api.getModelDrift(selectedModelId), api.listModelVersions(selectedModelId)])
      .then(([nextDrift, nextVersions]) => {
        if (!cancelled) {
          setDrift(nextDrift)
          setVersions(nextVersions)
        }
      })
      .catch((err) => {
        if (!cancelled) setDetailError(err instanceof Error ? err.message : String(err))
      })
    return () => {
      cancelled = true
    }
  }, [selectedModelId])

  async function promote(version: string) {
    if (!selected) return
    setPromoting(version)
    setDetailError(null)
    try {
      await api.promoteModelVersion(selected.model_id, version, 'champion')
      setVersions(await api.listModelVersions(selected.model_id))
      await refreshModels()
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : String(err))
    } finally {
      setPromoting(null)
    }
  }

  async function rollback(version: string) {
    if (!selected) return
    setPromoting(version)
    setDetailError(null)
    try {
      await api.rollbackModelVersion(selected.model_id, version)
      setVersions(await api.listModelVersions(selected.model_id))
      await refreshModels()
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : String(err))
    } finally {
      setPromoting(null)
    }
  }

  async function startTraining() {
    if (!selected) return
    setTraining(true)
    setJobMsg(null)
    setDetailError(null)
    try {
      const job = await api.startTrainingJob(selected.model_id, { run_async: true })
      setJobMsg(`Started job ${job.job_id} (${job.status})`)
      let status = job.status
      let version = job.version
      let attempts = 0
      while (
        status !== 'completed' &&
        status !== 'failed' &&
        status !== 'error' &&
        attempts < 30
      ) {
        await new Promise((r) => setTimeout(r, 1000))
        const next = await api.getTrainingJob(job.job_id)
        status = next.status
        version = next.version
        setJobMsg(`Job ${job.job_id}: ${status}${version ? ` → v${version}` : ''}`)
        attempts += 1
      }
      setVersions(await api.listModelVersions(selected.model_id))
      await refreshModels()
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : String(err))
    } finally {
      setTraining(false)
    }
  }

  if (loading) return <div className="loading">Loading models…</div>
  if (error) return <div className="error">{error}</div>

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>Models</h1>
          <p>Inference models — train, promote, rollback, and inspect drift.</p>
        </div>
      </header>

      <div className="list-detail">
        <div className="panel" style={{ padding: 0 }}>
          {rows.map((row) => (
            <Link
              key={row.model_id}
              to={`/models/${row.model_id}`}
              className={`list-item${selected?.model_id === row.model_id ? ' active' : ''}`}
            >
              <strong>{row.name}</strong>
              <div className="muted">
                <StatusBadge value={row.status} kind="health" /> {row.modality} · v{row.version}
              </div>
            </Link>
          ))}
        </div>

        <div className="panel">
          {notFound ? (
            <div className="empty">
              Model <span className="mono">{id}</span> was not found.{' '}
              <Link to="/models">Back to all models</Link>
            </div>
          ) : selected ? (
            <>
              <div className="toolbar" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
                <h2 style={{ margin: 0 }}>{selected.name}</h2>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={training}
                  onClick={() => void startTraining()}
                >
                  {training ? 'Training…' : 'Start training'}
                </button>
              </div>
              {jobMsg ? <p className="muted mono">{jobMsg}</p> : null}
              <dl className="kv">
                <dt>ID</dt>
                <dd className="mono">{selected.model_id}</dd>
                <dt>Modality</dt>
                <dd>{selected.modality}</dd>
                <dt>Version</dt>
                <dd className="mono">{selected.version}</dd>
                <dt>Status</dt>
                <dd>
                  <StatusBadge value={selected.status} kind="health" />
                </dd>
                <dt>Last inference</dt>
                <dd className="mono">{formatTime(selected.last_inference)}</dd>
                <dt>Findings 24h</dt>
                <dd>{selected.findings_24h}</dd>
                <dt>Avg latency</dt>
                <dd>{selected.avg_latency_ms} ms</dd>
              </dl>
              <Link className="btn" to="/findings">
                Browse findings
              </Link>
              <h3>Drift</h3>
              {detailError ? <div className="error">{detailError}</div> : null}
              {drift ? (
                <dl className="kv">
                  <dt>Overall score</dt>
                  <dd>{drift.overall_score.toFixed(3)}</dd>
                  <dt>Recommendation</dt>
                  <dd>{drift.recommendation}</dd>
                  <dt>Computed</dt>
                  <dd>{formatTime(drift.computed_at)}</dd>
                </dl>
              ) : !detailError ? (
                <div className="loading">Loading drift…</div>
              ) : null}
              <h3>Version and promotion history</h3>
              {versions.length === 0 ? (
                <div className="empty">No persisted model versions.</div>
              ) : (
                <table className="data">
                  <thead>
                    <tr>
                      <th>Version</th>
                      <th>Aliases</th>
                      <th>Created</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {versions.map((version) => (
                      <tr key={version.version}>
                        <td className="mono">{version.version}</td>
                        <td>{version.aliases.join(', ') || '—'}</td>
                        <td>{formatTime(version.created_at)}</td>
                        <td className="toolbar">
                          <button
                            type="button"
                            className="btn"
                            disabled={
                              promoting === version.version ||
                              version.aliases.includes('champion')
                            }
                            onClick={() => void promote(version.version)}
                          >
                            {promoting === version.version ? 'Working…' : 'Promote champion'}
                          </button>
                          {version.aliases.includes('champion') ? (
                            <button
                              type="button"
                              className="btn"
                              disabled={promoting === version.version}
                              onClick={() => void rollback(version.version)}
                            >
                              Rollback
                            </button>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          ) : (
            <div className="empty">Select a model.</div>
          )}
        </div>
      </div>
    </div>
  )
}

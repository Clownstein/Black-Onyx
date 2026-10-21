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
  const [datasetPath, setDatasetPath] = useState('')
  const [datasetReviewed, setDatasetReviewed] = useState(false)
  const [activeJobId, setActiveJobId] = useState<string | null>(null)

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
    setActiveJobId(null)
    setJobMsg(null)
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

  useEffect(() => {
    if (!selectedModelId) return
    let cancelled = false
    api.listTrainingJobs(selectedModelId)
      .then((jobs) => {
        if (cancelled) return
        const active = jobs.find((job) => !['completed', 'succeeded', 'failed', 'error', 'cancelled'].includes(job.status))
        setActiveJobId(active?.job_id ?? null)
        if (active) setJobMsg(`Resuming job ${active.job_id}: ${active.status}`)
      })
      .catch((err) => {
        if (!cancelled) setDetailError(err instanceof Error ? err.message : String(err))
      })
    return () => { cancelled = true }
  }, [selectedModelId])

  useEffect(() => {
    if (!activeJobId || !selectedModelId) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const poll = async () => {
      try {
        const job = await api.getTrainingJob(activeJobId)
        if (cancelled) return
        setJobMsg(`Job ${job.job_id}: ${job.status}${job.version ? ` → v${job.version}` : ''}`)
        if (['completed', 'succeeded', 'failed', 'error', 'cancelled'].includes(job.status)) {
          setActiveJobId(null)
          if (job.failure_reason) setDetailError(job.failure_reason)
          const [nextVersions, nextModels] = await Promise.all([
            api.listModelVersions(selectedModelId), api.listModels(),
          ])
          if (!cancelled) {
            setVersions(nextVersions)
            setRows(nextModels)
          }
          return
        }
      } catch (err) {
        if (!cancelled) setDetailError(err instanceof Error ? err.message : String(err))
      }
      if (!cancelled) timer = setTimeout(() => void poll(), 2000)
    }
    void poll()
    return () => { cancelled = true; if (timer) clearTimeout(timer) }
  }, [activeJobId, selectedModelId])

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
      const job = await api.startTrainingJob(selected.model_id, {
        dataset_path: datasetPath.trim(),
        dataset_reviewed: datasetReviewed,
        run_async: true,
      })
      setJobMsg(`Started job ${job.job_id} (${job.status})`)
      if (!['completed', 'succeeded', 'failed', 'error', 'cancelled'].includes(job.status)) {
        setActiveJobId(job.job_id)
      }
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
                  disabled={training || Boolean(activeJobId) || !selected.trainable || !datasetPath.trim() || !datasetReviewed}
                  onClick={() => void startTraining()}
                >
                  {training || activeJobId ? 'Training…' : 'Start training'}
                </button>
              </div>
              {selected.trainable ? (
                <label>
                  Reviewed dataset path
                  <input
                    value={datasetPath}
                    onChange={(event) => setDatasetPath(event.target.value)}
                    placeholder="/datasets/reviewed/model-input.jsonl"
                  />
                  <span>
                    <input
                      type="checkbox"
                      checked={datasetReviewed}
                      onChange={(event) => setDatasetReviewed(event.target.checked)}
                    />{' '}
                    I confirm this dataset was reviewed for production training.
                  </span>
                </label>
              ) : (
                <p className="muted">{selected.capability_reason || 'This model is inference-only.'}</p>
              )}
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
                <dt>Training</dt>
                <dd>{selected.trainable ? 'Supported with a reviewed dataset' : 'Inference-only'}</dd>
                <dt>Artifact state</dt>
                <dd>{selected.artifact_state}</dd>
                <dt>Last inference</dt>
                <dd className="mono">{selected.last_inference ? formatTime(selected.last_inference) : 'Not reported'}</dd>
                <dt>Findings 24h</dt>
                <dd>{selected.findings_24h == null ? 'Not reported' : selected.findings_24h}</dd>
                <dt>Avg latency</dt>
                <dd>{selected.avg_latency_ms == null ? 'Not reported' : `${selected.avg_latency_ms} ms`}</dd>
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

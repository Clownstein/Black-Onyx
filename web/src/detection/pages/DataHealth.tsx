import { useEffect, useRef, useState } from 'react'
import { api } from '../api/client'
import type { DataHealthSource, ThreatIntelFeedHealth } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'
import { formatTime } from '../utils/format'

function feedStatusKind(status: string): 'ok' | 'lagging' | 'stale' | 'error' {
  const s = status.toLowerCase()
  if (s === 'ok' || s === 'success' || s === 'ready') return 'ok'
  if (s === 'skipped' || s === 'disabled') return 'stale'
  if (s === 'degraded' || s === 'partial') return 'lagging'
  return 'error'
}

export function DataHealth() {
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])
  const [rows, setRows] = useState<DataHealthSource[]>([])
  const [feeds, setFeeds] = useState<ThreatIntelFeedHealth[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [actionMsg, setActionMsg] = useState<string | null>(null)
  const [stixText, setStixText] = useState('{\n  "type": "bundle",\n  "id": "bundle--example",\n  "objects": []\n}')

  async function refresh() {
    const [data, feedRows] = await Promise.all([
      api.listDataHealth(),
      api.listThreatIntelFeeds().catch(() => [] as ThreatIntelFeedHealth[]),
    ])
    if (!mounted.current) return
    setRows(data)
    setFeeds(feedRows)
    setSelectedId((cur) => cur ?? data[0]?.source_id ?? null)
  }

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        await refresh()
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

  const selected = rows.find((r) => r.source_id === selectedId) ?? null

  async function syncFeed(feed: 'kev' | 'taxii' | 'misp') {
    setBusy(true)
    setActionMsg(null)
    setError(null)
    try {
      const result = await api.syncThreatIntelFeed(feed)
      setActionMsg(`${feed.toUpperCase()} sync: ${JSON.stringify(result)}`)
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function uploadStix() {
    setBusy(true)
    setActionMsg(null)
    setError(null)
    try {
      const bundle = JSON.parse(stixText) as Record<string, unknown>
      const result = await api.uploadStixBundle(bundle)
      setActionMsg(`STIX upload: ${JSON.stringify(result)}`)
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <div className="loading">Loading data health…</div>
  if (error && rows.length === 0) return <div className="error">{error}</div>

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>Data Health</h1>
          <p>Ingestion lag, source throughput, and threat-intel feed sync status.</p>
        </div>
        <button type="button" className="btn" disabled={busy} onClick={() => void refresh()}>
          Refresh
        </button>
      </header>

      {error ? <div className="error">{error}</div> : null}
      {actionMsg ? <div className="panel muted mono">{actionMsg}</div> : null}

      <section className="grid grid-4" style={{ marginBottom: '1rem' }}>
        {rows.map((row) => (
          <button
            key={row.source_id}
            type="button"
            className="panel"
            style={{
              textAlign: 'left',
              cursor: 'pointer',
              borderColor: selectedId === row.source_id ? 'var(--accent)' : undefined,
            }}
            onClick={() => setSelectedId(row.source_id)}
          >
            <div className="muted mono" style={{ fontSize: '0.8rem' }}>
              {row.name}
            </div>
            <div className="stat-value">
              {row.lag_records == null ? 'unavailable' : row.lag_records.toLocaleString()}
            </div>
            <div className="stat-label">records behind</div>
            <div style={{ marginTop: '0.45rem' }}>
              <StatusBadge value={row.status} kind="health" />
            </div>
          </button>
        ))}
      </section>

      <div className="panel" style={{ marginBottom: '1rem' }}>
        {selected ? (
          <>
            <h2>{selected.name}</h2>
            <dl className="kv">
              <dt>Source ID</dt>
              <dd className="mono">{selected.source_id}</dd>
              <dt>Modality</dt>
              <dd>{selected.modality}</dd>
              <dt>Lag</dt>
              <dd>
                {selected.lag_records == null
                  ? 'Telemetry unavailable'
                  : `${selected.lag_records.toLocaleString()} records`}
              </dd>
              <dt>Throughput</dt>
              <dd>
                {selected.events_per_min == null
                  ? 'Telemetry unavailable'
                  : `${selected.events_per_min.toLocaleString()} events/min`}
              </dd>
              <dt>Status</dt>
              <dd>
                <StatusBadge value={selected.status} kind="health" />
              </dd>
              <dt>Last event</dt>
              <dd className="mono">
                {selected.last_event ? formatTime(selected.last_event) : 'Telemetry unavailable'}
              </dd>
              {selected.reason ? (
                <>
                  <dt>Dependency</dt>
                  <dd>{selected.reason}</dd>
                </>
              ) : null}
            </dl>
          </>
        ) : (
          <div className="empty">No sources.</div>
        )}
      </div>

      <section className="panel" style={{ marginBottom: '1rem' }}>
        <h2>Threat intel feeds</h2>
        <div className="toolbar" style={{ flexWrap: 'wrap', marginBottom: '0.75rem' }}>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void syncFeed('kev')}>
            Sync KEV
          </button>
          <button type="button" className="btn" disabled={busy} onClick={() => void syncFeed('taxii')}>
            Sync TAXII
          </button>
          <button type="button" className="btn" disabled={busy} onClick={() => void syncFeed('misp')}>
            Sync MISP
          </button>
        </div>
        {feeds.length === 0 ? (
          <div className="empty">No feed health rows (service offline or key missing).</div>
        ) : (
          <table className="table data">
            <thead>
              <tr>
                <th>Feed</th>
                <th>Status</th>
                <th>Indicators</th>
                <th>Last sync</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {feeds.map((f) => (
                <tr key={f.feed_name}>
                  <td className="mono">{f.feed_name}</td>
                  <td>
                    <StatusBadge value={feedStatusKind(f.last_status)} kind="health" />
                  </td>
                  <td className="mono">{f.indicator_count}</td>
                  <td className="mono">
                    {f.last_sync_at ? formatTime(f.last_sync_at) : '—'}
                  </td>
                  <td className="muted">{f.last_error ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <h2>Upload STIX bundle</h2>
        <textarea
          className="mono"
          rows={8}
          aria-label="STIX JSON"
          value={stixText}
          onChange={(e) => setStixText(e.target.value)}
          style={{ width: '100%' }}
        />
        <button
          type="button"
          className="btn btn-primary"
          style={{ marginTop: '0.75rem' }}
          disabled={busy}
          onClick={() => void uploadStix()}
        >
          Upload STIX
        </button>
      </section>
    </div>
  )
}

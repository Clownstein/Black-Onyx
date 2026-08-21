import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { api, type HuntHit } from '../api/client'
import type { FederatedHuntHit, SavedHunt, VectorHuntHit } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'

type HuntMode = 'opensearch' | 'federated' | 'vector'

export function Hunt() {
  const [q, setQ] = useState('')
  const [mode, setMode] = useState<HuntMode>('opensearch')
  const [hits, setHits] = useState<HuntHit[]>([])
  const [fedHits, setFedHits] = useState<FederatedHuntHit[]>([])
  const [vectorHits, setVectorHits] = useState<VectorHuntHit[]>([])
  const [warnings, setWarnings] = useState<string[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [searched, setSearched] = useState(false)
  const [savedHunts, setSavedHunts] = useState<SavedHunt[]>([])
  const [saveName, setSaveName] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    let cancelled = false
    api
      .listSavedHunts()
      .then((items) => {
        if (!cancelled) setSavedHunts(items)
      })
      .catch((err) => {
        if (!cancelled && !api.useMock) setError(err instanceof Error ? err.message : String(err))
      })
    return () => {
      cancelled = true
    }
  }, [])

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setSearched(true)
    setWarnings([])
    try {
      if (mode === 'federated') {
        const result = await api.federatedHunt(q)
        setFedHits(result.hits)
        setWarnings(result.warnings)
        setHits([])
        setVectorHits([])
        setTotal(result.hits.length)
      } else if (mode === 'vector') {
        const result = await api.huntVector(q)
        setVectorHits(result.hits)
        setHits([])
        setFedHits([])
        setTotal(result.hits.length)
        if (result.status && result.status !== 'ready') {
          setWarnings([
            `${result.capability ?? 'vector_search'} ${result.status}${
              result.reason ? `: ${result.reason}` : ''
            }`,
          ])
        }
      } else {
        const result = await api.huntSearch(q)
        setHits(result.hits)
        setFedHits([])
        setVectorHits([])
        setTotal(result.total)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setHits([])
      setFedHits([])
      setVectorHits([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }

  async function saveCurrentHunt() {
    if (!q.trim() || !saveName.trim()) return
    setSaving(true)
    setError(null)
    try {
      const saved = await api.saveHunt({
        name: saveName.trim(),
        query: q.trim(),
        query_type: mode,
        filters: {},
      })
      setSavedHunts((items) => [saved, ...items.filter((item) => item.hunt_id !== saved.hunt_id)])
      setSaveName('')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  function modeFromSaved(queryType: string): HuntMode {
    if (queryType === 'federated') return 'federated'
    if (queryType === 'vector') return 'vector'
    return 'opensearch'
  }

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>Hunt</h1>
          <p className="muted">
            OpenSearch, federated, and vector hunt across detection evidence. For TIP semantic search
            over indexed knowledge, use <Link to="/search">Search</Link>.
          </p>
        </div>
        <Link className="btn btn-secondary" to="/search">
          Semantic search
        </Link>
      </header>

      <form className="toolbar" onSubmit={onSubmit}>
        <input
          aria-label="Hunt query"
          placeholder="Search title, asset, technique…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ minWidth: '16rem', flex: 1 }}
        />
        <select
          aria-label="Hunt mode"
          value={mode}
          onChange={(e) => setMode(e.target.value as HuntMode)}
        >
          <option value="opensearch">OpenSearch</option>
          <option value="federated">Federated</option>
          <option value="vector">Vector</option>
        </select>
        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? 'Searching…' : 'Search'}
        </button>
      </form>

      <div className="toolbar">
        <select
          aria-label="Saved hunts"
          value=""
          onChange={(e) => {
            const saved = savedHunts.find((item) => item.hunt_id === e.target.value)
            if (!saved) return
            setQ(saved.query)
            setMode(modeFromSaved(saved.query_type))
          }}
        >
          <option value="">Load saved hunt…</option>
          {savedHunts.map((item) => (
            <option key={item.hunt_id} value={item.hunt_id}>
              {item.name}
            </option>
          ))}
        </select>
        <input
          aria-label="Saved hunt name"
          placeholder="Name this hunt"
          value={saveName}
          onChange={(e) => setSaveName(e.target.value)}
        />
        <button
          type="button"
          className="btn"
          disabled={saving || !q.trim() || !saveName.trim()}
          onClick={() => void saveCurrentHunt()}
        >
          {saving ? 'Saving…' : 'Save hunt'}
        </button>
      </div>

      {error ? <div className="error">{error}</div> : null}
      {warnings.length ? (
        <div className="muted">Partial results: {warnings.join('; ')}</div>
      ) : null}

      {!searched ? (
        <div className="empty">Enter a query to hunt across indexed findings and incidents.</div>
      ) : loading ? (
        <div className="loading">Searching…</div>
      ) : mode === 'federated' ? (
        fedHits.length === 0 ? (
          <div className="empty">No federated hits for this query.</div>
        ) : (
          <>
            <p className="muted">
              {total} result{total === 1 ? '' : 's'}
            </p>
            <table className="table data">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Title</th>
                  <th>Score</th>
                  <th>Id</th>
                </tr>
              </thead>
              <tbody>
                {fedHits.map((h) => (
                  <tr key={`${h.source}-${h.id}`}>
                    <td className="mono">{h.source}</td>
                    <td>
                      {h.title}
                      {h.summary ? (
                        <div className="muted" style={{ fontSize: '0.85rem' }}>
                          {h.summary}
                        </div>
                      ) : null}
                    </td>
                    <td className="mono">{h.score.toFixed(2)}</td>
                    <td className="mono muted">{h.id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )
      ) : mode === 'vector' ? (
        vectorHits.length === 0 ? (
          <div className="empty">No vector hits for this query.</div>
        ) : (
          <>
            <p className="muted">
              {total} result{total === 1 ? '' : 's'}
            </p>
            <table className="table data">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Title</th>
                  <th>Score</th>
                  <th>Id</th>
                </tr>
              </thead>
              <tbody>
                {vectorHits.map((h) => (
                  <tr key={`${h.source}-${h.id}`}>
                    <td className="mono">{h.source}</td>
                    <td>
                      <Link to={`/findings/${h.id}`}>{h.title}</Link>
                      {h.summary ? (
                        <div className="muted" style={{ fontSize: '0.85rem' }}>
                          {h.summary}
                        </div>
                      ) : null}
                    </td>
                    <td className="mono">{h.score.toFixed(2)}</td>
                    <td className="mono muted">{h.id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )
      ) : hits.length === 0 ? (
        <div className="empty">No hits for this query.</div>
      ) : (
        <>
          <p className="muted">
            {total} result{total === 1 ? '' : 's'}
          </p>
          <table className="table data">
            <thead>
              <tr>
                <th>Type</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Id</th>
              </tr>
            </thead>
            <tbody>
              {hits.map((h) => (
                <tr key={`${h.doc_type}-${h.id}`}>
                  <td className="mono">{h.doc_type}</td>
                  <td>
                    {h.doc_type === 'incident' ? (
                      <Link to={`/incidents/${h.id}`}>{h.title}</Link>
                    ) : (
                      <Link to={`/findings/${h.id}`}>{h.title}</Link>
                    )}
                    {h.summary ? (
                      <div className="muted" style={{ fontSize: '0.85rem' }}>
                        {h.summary}
                      </div>
                    ) : null}
                  </td>
                  <td>{h.severity ? <StatusBadge value={h.severity} kind="severity" /> : '—'}</td>
                  <td className="mono muted">{h.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}

import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import type { Asset, AssetBaseline, AssetTopology } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'
import { formatTime } from '../utils/format'
import { useAsyncData } from '../utils/useAsyncData'

type AssetBundle = {
  asset: Asset
  topology: AssetTopology
  baseline: AssetBaseline
}

export function AssetDetail() {
  const { id = '' } = useParams()
  const { data, loading, error } = useAsyncData<AssetBundle>(async () => {
    const [asset, topology, baseline] = await Promise.all([
      api.getAsset(id),
      api.getAssetTopology(id),
      api.getAssetBaseline(id),
    ])
    return { asset, topology, baseline }
  }, [id])

  if (!id) {
    return <div className="error">Missing asset id</div>
  }
  if (loading) {
    return <div className="loading">Loading asset…</div>
  }
  if (error || !data) {
    return (
      <div>
        <div className="error">{error ?? 'Asset not found'}</div>
        <Link className="btn btn-secondary" to="/assets">
          Back to assets
        </Link>
      </div>
    )
  }

  const { asset, topology, baseline } = data
  const stats = baseline.stats

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>{asset.name}</h1>
          <p className="muted mono">{asset.asset_id}</p>
        </div>
        <Link className="btn btn-secondary" to="/assets">
          All assets
        </Link>
      </header>

      <div className="list-detail">
        <section className="panel">
          <h2>Asset</h2>
          <dl className="kv">
            <dt>Status</dt>
            <dd>
              <StatusBadge value={asset.status} kind="health" />
            </dd>
            <dt>Kind</dt>
            <dd>{asset.kind}</dd>
            <dt>Environment</dt>
            <dd>{asset.environment}</dd>
            <dt>Owner</dt>
            <dd>{asset.owner}</dd>
            <dt>Last seen</dt>
            <dd>{formatTime(asset.last_seen)}</dd>
            <dt>Services</dt>
            <dd>
              {asset.services.length
                ? asset.services.map((service, i) => (
                    <span key={service}>
                      {i > 0 ? ', ' : ''}
                      <Link to="/detection-services">{service}</Link>
                    </span>
                  ))
                : '—'}
            </dd>
          </dl>
        </section>

        <section className="panel">
          <h2>Baseline ({baseline.window_days}d)</h2>
          {stats.status && stats.status !== 'ready' ? (
            <p className="muted">
              {stats.capability ?? 'baseline'}: {stats.status}
              {stats.reason ? ` — ${stats.reason}` : ''}
            </p>
          ) : null}
          <dl className="kv">
            <dt>Samples</dt>
            <dd className="mono">{stats.sample_count}</dd>
            <dt>Mean score</dt>
            <dd className="mono">{stats.mean_score != null ? stats.mean_score.toFixed(3) : '—'}</dd>
            <dt>P95 score</dt>
            <dd className="mono">{stats.p95_score != null ? stats.p95_score.toFixed(3) : '—'}</dd>
          </dl>
        </section>
      </div>

      <section className="panel">
        <h2>Topology</h2>
        {topology.nodes.length === 0 ? (
          <div className="empty">No topology nodes for this asset.</div>
        ) : (
          <table className="table data">
            <thead>
              <tr>
                <th>Id</th>
                <th>Kind</th>
                <th>Label</th>
              </tr>
            </thead>
            <tbody>
              {topology.nodes.map((node) => (
                <tr key={node.id}>
                  <td className="mono">{node.id}</td>
                  <td>{node.kind}</td>
                  <td>{node.label ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {topology.edges.length > 0 ? (
          <>
            <h3>Edges</h3>
            <table className="table data">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Relation</th>
                  <th>Target</th>
                </tr>
              </thead>
              <tbody>
                {topology.edges.map((edge, i) => (
                  <tr key={`${edge.source}-${edge.relation}-${edge.target}-${i}`}>
                    <td className="mono">{edge.source}</td>
                    <td>{edge.relation}</td>
                    <td className="mono">{edge.target}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        ) : null}
      </section>
    </div>
  )
}

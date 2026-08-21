import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { EvidenceItem, Finding, Incident } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'

type NetworkRow = {
  id: string
  title: string
  service: string
  severity: string
  risk_score: number
  incident_id: string | null
  summary: string
  peer: string | null
  source: 'flow' | 'suricata' | 'other'
  beaconInterval?: number | null
  communityId?: string | null
}

type GraphNode = { id: string; label: string; kind: 'asset' | 'peer' | 'alert' }
type GraphEdge = { from: string; to: string; weight: number }

function peerFromEvidence(ev: EvidenceItem | undefined): string | null {
  if (!ev?.raw) return null
  if (typeof ev.raw.dst === 'string') return ev.raw.dst
  if (typeof ev.raw.dest_ip === 'string') return ev.raw.dest_ip
  if (typeof ev.raw.signature === 'string') return ev.raw.signature
  const peers = ev.raw.peers
  if (Array.isArray(peers) && peers[0] && typeof peers[0] === 'object') {
    const first = peers[0] as { peer?: string }
    return first.peer ?? null
  }
  return null
}

function sourceFromFinding(f: Finding, ev?: EvidenceItem): NetworkRow['source'] {
  const blob = `${f.title} ${f.summary} ${f.model} ${JSON.stringify(ev?.raw ?? {})}`.toLowerCase()
  if (blob.includes('suricata') || blob.includes('sid ') || blob.includes('signature_id')) {
    return 'suricata'
  }
  if (f.kind === 'network' || blob.includes('flow') || blob.includes('beacon')) {
    return 'flow'
  }
  return 'other'
}

function beaconIntervalFromRaw(raw: Record<string, unknown> | undefined): number | null {
  if (!raw) return null
  const direct = raw.beacon_interval_s ?? raw.interval_seconds ?? raw.iat_mean
  if (typeof direct === 'number' && Number.isFinite(direct)) return direct
  const detections = raw.detections
  if (Array.isArray(detections)) {
    for (const d of detections) {
      if (d && typeof d === 'object') {
        const ev = (d as { evidence?: Record<string, unknown> }).evidence
        const iv = ev?.interval_seconds ?? ev?.beacon_interval_s
        if (typeof iv === 'number') return iv
      }
    }
  }
  return null
}

function layoutGraph(nodes: GraphNode[], width: number, height: number): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>()
  const assets = nodes.filter((n) => n.kind === 'asset')
  const peers = nodes.filter((n) => n.kind !== 'asset')
  assets.forEach((n, i) => {
    const y = assets.length <= 1 ? height / 2 : 40 + (i * (height - 80)) / Math.max(1, assets.length - 1)
    positions.set(n.id, { x: 80, y })
  })
  peers.forEach((n, i) => {
    const angle = peers.length <= 1 ? 0 : (i / peers.length) * Math.PI * 1.6 - Math.PI * 0.8
    const cx = width - 120
    const cy = height / 2
    const rx = 90
    const ry = Math.min(140, height / 2 - 30)
    positions.set(n.id, { x: cx + Math.cos(angle) * rx * 0.2, y: cy + Math.sin(angle) * ry })
  })
  return positions
}

function PeerSessionGraph({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const width = 520
  const height = 260
  const pos = useMemo(() => layoutGraph(nodes, width, height), [nodes])
  if (nodes.length === 0) {
    return <div className="empty">No peer/session edges yet.</div>
  }
  return (
    <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} role="img" aria-label="Peer session graph">
      {edges.map((e, i) => {
        const a = pos.get(e.from)
        const b = pos.get(e.to)
        if (!a || !b) return null
        return (
          <line
            key={`e-${i}`}
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            stroke="var(--border, #889)"
            strokeWidth={Math.min(4, 1 + e.weight)}
            opacity={0.7}
          />
        )
      })}
      {nodes.map((n) => {
        const p = pos.get(n.id)
        if (!p) return null
        const fill =
          n.kind === 'asset' ? 'var(--accent, #3b82f6)' : n.kind === 'alert' ? 'var(--critical, #dc2626)' : 'var(--muted, #94a3b8)'
        return (
          <g key={n.id}>
            <circle cx={p.x} cy={p.y} r={n.kind === 'asset' ? 14 : 10} fill={fill} />
            <text x={p.x} y={p.y + 28} textAnchor="middle" fontSize={11} fill="currentColor">
              {n.label.length > 22 ? `${n.label.slice(0, 20)}…` : n.label}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

function BeaconScatter({ points }: { points: { x: number; y: number; label: string }[] }) {
  const width = 520
  const height = 200
  if (points.length === 0) {
    return <div className="muted">No beacon-interval detections in current findings.</div>
  }
  const maxX = Math.max(...points.map((p) => p.x), 1)
  const maxY = Math.max(...points.map((p) => p.y), 1)
  return (
    <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} role="img" aria-label="Beacon scatter">
      <line x1={40} y1={height - 30} x2={width - 20} y2={height - 30} stroke="currentColor" opacity={0.4} />
      <line x1={40} y1={20} x2={40} y2={height - 30} stroke="currentColor" opacity={0.4} />
      <text x={width / 2} y={height - 8} textAnchor="middle" fontSize={11} fill="currentColor">
        Interval (s)
      </text>
      <text x={14} y={height / 2} textAnchor="middle" fontSize={11} fill="currentColor" transform={`rotate(-90 14 ${height / 2})`}>
        Risk
      </text>
      {points.map((p, i) => {
        const x = 40 + (p.x / maxX) * (width - 70)
        const y = height - 30 - (p.y / maxY) * (height - 60)
        return <circle key={i} cx={x} cy={y} r={5} fill="var(--accent, #3b82f6)" opacity={0.85}>
          <title>{`${p.label}: ${p.x.toFixed(1)}s / risk ${p.y.toFixed(2)}`}</title>
        </circle>
      })}
    </svg>
  )
}

export function Network() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [incs, finds] = await Promise.all([api.listIncidents(), api.listFindings()])
        if (!cancelled) {
          setIncidents(incs)
          setFindings(finds)
        }
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

  const rows = useMemo(() => {
    const fromFindings: NetworkRow[] = findings
      .filter((f) => f.kind === 'network' || f.model.toLowerCase().includes('suricata') || f.model.toLowerCase().includes('network'))
      .map((f) => {
        const inc = incidents.find((i) => i.incident_id === f.incident_id)
        // Match evidence to this specific finding; a lone item is unambiguous,
        // but never borrow another finding's evidence when several exist.
        const kindEvidence = inc?.evidence.filter((e) => e.kind === 'network') ?? []
        const ev =
          kindEvidence.find((e) => e.raw?.finding_id === f.finding_id) ??
          (kindEvidence.length === 1 ? kindEvidence[0] : undefined)
        const raw = ev?.raw as Record<string, unknown> | undefined
        return {
          id: f.finding_id,
          title: f.title,
          service: f.service,
          severity: f.severity,
          risk_score: f.risk_score,
          incident_id: f.incident_id,
          summary: f.summary,
          peer: peerFromEvidence(ev),
          source: sourceFromFinding(f, ev),
          beaconInterval: beaconIntervalFromRaw(raw),
          communityId:
            typeof raw?.community_id === 'string'
              ? raw.community_id
              : typeof raw?.zeek_uid === 'string'
                ? raw.zeek_uid
                : null,
        }
      })
    if (fromFindings.length > 0) return fromFindings
    return incidents.flatMap((inc) =>
      inc.evidence
        .filter((e) => e.kind === 'network')
        .map((e, idx) => {
          const raw = e.raw as Record<string, unknown> | undefined
          const title = e.title
          const source: NetworkRow['source'] =
            title.toLowerCase().includes('suricata') || String(raw?.signature_id || '').length > 0
              ? 'suricata'
              : 'flow'
          return {
            id: `${inc.incident_id}-net-${idx}`,
            title,
            service: inc.services[0] ?? 'unknown',
            severity: inc.severity,
            risk_score: e.score ?? inc.risk_score,
            incident_id: inc.incident_id,
            summary: e.detail,
            peer: peerFromEvidence(e),
            source,
            beaconInterval: beaconIntervalFromRaw(raw),
            communityId:
              typeof raw?.community_id === 'string'
                ? raw.community_id
                : typeof raw?.zeek_uid === 'string'
                  ? raw.zeek_uid
                  : null,
          }
        }),
    )
  }, [findings, incidents])

  const graph = useMemo(() => {
    const nodeMap = new Map<string, GraphNode>()
    const edgeMap = new Map<string, GraphEdge>()
    for (const row of rows) {
      const assetId = `asset:${row.service}`
      if (!nodeMap.has(assetId)) {
        nodeMap.set(assetId, { id: assetId, label: row.service, kind: 'asset' })
      }
      const peerLabel = row.peer ?? row.communityId ?? row.title
      const peerId = `peer:${peerLabel}`
      if (!nodeMap.has(peerId)) {
        nodeMap.set(peerId, {
          id: peerId,
          label: peerLabel,
          kind: row.source === 'suricata' ? 'alert' : 'peer',
        })
      }
      const ek = `${assetId}->${peerId}`
      const prev = edgeMap.get(ek)
      edgeMap.set(ek, { from: assetId, to: peerId, weight: (prev?.weight ?? 0) + 1 })
    }
    return { nodes: [...nodeMap.values()], edges: [...edgeMap.values()] }
  }, [rows])

  const beaconPoints = useMemo(
    () =>
      rows
        .filter((r) => typeof r.beaconInterval === 'number' && r.beaconInterval > 0)
        .map((r) => ({
          x: r.beaconInterval as number,
          y: r.risk_score,
          label: r.title,
        })),
    [rows],
  )

  const suricataTimeline = useMemo(() => {
    return rows
      .filter((r) => r.source === 'suricata' || r.source === 'flow')
      .slice(0, 12)
      .map((r) => ({
        id: r.id,
        label: r.source === 'suricata' ? `Suricata · ${r.title}` : `Flow · ${r.title}`,
        incident_id: r.incident_id,
        severity: r.severity,
      }))
  }, [rows])

  const active = rows.find((r) => r.id === selected) ?? rows[0] ?? null

  if (loading) return <div className="loading">Loading network findings…</div>
  if (error) return <div className="error">{error}</div>

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>Network</h1>
          <p>Flow and Suricata anomalies, peer graphs, and selective session context.</p>
        </div>
      </header>

      <div className="panel" style={{ marginBottom: '1rem' }}>
        <h2>Peer / session graph</h2>
        <PeerSessionGraph nodes={graph.nodes} edges={graph.edges} />
      </div>

      <div className="panel" style={{ marginBottom: '1rem' }}>
        <h2>Beacon scatter</h2>
        <BeaconScatter points={beaconPoints} />
      </div>

      <div className="panel" style={{ marginBottom: '1rem' }}>
        <h2>Incident timeline awareness</h2>
        <p className="muted">Suricata SID hits and flow findings linked to correlated incidents.</p>
        {suricataTimeline.length === 0 ? (
          <div className="empty">No Suricata/flow timeline entries.</div>
        ) : (
          <ul className="timeline">
            {suricataTimeline.map((item) => (
              <li key={item.id} className="timeline-item">
                <div className="timeline-body">
                  <StatusBadge value={item.severity} kind="severity" /> {item.label}
                  {item.incident_id ? (
                    <>
                      {' · '}
                      <Link to={`/incidents/${item.incident_id}`}>{item.incident_id}</Link>
                    </>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="list-detail">
        <div className="panel" style={{ padding: 0 }}>
          {rows.map((row) => (
            <button
              key={row.id}
              type="button"
              className={`list-item${active?.id === row.id ? ' active' : ''}`}
              onClick={() => setSelected(row.id)}
            >
              <strong>{row.title}</strong>
              <div className="muted">
                <StatusBadge value={row.severity} kind="severity" /> {row.service}
                {row.source === 'suricata' ? ' · Suricata' : row.source === 'flow' ? ' · Flow' : ''}
                {row.peer ? ` · ${row.peer}` : ''}
              </div>
            </button>
          ))}
          {rows.length === 0 ? <div className="empty">No network findings.</div> : null}
        </div>

        <div className="panel">
          {active ? (
            <>
              <h2>{active.title}</h2>
              <dl className="kv">
                <dt>Source</dt>
                <dd className="mono">{active.source}</dd>
                <dt>Peer</dt>
                <dd className="mono">{active.peer ?? '—'}</dd>
                <dt>Community / Zeek UID</dt>
                <dd className="mono">{active.communityId ?? '—'}</dd>
                <dt>Service</dt>
                <dd>
                  <Link to="/detection-services">{active.service}</Link>
                </dd>
                <dt>Risk</dt>
                <dd className="mono">{active.risk_score.toFixed(2)}</dd>
                <dt>Incident</dt>
                <dd>
                  {active.incident_id ? (
                    <Link to={`/incidents/${active.incident_id}`}>{active.incident_id}</Link>
                  ) : (
                    '—'
                  )}
                </dd>
              </dl>
              <p>{active.summary}</p>
            </>
          ) : (
            <div className="empty">Select a network finding.</div>
          )}
        </div>
      </div>
    </div>
  )
}

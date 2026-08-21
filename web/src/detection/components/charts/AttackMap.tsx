import { useMemo } from 'react'
import type { Incident } from '../../api/contracts'

type Node = {
  id: string
  label: string
  severity: string
  risk: number
  x: number
  y: number
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
}

/** Deterministic 0..1 hash so node positions are stable across renders. */
function hash01(input: string, salt: number): number {
  let h = 2166136261 ^ salt
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return ((h >>> 0) % 10_000) / 10_000
}

/**
 * Stylized attack-intelligence map: active incidents plotted as pulsing nodes
 * over a dot-grid field, with animated command-path arcs converging on the
 * highest-risk incident. Layout is deterministic, not geographic.
 */
export function AttackMap({ incidents }: { incidents: Incident[] }) {
  const width = 720
  const height = 340

  const nodes = useMemo<Node[]>(() => {
    const active = incidents
      .filter((i) => ['open', 'acknowledged', 'investigating'].includes(i.status))
      .slice(0, 12)
    return active.map((i) => ({
      id: i.incident_id,
      label: i.services[0] ?? i.assets[0] ?? i.incident_id,
      severity: i.severity,
      risk: i.risk_score,
      x: 70 + hash01(i.incident_id, 7) * (width - 150),
      y: 55 + hash01(i.incident_id, 31) * (height - 120),
    }))
  }, [incidents])

  const hub = useMemo(
    () => nodes.reduce<Node | null>((acc, n) => (acc == null || n.risk > acc.risk ? n : acc), null),
    [nodes],
  )

  if (nodes.length === 0) {
    return <div className="empty">No active incidents to map.</div>
  }

  const dots: Array<{ x: number; y: number }> = []
  for (let gx = 24; gx < width; gx += 32) {
    for (let gy = 24; gy < height; gy += 32) {
      if (hash01(`${gx}:${gy}`, 3) > 0.45) dots.push({ x: gx, y: gy })
    }
  }

  return (
    <div className="chart-frame">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Active incident attack map">
        {dots.map((d, i) => (
          <circle key={`d-${i}`} cx={d.x} cy={d.y} r={1.1} fill="var(--accent)" opacity={0.12} />
        ))}
        {hub
          ? nodes
              .filter((n) => n.id !== hub.id)
              .map((n) => {
                const mx = (n.x + hub.x) / 2
                const my = Math.min(n.y, hub.y) - 40
                return (
                  <path
                    key={`arc-${n.id}`}
                    className="attack-map-arc"
                    d={`M ${n.x} ${n.y} Q ${mx} ${my} ${hub.x} ${hub.y}`}
                    fill="none"
                    stroke={SEVERITY_COLOR[n.severity] ?? 'var(--accent)'}
                    strokeWidth={1}
                    opacity={0.4}
                  />
                )
              })
          : null}
        {nodes.map((n) => {
          const color = SEVERITY_COLOR[n.severity] ?? 'var(--accent)'
          const r = 5 + n.risk * 7
          return (
            <g key={n.id}>
              <circle className="attack-map-node" cx={n.x} cy={n.y} r={r} fill={color} opacity={0.85}>
                <title>{`${n.label} · ${n.severity} · risk ${n.risk.toFixed(2)}`}</title>
              </circle>
              <circle cx={n.x} cy={n.y} r={r + 6} fill="none" stroke={color} opacity={0.25} />
              <text
                x={n.x + r + 8}
                y={n.y + 3}
                fontSize={10}
                fill="var(--text-muted)"
                fontFamily="var(--mono)"
              >
                {n.label.length > 18 ? `${n.label.slice(0, 16)}…` : n.label}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

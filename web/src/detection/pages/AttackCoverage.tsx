import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/client'
import type { Incident } from '../api/contracts'
import { downloadBlob } from '../utils/download'

type Depth = 'none' | 'rules' | 'model' | 'correlated'

type CoverageRow = {
  technique: string
  name: string
  tactic: string
  depth: Depth
  detectors: string[]
  sightings: number
}

/** Detector catalog — merged with live incident MITRE tags. */
const DETECTOR_CATALOG: Omit<CoverageRow, 'sightings'>[] = [
  {
    technique: 'T1046',
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    depth: 'rules',
    detectors: ['port_scan_heuristic', 'failed_connection_burst'],
  },
  {
    technique: 'T1059.001',
    name: 'PowerShell',
    tactic: 'Execution',
    depth: 'rules',
    detectors: ['suspicious_parent_child', 'sigma:proc_powershell_encoded'],
  },
  {
    technique: 'T1053.005',
    name: 'Scheduled Task',
    tactic: 'Persistence',
    depth: 'rules',
    detectors: ['sigma:rare_scheduled_task'],
  },
  {
    technique: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    depth: 'model',
    detectors: [
      'new_external_peer',
      'beaconing_heuristic',
      'cross_host_external_ip',
      'network-model',
    ],
  },
  {
    technique: 'T1102',
    name: 'Web Service',
    tactic: 'Command and Control',
    depth: 'rules',
    detectors: ['cross_host_external_ip'],
  },
  {
    technique: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    depth: 'rules',
    detectors: ['sigma:failed_logon_burst'],
  },
  {
    technique: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    depth: 'rules',
    detectors: ['deny_spike', 'vuln_ingest'],
  },
  {
    technique: 'T1547',
    name: 'Boot or Logon Autostart Execution',
    tactic: 'Persistence',
    depth: 'rules',
    detectors: ['rare_binary_path'],
  },
  {
    technique: 'T1562',
    name: 'Impair Defenses',
    tactic: 'Defense Evasion',
    depth: 'rules',
    detectors: ['rule_change_outside_window'],
  },
  {
    technique: 'T1573',
    name: 'Encrypted Channel',
    tactic: 'Command and Control',
    depth: 'rules',
    detectors: ['beaconing_heuristic'],
  },
  {
    technique: 'T1049',
    name: 'System Network Connections Discovery',
    tactic: 'Discovery',
    depth: 'rules',
    detectors: ['new_listening_port'],
  },
  {
    technique: 'T1021',
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    depth: 'correlated',
    detectors: ['correlation-engine (multi-modality)'],
  },
  {
    technique: 'T1048',
    name: 'Exfiltration Over Alternative Protocol',
    tactic: 'Exfiltration',
    depth: 'model',
    detectors: ['threat-intel match', 'network-model'],
  },
]

const DEPTH_ORDER: Depth[] = ['none', 'rules', 'model', 'correlated']

function depthClass(depth: Depth): string {
  return `attack-depth attack-depth-${depth}`
}

function depthLabel(depth: Depth): string {
  switch (depth) {
    case 'none':
      return 'None'
    case 'rules':
      return 'Rules'
    case 'model':
      return 'Model'
    case 'correlated':
      return 'Correlated'
  }
}

function collectTechniquesFromIncidents(incidents: Incident[]): Map<string, number> {
  const counts = new Map<string, number>()
  const bump = (raw: unknown) => {
    if (typeof raw !== 'string') return
    const id = raw.trim().toUpperCase()
    if (!/^T\d{4}/.test(id)) return
    counts.set(id, (counts.get(id) ?? 0) + 1)
  }
  for (const inc of incidents) {
    const ctx = inc.context ?? {}
    const top = (inc as Incident & { mitre_techniques?: string[] }).mitre_techniques
    if (Array.isArray(top)) top.forEach(bump)
    const ctxTech = ctx.mitre_techniques
    if (Array.isArray(ctxTech)) ctxTech.forEach(bump)
    const ti = ctx.threat_intel as
      | { matched_indicators?: Array<{ mitre_techniques?: string[] }> }
      | undefined
    for (const m of ti?.matched_indicators ?? []) {
      for (const t of m.mitre_techniques ?? []) bump(t)
    }
    for (const ev of inc.evidence ?? []) {
      const raw = ev.raw ?? {}
      const mitre = raw.mitre_techniques
      if (Array.isArray(mitre)) mitre.forEach(bump)
    }
  }
  return counts
}

function buildNavigatorLayer(rows: CoverageRow[]): Record<string, unknown> {
  const scores: Record<Depth, string> = {
    none: '0',
    rules: '1',
    model: '2',
    correlated: '3',
  }
  return {
    name: 'Black Onyx coverage',
    versions: { attack: '16', navigator: '5.0.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description: 'Generated from detector catalog + live incident sightings',
    techniques: rows.map((r) => ({
      techniqueID: r.technique.split('.')[0],
      score: Number(scores[r.depth]),
      comment: `${r.detectors.join(', ')}; sightings=${r.sightings}`,
    })),
    gradient: {
      colors: ['#ffffff', '#8ecbe6', '#1a73e8', '#0b3d91'],
      minValue: 0,
      maxValue: 3,
    },
  }
}

export function AttackCoverage() {
  const [filter, setFilter] = useState('')
  const [profileOnly, setProfileOnly] = useState(false)
  const [profileTechniques, setProfileTechniques] = useState<Set<string>>(new Set())
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [data, packs] = await Promise.all([api.listIncidents(), api.listSecurityPacks()])
        if (cancelled) return
        setIncidents(data)
        const tech = new Set<string>()
        for (const pack of packs.items) {
          if (!pack.pack_id.includes('mitre') && pack.kind !== 'framework') continue
          for (const check of pack.checks) {
            for (const t of check.mitre_techniques ?? []) tech.add(t.toUpperCase())
          }
        }
        // Always include MITRE core pack techniques when present
        for (const pack of packs.items.filter((p) => p.pack_id === 'mitre-attack-core')) {
          for (const check of pack.checks) {
            for (const t of check.mitre_techniques ?? []) tech.add(t.toUpperCase())
          }
        }
        setProfileTechniques(tech)
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

  const coverage = useMemo(() => {
    const sightings = collectTechniquesFromIncidents(incidents)
    const byId = new Map<string, CoverageRow>()
    for (const row of DETECTOR_CATALOG) {
      const key = row.technique.toUpperCase()
      const count =
        [...sightings.entries()]
          .filter(([t]) => t === key || t.startsWith(`${key}.`) || key.startsWith(`${t}.`))
          .reduce((n, [, c]) => n + c, 0) || (sightings.get(key) ?? 0)
      let depth = row.depth
      if (count > 0 && depth !== 'correlated') {
        depth = depth === 'model' ? 'correlated' : depth
      }
      byId.set(key, { ...row, depth, sightings: count })
    }
    for (const [tech, count] of sightings) {
      if (byId.has(tech)) continue
      // Parent technique when only sub-technique sighted
      const parent = tech.split('.')[0]
      if (byId.has(parent)) {
        const existing = byId.get(parent)!
        byId.set(parent, { ...existing, sightings: existing.sightings + count })
        continue
      }
      byId.set(tech, {
        technique: tech,
        name: tech,
        tactic: 'Observed',
        depth: 'correlated',
        detectors: ['live incident / TI'],
        sightings: count,
      })
    }
    return [...byId.values()].sort((a, b) => a.technique.localeCompare(b.technique))
  }, [incidents])

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase()
    return coverage.filter((r) => {
      if (profileOnly && profileTechniques.size > 0) {
        const id = r.technique.toUpperCase()
        const parent = id.split('.')[0]
        if (!profileTechniques.has(id) && !profileTechniques.has(parent)) return false
      }
      if (!q) return true
      return (
        r.technique.toLowerCase().includes(q) ||
        r.name.toLowerCase().includes(q) ||
        r.tactic.toLowerCase().includes(q) ||
        r.detectors.some((d) => d.toLowerCase().includes(q))
      )
    })
  }, [filter, coverage, profileOnly, profileTechniques])

  const summary = useMemo(() => {
    const counts: Record<Depth, number> = {
      none: 0,
      rules: 0,
      model: 0,
      correlated: 0,
    }
    for (const row of coverage) counts[row.depth] += 1
    return counts
  }, [coverage])

  function downloadNavigator() {
    const layer = buildNavigatorLayer(coverage)
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' })
    downloadBlob(blob, 'black-onyx-attack-navigator-layer.json')
  }

  if (loading) return <div className="loading">Loading ATT&amp;CK coverage…</div>
  if (error) return <div className="error">{error}</div>

  return (
    <div>
      <div className="page-header">
        <h1>ATT&amp;CK coverage</h1>
        <p className="muted">
          Detection depth heatmap from platform detectors, merged with MITRE tags on open
          incidents and threat-intel matches. Export an ATT&amp;CK Navigator layer for offline
          review.
        </p>
      </div>

      <div className="attack-summary">
        {DEPTH_ORDER.map((d) => (
          <span key={d} className={depthClass(d)}>
            {depthLabel(d)}: {summary[d]}
          </span>
        ))}
        <button type="button" className="btn" onClick={downloadNavigator}>
          Export Navigator layer
        </button>
      </div>

      <div className="toolbar" style={{ marginBottom: '0.75rem', flexWrap: 'wrap' }}>
        <label className="muted">
          Filter{' '}
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="T1071 / beacon / Persistence"
            aria-label="Filter techniques"
          />
        </label>
        <label className="muted">
          <input
            type="checkbox"
            checked={profileOnly}
            onChange={(e) => setProfileOnly(e.target.checked)}
            aria-label="Filter by active profile MITRE packs"
          />{' '}
          Active profile MITRE packs only
        </label>
      </div>

      <table className="table data attack-heatmap">
        <thead>
          <tr>
            <th>Technique</th>
            <th>Name</th>
            <th>Tactic</th>
            <th>Depth</th>
            <th>Sightings</th>
            <th>Detectors / sources</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.technique}>
              <td className="mono">{row.technique}</td>
              <td>{row.name}</td>
              <td>{row.tactic}</td>
              <td>
                <span className={depthClass(row.depth)}>{depthLabel(row.depth)}</span>
              </td>
              <td className="mono">{row.sightings}</td>
              <td className="mono">{row.detectors.join(', ')}</td>
            </tr>
          ))}
          {rows.length === 0 ? (
            <tr>
              <td colSpan={6}>
                <div className="empty">No techniques match the filter.</div>
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  )
}

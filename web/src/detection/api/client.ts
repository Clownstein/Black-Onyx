import type {
  AnalystFeedback,
  Asset,
  AssetBaseline,
  AssetTopology,
  CapabilityState,
  Comment,
  DataHealthSource,
  DeploymentEvent,
  EvidenceItem,
  FederatedHuntResult,
  Finding,
  Incident,
  IncidentDisposition,
  LinkedFindingRow,
  MalwareReport,
  ModelDrift,
  ModelInfo,
  ModelVersionInfo,
  NotificationSetting,
  ProfileCoverage,
  SavedHunt,
  SecurityPack,
  SecurityPreset,
  SecurityProfile,
  SimilarHit,
  ThreatIntelFeedHealth,
  TimelineEntry,
  TrainingJobSummary,
  VectorHuntResult,
} from './contracts'

export type HuntHit = {
  doc_type: 'finding' | 'incident'
  id: string
  title: string
  summary?: string
  severity?: string
}

const API_BASE = '/api/v1/detection/incident'
const ASSET_REGISTRY_BASE = '/api/v1/detection/assets'
const TRAINING_API_BASE = '/api/v1/detection/training'
const MODEL_GATEWAY_BASE = '/api/v1/detection/models'
const RESPONSE_ORCHESTRATOR_BASE = '/api/v1/detection/response'
const THREAT_INTEL_BASE = '/api/v1/detection/ti'
/** Malware analyze/submit go through ingestion-gateway BFF (server injects ingest key). */
const MALWARE_GATEWAY_BASE = '/api/v1/detection/ingest'
const NOTIFICATION_BASE = '/api/v1/detection/notify'
const INTEGRATION_HUB_BASE = '/api/v1/detection/hub'
const GRAFANA_URL = (import.meta.env.VITE_GRAFANA_URL ?? '').replace(/\/$/, '')
/** Grafana Explore links only render when VITE_GRAFANA_URL is configured. */
const GRAFANA_ENABLED = Boolean(GRAFANA_URL)
/** TheHive / Velociraptor links require the hub proxy to be explicitly enabled. */
const INTEGRATION_HUB_ENABLED =
  (import.meta.env.VITE_INTEGRATION_HUB_ENABLED ?? 'true').toLowerCase() !== 'false'

const KNOWN_MODEL_IDS = ['log-model', 'metrics-model', 'network-model', 'code-model', 'host-state-model'] as const

type ApiFinding = {
  finding_id: string
  incident_ids?: string[]
  evidence_refs?: string[]
  finding_type?: string
  asset_id?: string
  service_id?: string | null
  model_name?: string
  calibrated_score?: number
  raw_score?: number
  severity_hint?: string | null
  window?: { start?: string; end?: string }
  contributors?: Array<Record<string, unknown>>
  payload?: Record<string, unknown>
  context?: Record<string, unknown>
}

type ApiAssetRead = {
  asset_id: string
  name?: string
  asset_type?: string
  environment?: string | null
  owner_team?: string | null
  service_id?: string | null
  active?: boolean
  updated_at?: string
  created_at?: string
}

type HealthTarget = {
  source_id: string
  name: string
  modality: string
  url: string
}

const DEFAULT_HEALTH_TARGETS: HealthTarget[] = [
  {
    source_id: 'ingestion-gateway',
    name: 'ingestion-gateway',
    modality: 'ingest',
    url: '/api/v1/detection/ingest/health/live',
  },
  {
    source_id: 'asset-registry',
    name: 'asset-registry',
    modality: 'assets',
    url: '/api/v1/detection/assets/health/live',
  },
  {
    source_id: 'incident-api',
    name: 'incident-api',
    modality: 'incidents',
    url: '/api/v1/detection/incident/health/live',
  },
  {
    source_id: 'model-gateway',
    name: 'model-gateway',
    modality: 'models',
    url: '/api/v1/detection/models/health/live',
  },
  {
    source_id: 'training-orchestrator',
    name: 'training-orchestrator',
    modality: 'training',
    url: '/api/v1/detection/training/health/live',
  },
  {
    source_id: 'threat-intel-service',
    name: 'threat-intel-service',
    modality: 'threat-intel',
    url: '/api/v1/detection/ti/health/live',
  },
  {
    source_id: 'threat-intel-feeds',
    name: 'threat-intel feeds',
    modality: 'threat-intel',
    url: '/api/v1/detection/ti/health/ready',
  },
  {
    source_id: 'response-orchestrator',
    name: 'response-orchestrator',
    modality: 'response',
    url: '/api/v1/detection/response/health/live',
  },
  {
    source_id: 'integration-hub',
    name: 'integration-hub',
    modality: 'integrations',
    url: '/api/v1/detection/hub/health/live',
  },
  {
    source_id: 'notification-service',
    name: 'notification-service',
    modality: 'notifications',
    url: '/api/v1/detection/notify/health/live',
  },
]

function kindFromFindingType(findingType: string | undefined): Finding['kind'] {
  const t = (findingType ?? '').toLowerCase()
  if (t.includes('malware')) return 'malware'
  if (t.includes('firewall')) return 'firewall'
  if (t.includes('host_state') || t.includes('host-state')) return 'host_state'
  if (t.includes('log')) return 'logs'
  if (t.includes('net') || t.includes('flow') || t.includes('suricata')) return 'network'
  if (t.includes('met')) return 'metrics'
  if (t.includes('code')) return 'code'
  return 'correlation'
}

function unwrapItems<T>(payload: T[] | { items?: T[] } | null | undefined): T[] {
  if (!payload) return []
  if (Array.isArray(payload)) return payload
  return payload.items ?? []
}

function normalizeFinding(raw: ApiFinding): Finding {
  const payload = raw.payload ?? {}
  const severity = (raw.severity_hint ?? 'medium') as Finding['severity']
  const first = raw.window?.start ?? new Date().toISOString()
  const last = raw.window?.end ?? first
  const summary =
    typeof payload.summary === 'string'
      ? payload.summary
      : String(payload.summary ?? raw.model_name ?? raw.finding_id)
  const legacyIncidentId =
    typeof payload.incident_id === 'string'
      ? payload.incident_id
      : typeof raw.context?.incident_id === 'string'
        ? String(raw.context.incident_id)
        : null
  const ctx = (raw.context ?? {}) as Record<string, unknown>
  const enrichmentRaw =
    (ctx.code_enrichment as Record<string, unknown> | undefined) ??
    (payload.code_enrichment as Record<string, unknown> | undefined)
  const cweIds = Array.isArray(ctx.cwe_ids)
    ? (ctx.cwe_ids as string[])
    : Array.isArray(payload.cwe_ids)
      ? (payload.cwe_ids as string[])
      : undefined
  return {
    finding_id: raw.finding_id,
    model: raw.model_name ?? 'unknown',
    kind: kindFromFindingType(raw.finding_type),
    severity,
    risk_score: Number(raw.calibrated_score ?? raw.raw_score ?? 0),
    title:
      typeof payload.title === 'string'
        ? payload.title
        : typeof ctx.title === 'string'
          ? ctx.title
          : `${raw.finding_type ?? 'finding'} on ${raw.asset_id ?? 'unknown'}`,
    asset_id: raw.asset_id ?? 'unknown',
    service: raw.service_id ?? 'unknown',
    first_seen: first,
    last_seen: last,
    incident_id: raw.incident_ids?.[0] ?? legacyIncidentId,
    incident_ids: raw.incident_ids?.length ? raw.incident_ids : legacyIncidentId ? [legacyIncidentId] : [],
    evidence_refs: raw.evidence_refs ?? [],
    summary: typeof ctx.summary === 'string' && typeof payload.summary !== 'string' ? ctx.summary : summary,
    enrichment: enrichmentRaw
      ? {
          status: typeof enrichmentRaw.status === 'string' ? enrichmentRaw.status : undefined,
          cwe_ids: Array.isArray(enrichmentRaw.cwe_ids)
            ? (enrichmentRaw.cwe_ids as string[])
            : undefined,
          human_review_required: enrichmentRaw.human_review_required !== false,
          model_ran: Boolean(enrichmentRaw.model_ran),
          degraded: Boolean(enrichmentRaw.degraded),
          file_hits: Array.isArray(enrichmentRaw.file_hits)
            ? (enrichmentRaw.file_hits as Array<{
                path?: string
                cwe_ids?: string[]
                title?: string
              }>)
            : undefined,
          advisory:
            typeof enrichmentRaw.advisory === 'string' ? enrichmentRaw.advisory : undefined,
        }
      : null,
    cwe_ids: cweIds,
  }
}

function contributorSummary(contributors: unknown): string | null {
  if (!Array.isArray(contributors)) return null
  const lines: string[] = []
  for (const item of contributors) {
    if (!item || typeof item !== 'object') continue
    const c = item as Record<string, unknown>
    if (typeof c.summary === 'string' && c.summary.trim()) {
      lines.push(c.summary.trim())
      continue
    }
    if (typeof c.metric === 'string' && c.metric.trim()) {
      lines.push(c.metric.trim())
      continue
    }
    if (typeof c.template_id === 'string' && c.template_id.trim()) {
      lines.push(`template ${c.template_id.trim()}`)
      continue
    }
    if (typeof c.type === 'string' && c.type.trim()) {
      lines.push(c.type.replace(/_/g, ' '))
    }
  }
  return lines.length ? lines.slice(0, 3).join('; ') : null
}

function findingToEvidence(raw: ApiFinding): EvidenceItem {
  const payload = raw.payload ?? {}
  const ctx = (raw.context ?? payload.context ?? {}) as Record<string, unknown>
  const title =
    typeof payload.title === 'string'
      ? payload.title
      : typeof ctx.title === 'string'
        ? ctx.title
        : `${raw.finding_type ?? 'finding'} on ${raw.asset_id ?? 'unknown'}`
  const detail =
    typeof payload.summary === 'string'
      ? payload.summary
      : contributorSummary(raw.contributors ?? payload.contributors) ??
        (typeof ctx.summary === 'string' ? ctx.summary : null) ??
        String(raw.model_name ?? raw.finding_id)
  const evidenceRefs = [
    ...(raw.evidence_refs ?? []),
    ...(Array.isArray(ctx.evidence_refs) ? (ctx.evidence_refs as string[]) : []),
  ]
  return {
    kind: kindFromFindingType(raw.finding_type),
    model: raw.model_name ?? 'unknown',
    title,
    detail,
    score: Number(raw.calibrated_score ?? raw.raw_score ?? 0),
    timestamp: raw.window?.end ?? raw.window?.start ?? new Date().toISOString(),
    raw: {
      ...payload,
      finding_id: raw.finding_id,
      finding_type: raw.finding_type,
      contributors: raw.contributors ?? payload.contributors ?? [],
      evidence_refs: evidenceRefs,
      context: ctx,
    },
  }
}

function normalizeAssetRead(raw: ApiAssetRead): Asset {
  return {
    asset_id: raw.asset_id,
    name: raw.name ?? raw.asset_id,
    kind: raw.asset_type ?? 'unknown',
    environment: raw.environment ?? 'unknown',
    owner: raw.owner_team ?? 'unknown',
    services: raw.service_id ? [raw.service_id] : [],
    last_seen: raw.updated_at ?? raw.created_at ?? new Date().toISOString(),
    status: raw.active === false ? 'degraded' : 'healthy',
  }
}

function cookie(name: string): string {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}=([^;]*)`))
  return match ? decodeURIComponent(match[1]) : ""
}

async function fetchJson<T>(base: string, path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method || "GET").toUpperCase()
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(init?.body != null ? { "Content-Type": "application/json" } : {}),
    ...((init?.headers as Record<string, string>) ?? {}),
  }
  if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
    headers["X-CSRF-Token"] = cookie("blackonyx_csrf")
  }
  const res = await fetch(`${base}${path}`, {
    ...init,
    credentials: "same-origin",
    headers,
  })
  if (!res.ok) {
    if (res.status === 401) {
      window.dispatchEvent(new Event("blackonyx:session-expired"))
    }
    const text = await res.text().catch(() => "")
    throw new Error(`API ${res.status}: ${text || res.statusText}`)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  return fetchJson<T>(API_BASE, path, init)
}

function normalizeIncident(raw: Incident): Incident {
  const evidence = Array.isArray(raw.evidence) ? raw.evidence : []
  const context = raw.context ?? {}
  const openingReason =
    raw.opening_reason ??
    (typeof context.opening_reason === 'string' ? context.opening_reason : null)
  const models =
    raw.models?.length
      ? raw.models
      : [...new Set(evidence.map((e) => e.model).filter(Boolean))]
  const summary =
    raw.summary?.trim() ||
    openingReason?.trim() ||
    ''
  return {
    ...raw,
    category: raw.category ?? [],
    assets: raw.assets ?? [],
    services: raw.services ?? [],
    finding_ids: raw.finding_ids ?? [],
    evidence,
    context,
    models,
    summary,
    opening_reason: openingReason,
  }
}

function evidenceLooksThin(items: EvidenceItem[]): boolean {
  if (items.length === 0) return true
  return items.every((item) => {
    const detail = (item.detail || '').trim().toLowerCase()
    const title = (item.title || '').trim().toLowerCase()
    return (
      detail.startsWith('calibrated_score=') ||
      detail.startsWith('detail=calibrated_score=') ||
      (title.startsWith('calibrated_score=') && (!detail || detail.startsWith('calibrated_score=')))
    )
  })
}

async function enrichIncidentEvidence(row: Incident): Promise<Incident> {
  const existing = Array.isArray(row.evidence) ? row.evidence : []
  if (!evidenceLooksThin(existing)) return normalizeIncident(row)
  const findingIds = row.finding_ids ?? []
  if (findingIds.length === 0) return normalizeIncident(row)

  const evidence = (
    await Promise.all(
      findingIds.map(async (fid) => {
        try {
          const finding = await apiFetch<ApiFinding>(`/api/v1/findings/${fid}`)
          return findingToEvidence(finding)
        } catch {
          return null
        }
      }),
    )
  ).filter((e): e is EvidenceItem => e != null)

  return normalizeIncident({ ...row, evidence })
}

async function listIncidentsFromApi(): Promise<Incident[]> {
  const payload = await apiFetch<Incident[] | { items?: Incident[] }>('/api/v1/incidents')
  const items = unwrapItems(payload).map(normalizeIncident)
  // Hydrate evidence for list rows that only carry finding_ids.
  return Promise.all(
    items.map(async (row) => {
      if ((row.evidence?.length ?? 0) > 0) return row
      if (!(row.finding_ids?.length > 0)) return row
      try {
        return await enrichIncidentEvidence(row)
      } catch {
        return row
      }
    }),
  )
}

function modelTemplate(id: string): ModelInfo {
  return {
    model_id: id,
    name: id,
    modality: kindFromFindingType(id),
    version: 'unknown',
    status: 'offline',
    last_inference: null,
    findings_24h: null,
    avg_latency_ms: null,
    aliases: [],
    artifact_state: 'unknown',
    trainable: id !== 'host-state-model',
    capability_reason: id === 'host-state-model' ? 'inference-only; trainer unavailable' : null,
  }
}

function parseHealthTargets(): HealthTarget[] {
  return DEFAULT_HEALTH_TARGETS
}

async function probeHealthUrl(url: string): Promise<boolean> {
  try {
    if (!url.startsWith('/api/v1/detection/')) return false
    const res = await fetch(url, {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    })
    return res.ok
  } catch {
    return false
  }
}

async function loadModelsFromOps(): Promise<ModelInfo[] | null> {
  try {
    const payload = await apiFetch<ModelInfo[] | { items?: ModelInfo[] }>('/api/v1/ops/models')
    const items = unwrapItems(payload)
    return items.length > 0 ? items : null
  } catch {
    return null
  }
}

async function loadModelsFromTraining(): Promise<ModelInfo[] | null> {
  try {
    const payload = await fetchJson<ModelInfo[] | { items?: ModelInfo[] } | { models?: string[] }>(
      TRAINING_API_BASE,
      '/api/v1/models',
    )
    if (Array.isArray(payload)) return payload.length > 0 ? payload : null
    if (payload && 'items' in payload && Array.isArray(payload.items) && payload.items.length > 0) {
      return payload.items
    }
    if (payload && 'models' in payload && Array.isArray(payload.models)) {
      return payload.models.map((id) => modelTemplate(id))
    }
    return null
  } catch {
    return null
  }
}

async function gatewayModelHealth(): Promise<Map<string, ModelInfo['status']>> {
  const statuses = new Map<string, ModelInfo['status']>()
  for (const path of ['/health/dependencies', '/health/ready']) {
    try {
      const body = await fetchJson<Record<string, unknown>>(MODEL_GATEWAY_BASE, path)
      const models = body.models
      if (models && typeof models === 'object' && !Array.isArray(models)) {
        for (const [id, value] of Object.entries(models as Record<string, unknown>)) {
          if (typeof value === 'string') {
            // ready payload maps model -> url; presence means configured
            statuses.set(id, body.status === 'ready' || body.status === 'ok' ? 'ready' : 'degraded')
          } else if (value && typeof value === 'object') {
            const st = String((value as { status?: string }).status ?? '').toLowerCase()
            if (st === 'up' || st === 'ok' || st === 'ready' || st === 'alive') {
              statuses.set(id, 'ready')
            } else if (st === 'training') {
              statuses.set(id, 'training')
            } else if (st) {
              statuses.set(id, 'degraded')
            }
          }
        }
      }
      if (Array.isArray(models)) {
        for (const id of models) {
          if (typeof id === 'string') statuses.set(id, 'ready')
        }
      }
      // Also probe /health/live as overall gateway signal
      if (statuses.size === 0) {
        const liveOk = await probeHealthUrl(`${MODEL_GATEWAY_BASE}/health/live`)
        for (const id of KNOWN_MODEL_IDS) {
          statuses.set(id, liveOk ? 'ready' : 'offline')
        }
      }
      if (statuses.size > 0) break
    } catch {
      // try next path
    }
  }
  return statuses
}

async function loadModelsLive(): Promise<ModelInfo[]> {
  const fromOps = await loadModelsFromOps()
  if (fromOps) return fromOps

  const fromTraining = await loadModelsFromTraining()
  if (fromTraining) return fromTraining

  const health = await gatewayModelHealth()
  const ids = health.size > 0 ? [...new Set([...KNOWN_MODEL_IDS, ...health.keys()])] : [...KNOWN_MODEL_IDS]
  const liveOk = health.size > 0 || (await probeHealthUrl(`${MODEL_GATEWAY_BASE}/health/live`))

  if (!liveOk && health.size === 0) {
    throw new Error('model catalog unavailable')
  }

  return ids.map((id) => {
    const base = modelTemplate(id)
    return {
      ...base,
      status: health.get(id) ?? (liveOk ? 'ready' : 'offline'),
    }
  })
}

async function loadDataHealthFromOps(): Promise<DataHealthSource[] | null> {
  try {
    const payload = await apiFetch<DataHealthSource[] | { items?: DataHealthSource[] }>(
      '/api/v1/ops/data-health',
    )
    const items = unwrapItems(payload)
    return items.length > 0 ? items : null
  } catch {
    return null
  }
}

async function probeDataHealthTargets(): Promise<DataHealthSource[]> {
  const targets = parseHealthTargets()
  return Promise.all(
    targets.map(async (t) => {
      const ok = await probeHealthUrl(t.url)
      return {
        source_id: t.source_id,
        name: t.name,
        modality: t.modality,
        lag_seconds: null,
        lag_records: null,
        events_per_min: null,
        status: ok ? 'ok' : 'error',
        last_event: null,
        reason: 'service probe only; broker telemetry endpoint unavailable',
      } satisfies DataHealthSource
    }),
  )
}

export const api = {
  apiBase: API_BASE,
  grafanaEnabled: GRAFANA_ENABLED,
  integrationHubEnabled: INTEGRATION_HUB_ENABLED,

  async listIncidents(): Promise<Incident[]> {
    return listIncidentsFromApi()
  },

  async getIncident(id: string): Promise<Incident> {
    const row = await apiFetch<Incident>(`/api/v1/incidents/${id}`)
    return enrichIncidentEvidence(row)
  },

  async getTimeline(id: string): Promise<TimelineEntry[]> {
    type ApiTimeline = {
      occurred_at?: string
      created_at?: string
      event_type: string
      summary?: string
      refs?: Record<string, unknown>
      detail?: Record<string, unknown>
      actor?: string | null
      entry_id?: string
      tenant_id?: string
    }
    const rows = await apiFetch<ApiTimeline[]>(`/api/v1/incidents/${id}/timeline`)
    return rows.map((e, i) => {
      const refs = e.refs ?? e.detail ?? {}
      const summary =
        e.summary ??
        (typeof refs.summary === 'string' ? refs.summary : undefined) ??
        (typeof refs.note === 'string' ? refs.note : undefined)
      return {
        entry_id: e.entry_id || `${id}-tl-${i}`,
        incident_id: id,
        tenant_id: e.tenant_id ?? '',
        event_type: e.event_type,
        summary,
        detail: refs,
        actor: e.actor ?? null,
        created_at: e.created_at ?? e.occurred_at ?? new Date().toISOString(),
      }
    })
  },

  async listLinkedFindings(incident: Incident): Promise<LinkedFindingRow[]> {
    const ctx = incident.context ?? {}
    const related = Array.isArray(ctx.related_finding_ids)
      ? (ctx.related_finding_ids as string[])
      : []
    const primary = incident.finding_ids ?? []
    const ids = [...new Set([...primary, ...related])]
    if (ids.length === 0) return []
    const rows = await Promise.all(
      ids.map(async (findingId) => {
        try {
          const raw = await apiFetch<ApiFinding>(`/api/v1/findings/${encodeURIComponent(findingId)}`)
          const normalized = normalizeFinding(raw)
          return {
            finding_id: findingId,
            finding_type: raw.finding_type ?? normalized.kind,
            title: normalized.title,
            summary: normalized.summary,
            asset_id: normalized.asset_id,
            score: normalized.risk_score,
            linked: primary.includes(findingId),
          }
        } catch {
          return {
            finding_id: findingId,
            finding_type: 'unknown',
            title: findingId,
            summary: '',
            asset_id: '—',
            score: 0,
            linked: primary.includes(findingId),
          }
        }
      }),
    )
    return rows
  },

  async listRelated(id: string): Promise<Incident[]> {
    const payload = await apiFetch<Incident[] | { items?: Incident[] }>(
      `/api/v1/incidents/${id}/related`,
    )
    return unwrapItems(payload).map(normalizeIncident)
  },

  async getComments(id: string): Promise<Comment[]> {
    try {
      const rows = await apiFetch<Comment[]>(`/api/v1/incidents/${id}/comments`)
      return rows
    } catch {
      const timeline = await this.getTimeline(id)
      return timeline
        .filter((e) => e.event_type === 'comment')
        .map((e, i) => ({
          comment_id: e.entry_id || `cmt-${i}`,
          incident_id: id,
          tenant_id: e.tenant_id,
          author: String(e.detail.author ?? e.actor ?? 'unknown'),
          body: String(e.detail.body ?? ''),
          created_at: e.created_at,
        }))
    }
  },

  async acknowledge(id: string): Promise<Incident> {
    return apiFetch<Incident>(`/api/v1/incidents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status: 'acknowledged' }),
    })
  },

  async assign(id: string, assigned_to: string): Promise<Incident> {
    return apiFetch<Incident>(`/api/v1/incidents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ assigned_to, status: 'acknowledged' }),
    })
  },

  async comment(id: string, author: string, body: string): Promise<Comment> {
    return apiFetch<Comment>(`/api/v1/incidents/${id}/comments`, {
      method: 'POST',
      body: JSON.stringify({ author, body }),
    })
  },

  async disposition(
    id: string,
    disposition: IncidentDisposition,
    note?: string,
  ): Promise<Incident> {
    return apiFetch<Incident>(`/api/v1/incidents/${id}/disposition`, {
      method: 'POST',
      body: JSON.stringify({ disposition, note }),
    })
  },

  async resolve(id: string): Promise<Incident> {
    return apiFetch<Incident>(`/api/v1/incidents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status: 'resolved' }),
    })
  },

  grafanaExploreUrl(incident: Incident): string {
    const from = encodeURIComponent(incident.first_seen)
    const to = encodeURIComponent(incident.last_seen)
    const query = encodeURIComponent(
      `{incident_id="${incident.incident_id}"} or {service=~"${(incident.services || []).join('|') || '.*'}"}`,
    )
    return `${GRAFANA_URL}/explore?orgId=1&from=${from}&to=${to}&left=${encodeURIComponent(
      JSON.stringify({
        datasource: 'Loki',
        queries: [{ refId: 'A', expr: decodeURIComponent(query) }],
        range: { from: incident.first_seen, to: incident.last_seen },
      }),
    )}`
  },

  async huntSearch(q: string, size = 50): Promise<{ hits: HuntHit[]; total: number }> {
    const query = q.trim()
    const params = new URLSearchParams()
    if (query) params.set('q', query)
    params.set('size', String(size))
    const payload = await apiFetch<{
      hits?: Array<{ id?: string; source?: Record<string, unknown> }>
      total?: number
    }>(`/api/v1/hunt/search?${params}`)
    const hits: HuntHit[] = (payload.hits ?? []).map((h) => {
      const src = h.source || {}
      const docType = String(src.doc_type || 'finding')
      const id = String(src.incident_id || src.finding_id || h.id || '')
      return {
        doc_type: docType === 'incident' ? 'incident' : 'finding',
        id,
        title: String(src.title || id),
        summary: src.summary != null ? String(src.summary) : undefined,
        severity: src.severity != null ? String(src.severity) : undefined,
      }
    })
    return { hits, total: payload.total ?? hits.length }
  },

  async openTheHiveCase(incident: Incident): Promise<{ dry_run?: boolean; case_id?: string }> {
    return fetchJson(INTEGRATION_HUB_BASE, '/api/v1/thehive/cases', {
      method: 'POST',
      body: JSON.stringify({ incident }),
    })
  },

  async requestVelociraptorCollect(
    incident: Incident,
    assetId?: string,
  ): Promise<{ request_id: string; status: string; dry_run?: boolean }> {
    const asset = assetId || incident.assets[0] || 'unknown'
    return fetchJson(INTEGRATION_HUB_BASE, '/api/v1/dfir/collect', {
      method: 'POST',
      body: JSON.stringify({
        asset_id: asset,
        incident_id: incident.incident_id,
        dry_run: true,
      }),
    })
  },

  async listFindings(): Promise<Finding[]> {
    const all: ApiFinding[] = []
    let cursor: string | undefined
    do {
      const params = new URLSearchParams({ limit: '500' })
      if (cursor) params.set('cursor', cursor)
      const page = await apiFetch<{ items?: ApiFinding[]; next_cursor?: string | null }>(
        `/api/v1/findings?${params.toString()}`,
      )
      all.push(...(page.items ?? []))
      cursor = page.next_cursor ?? undefined
      if (cursor && all.length >= 20000) {
        throw new Error('More than 20,000 findings are available; narrow the time range before loading this view.')
      }
    } while (cursor)
    return all.map(normalizeFinding)
  },

  async getFindingEvidence(findingId: string): Promise<{
    finding_id: string
    evidence_refs: string[]
    contributors: Array<Record<string, unknown>>
    context: Record<string, unknown>
  }> {
    return apiFetch(`/api/v1/findings/${encodeURIComponent(findingId)}/evidence`)
  },

  async downloadFindingEvidence(findingId: string, uri: string): Promise<{ blob: Blob; filename: string }> {
    const query = new URLSearchParams({ uri })
    const response = await fetch(
      `${API_BASE}/api/v1/findings/${encodeURIComponent(findingId)}/evidence/download?${query.toString()}`,
      { credentials: 'same-origin', headers: { Accept: 'application/octet-stream' } },
    )
    if (!response.ok) {
      if (response.status === 401) window.dispatchEvent(new Event('blackonyx:session-expired'))
      const detail = await response.text().catch(() => '')
      throw new Error(`Evidence download failed (${response.status})${detail ? `: ${detail}` : ''}`)
    }
    const disposition = response.headers.get('content-disposition') ?? ''
    const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1]
    const basic = disposition.match(/filename="?([^";]+)"?/i)?.[1]
    let filename = basic ?? 'evidence.bin'
    if (encoded) {
      try { filename = decodeURIComponent(encoded) } catch { filename = 'evidence.bin' }
    }
    return { blob: await response.blob(), filename }
  },

  async listAssets(): Promise<Asset[]> {
    const payload = await fetchJson<ApiAssetRead[] | { items?: ApiAssetRead[] }>(
      ASSET_REGISTRY_BASE,
      '/api/v1/assets',
    )
    return unwrapItems(payload).map(normalizeAssetRead)
  },

  async getAsset(id: string): Promise<Asset> {
    const row = await fetchJson<ApiAssetRead>(ASSET_REGISTRY_BASE, `/api/v1/assets/${id}`)
    return normalizeAssetRead(row)
  },

  async getAssetTopology(id: string): Promise<AssetTopology> {
    return fetchJson(ASSET_REGISTRY_BASE, `/api/v1/assets/${id}/topology`)
  },

  async getAssetBaseline(id: string, windowDays = 7): Promise<AssetBaseline> {
    return fetchJson(
      ASSET_REGISTRY_BASE,
      `/api/v1/assets/${id}/baseline?window_days=${windowDays}`,
    )
  },

  async listModels(): Promise<ModelInfo[]> {
    return loadModelsLive()
  },

  async getModel(id: string): Promise<ModelInfo> {
    const all = await this.listModels()
    const row = all.find((m) => m.model_id === id)
    if (!row) throw new Error('model not found')
    return row
  },

  async getModelDrift(id: string): Promise<ModelDrift> {
    return fetchJson(TRAINING_API_BASE, `/api/v1/models/${id}/drift`)
  },

  async listModelVersions(id: string): Promise<ModelVersionInfo[]> {
    const body = await fetchJson<{ items: ModelVersionInfo[] }>(
      TRAINING_API_BASE,
      `/api/v1/models/${id}/versions`,
    )
    return body.items ?? []
  },

  async promoteModelVersion(
    id: string,
    version: string,
    alias: 'champion' | 'canary' | 'shadow' | 'candidate',
  ): Promise<void> {
    await fetchJson(
      TRAINING_API_BASE,
      `/api/v1/models/${id}/versions/${encodeURIComponent(version)}/promote`,
      {
        method: 'POST',
        body: JSON.stringify({ alias }),
      },
    )
  },

  async listDataHealth(): Promise<DataHealthSource[]> {
    const fromOps = await loadDataHealthFromOps()
    if (fromOps) return fromOps
    return probeDataHealthTargets()
  },

  async listThreatIntelFeeds(): Promise<ThreatIntelFeedHealth[]> {
    const body = await fetchJson<{ feeds?: ThreatIntelFeedHealth[] }>(
      THREAT_INTEL_BASE,
      '/api/v1/feeds/health',
    )
    return Array.isArray(body.feeds) ? body.feeds : []
  },

  async listNotificationSettings(): Promise<NotificationSetting[]> {
    return apiFetch('/api/v1/settings/notifications')
  },

  async saveNotificationSetting(input: {
    setting_id?: string
    channel: string
    enabled: boolean
    config: Record<string, unknown>
  }): Promise<NotificationSetting> {
    const settingId = input.setting_id ?? `setting-${input.channel}`
    return apiFetch(`/api/v1/settings/notifications/${encodeURIComponent(settingId)}`, {
      method: 'PUT',
      body: JSON.stringify({ ...input, setting_id: settingId }),
    })
  },

  async listDeployments(serviceId?: string): Promise<DeploymentEvent[]> {
    const query = serviceId ? `?service_id=${encodeURIComponent(serviceId)}` : ''
    return apiFetch(`/api/v1/deployments${query}`)
  },

  async listSavedHunts(): Promise<SavedHunt[]> {
    return apiFetch('/api/v1/saved-hunts')
  },

  async saveHunt(input: {
    hunt_id?: string
    name: string
    query: string
    query_type: string
    filters?: Record<string, unknown>
  }): Promise<SavedHunt> {
    return apiFetch('/api/v1/saved-hunts', {
      method: 'POST',
      body: JSON.stringify(input),
    })
  },

  async createAnalystFeedback(
    incidentId: string,
    input: { finding_id?: string; label: string; note?: string },
  ): Promise<AnalystFeedback> {
    return apiFetch(`/api/v1/incidents/${incidentId}/feedback`, {
      method: 'POST',
      body: JSON.stringify(input),
    })
  },

  async analyzeMalware(input: {
    sha256?: string
    file_name?: string
    content_base64?: string
  }): Promise<MalwareReport> {
    const body = await fetchJson<{ report: MalwareReport }>(
      MALWARE_GATEWAY_BASE,
      '/api/v1/malware/analyze',
      {
      method: 'POST',
      body: JSON.stringify({
        sha256: input.sha256,
        file_name: input.file_name,
        content_base64: input.content_base64,
      }),
      },
    )
    return body.report
  },

  async queueMalwareSandbox(input: {
    sha256: string
    file_name?: string
    machine_profile?: string
    content_base64?: string
  }): Promise<string> {
    const body = await fetchJson<{
      queued_sandbox?: boolean
      submission?: { submission_id?: string; sha256?: string }
      report?: MalwareReport
      detonation?: { queued?: boolean; reason?: string }
    }>(MALWARE_GATEWAY_BASE, '/api/v1/malware/submit', {
      method: 'POST',
      body: JSON.stringify({
        sha256: input.sha256,
        file_name: input.file_name,
        content_base64: input.content_base64,
        machine_profile: input.machine_profile ?? 'win10-office',
        queue_sandbox: true,
        policy_allow_detonate: true,
      }),
    })
    const shortHash = input.sha256.slice(0, 12)
    const submissionId = body.submission?.submission_id
    if (body.detonation && body.detonation.queued === false) {
      return `Sandbox not queued for ${shortHash}… (${body.detonation.reason ?? 'policy denied'})`
    }
    if (body.queued_sandbox || submissionId) {
      const idNote = submissionId ? ` submission ${submissionId}` : ''
      return `Queued ${shortHash}… for sandbox${idNote}. Dynamic score appears after CAPE/DRAKVUF finishes.`
    }
    return `Submit accepted for ${shortHash}… — check malware-orchestrator for detonation status.`
  },

  async listSecurityPacks(): Promise<{ items: SecurityPack[]; presets: SecurityPreset[] }> {
    return apiFetch('/api/v1/security-packs')
  },

  async listSecurityProfiles(): Promise<SecurityProfile[]> {
    const body = await apiFetch<{ items: SecurityProfile[] }>('/api/v1/security-profiles')
    return body.items ?? []
  },

  async createSecurityProfile(input: {
    name: string
    selected_packs: string[]
    enabled_surfaces?: string[]
  }): Promise<SecurityProfile> {
    return apiFetch('/api/v1/security-profiles', {
      method: 'POST',
      body: JSON.stringify(input),
    })
  },

  async getSecurityProfileCoverage(profileId: string): Promise<ProfileCoverage> {
    const body = await apiFetch<{
      profile_id: string
      coverage?: ProfileCoverage['checks']
      checks?: ProfileCoverage['checks']
      summary: Record<string, number>
    }>(`/api/v1/security-profiles/${profileId}/coverage`)
    const checks = (body.checks ?? body.coverage ?? []).map((c) => ({
      check_id: c.check_id,
      title: c.title ?? (c as { detail?: { title?: string } }).detail?.title ?? c.check_id,
      status: c.status,
      automation: c.automation ?? 'unknown',
      surfaces: c.surfaces ?? [],
      reason: c.reason,
    }))
    return { profile_id: body.profile_id, checks, summary: body.summary ?? {} }
  },

  async evaluateSecurityProfile(profileId: string): Promise<ProfileCoverage> {
    const body = await apiFetch<{
      profile_id: string
      coverage?: ProfileCoverage['checks']
      summary: Record<string, number>
    }>(`/api/v1/security-profiles/${profileId}/evaluate`, { method: 'POST' })
    const checks = (body.coverage ?? []).map((c) => ({
      check_id: c.check_id,
      title: c.title ?? c.check_id,
      status: c.status,
      automation: c.automation ?? 'unknown',
      surfaces: c.surfaces ?? [],
      reason: c.reason,
    }))
    return { profile_id: body.profile_id, checks, summary: body.summary ?? {} }
  },

  async attestSecurityCheck(
    profileId: string,
    checkId: string,
    note?: string,
  ): Promise<{ attestation_id: string; check_id: string; note?: string }> {
    return apiFetch(`/api/v1/security-profiles/${profileId}/attest`, {
      method: 'POST',
      body: JSON.stringify({ check_id: checkId, note }),
    })
  },

  async generateCertificationPackage(
    profileId: string,
    target: string,
    exportFormat: 'json' | 'csv' | 'zip' = 'json',
  ): Promise<{ package_id: string; target: string; disclaimer: string; control_count: number } | Blob> {
    if (exportFormat === 'json') {
      return apiFetch(`/api/v1/security-profiles/${profileId}/certification-package`, {
        method: 'POST',
        body: JSON.stringify({ target, include_unknown: true }),
      })
    }
    const resp = await fetch(
      `${API_BASE}/api/v1/security-profiles/${profileId}/certification-package?export_format=${exportFormat}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': cookie('blackonyx_csrf'),
        },
        credentials: 'same-origin',
        body: JSON.stringify({ target, include_unknown: true }),
      },
    )
    if (!resp.ok) {
      throw new Error(`certification package failed: ${resp.status}`)
    }
    return resp.blob()
  },

  async listProfileExceptions(
    profileId: string,
  ): Promise<Array<{ exception_id: string; check_id: string; rationale: string; status: string }>> {
    const body = await apiFetch<{
      items: Array<{ exception_id: string; check_id: string; rationale: string; status: string }>
    }>(`/api/v1/security-profiles/${profileId}/exceptions`)
    return body.items ?? []
  },

  async listSimilarFindings(findingId: string): Promise<SimilarHit[]> {
    const body = await apiFetch<{ items: SimilarHit[] } & Partial<CapabilityState>>(
      `/api/v1/findings/${findingId}/similar`,
    )
    if (body.status === 'disabled') return body.items ?? []
    if (body.status && body.status !== 'ready') {
      throw new Error(`${body.capability ?? 'similarity'} ${body.status}: ${body.reason ?? 'unavailable'}`)
    }
    return body.items ?? []
  },

  async listSimilarIncidents(incidentId: string): Promise<SimilarHit[]> {
    const body = await apiFetch<{ items: SimilarHit[] } & Partial<CapabilityState>>(
      `/api/v1/incidents/${incidentId}/similar`,
    )
    if (body.status === 'disabled') return body.items ?? []
    if (body.status && body.status !== 'ready') {
      throw new Error(`${body.capability ?? 'similarity'} ${body.status}: ${body.reason ?? 'unavailable'}`)
    }
    return body.items ?? []
  },

  async federatedHunt(q: string): Promise<FederatedHuntResult> {
    return apiFetch('/api/v1/hunt/federated', {
      method: 'POST',
      body: JSON.stringify({ query: q, size: 50 }),
    })
  },

  async huntVector(q: string): Promise<VectorHuntResult> {
    const body = await apiFetch<{
      hits?: Array<{
        source?: string
        id?: string
        title?: string
        score?: number
        payload?: Record<string, unknown>
      }>
      status?: VectorHuntResult['status']
      capability?: string
      reason?: string
    }>('/api/v1/hunt/vector', {
      method: 'POST',
      body: JSON.stringify({ text: q, limit: 25 }),
    })
    return {
      status: body.status,
      capability: body.capability,
      reason: body.reason,
      hits: (body.hits ?? []).map((h) => {
        const payload = h.payload ?? {}
        const summary =
          typeof payload.summary_text === 'string'
            ? payload.summary_text
            : typeof payload.summary === 'string'
              ? payload.summary
              : undefined
        return {
          source: String(h.source ?? 'qdrant'),
          id: String(h.id ?? ''),
          title: String(h.title ?? h.id ?? 'vector hit'),
          score: Number(h.score ?? 0),
          summary,
        }
      }),
    }
  },

  async getRunbookSuggestions(incidentId: string): Promise<{
    items: { title: string; score: number; path: string }[]
  }> {
    const body = await apiFetch<
      { items: { title: string; score: number; path: string }[] } & Partial<CapabilityState>
    >(`/api/v1/incidents/${incidentId}/runbooks`)
    if (body.status === 'disabled') return { items: body.items ?? [] }
    if (body.status && body.status !== 'ready') {
      throw new Error(`${body.capability ?? 'runbooks'} ${body.status}: ${body.reason ?? 'unavailable'}`)
    }
    return body
  },

  async listPendingResponses(): Promise<
    Array<{
      request_id: string
      incident_id: string
      playbook_id: string
      action: string
      status: string
      dry_run?: boolean
      payload?: { response_mode?: string; auto_execute?: boolean }
    }>
  > {
    const body = await fetchJson<{ items: Array<Record<string, unknown>> }>(
      RESPONSE_ORCHESTRATOR_BASE,
      '/api/v1/response/pending',
    )
    return (body.items ?? []) as Array<{
      request_id: string
      incident_id: string
      playbook_id: string
      action: string
      status: string
      dry_run?: boolean
      payload?: { response_mode?: string; auto_execute?: boolean }
    }>
  },

  async approveResponse(requestId: string, actor?: string, live = false): Promise<void> {
    await fetchJson(RESPONSE_ORCHESTRATOR_BASE, `/api/v1/response/${requestId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ actor, ...(live ? { dry_run: false } : {}) }),
    })
  },

  async listResponseReconciliation(): Promise<Array<{
    request_id: string
    incident_id: string
    playbook_id: string
    status: string
    result?: { message?: string; executed?: boolean | null }
  }>> {
    const body = await fetchJson<{ items: Array<Record<string, unknown>> }>(
      RESPONSE_ORCHESTRATOR_BASE,
      '/api/v1/response/reconciliation',
    )
    return (body.items ?? []) as Array<{
      request_id: string
      incident_id: string
      playbook_id: string
      status: string
      result?: { message?: string; executed?: boolean | null }
    }>
  },

  async scanResponseReconciliation(): Promise<void> {
    await fetchJson(RESPONSE_ORCHESTRATOR_BASE, '/api/v1/response/reconciliation/scan', {
      method: 'POST',
    })
  },

  async rejectResponse(requestId: string, actor?: string): Promise<void> {
    await fetchJson(RESPONSE_ORCHESTRATOR_BASE, `/api/v1/response/${requestId}/reject`, {
      method: 'POST',
      body: JSON.stringify(actor ? { actor } : {}),
    })
  },

  async startTrainingJob(
    modelId: string,
    input: { dataset_id?: string; dataset_path?: string; dataset_reviewed?: boolean; demo_synthetic?: boolean; run_async?: boolean },
    idempotencyKey = crypto.randomUUID(),
  ): Promise<{
    job_id: string
    status: string
    version?: string
    message?: string
  }> {
    return fetchJson(TRAINING_API_BASE, `/api/v1/models/${encodeURIComponent(modelId)}/training-jobs`, {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({
        dataset_id: input?.dataset_id ?? null,
        dataset_path: input?.dataset_path ?? null,
        dataset_reviewed: input?.dataset_reviewed ?? false,
        demo_synthetic: input?.demo_synthetic ?? false,
        run_async: input?.run_async ?? true,
        created_by: 'session',
      }),
    })
  },

  async getTrainingJob(jobId: string): Promise<{
    job_id: string
    status: string
    version?: string
    message?: string
    failure_reason?: string | null
  }> {
    return fetchJson(TRAINING_API_BASE, `/api/v1/training-jobs/${encodeURIComponent(jobId)}`)
  },

  async listTrainingJobs(modelId: string, limit = 50): Promise<TrainingJobSummary[]> {
    const query = new URLSearchParams({ model_name: modelId, limit: String(limit) })
    return fetchJson(TRAINING_API_BASE, `/api/v1/training-jobs?${query.toString()}`)
  },

  async rollbackModelVersion(id: string, version: string): Promise<void> {
    await fetchJson(
      TRAINING_API_BASE,
      `/api/v1/models/${encodeURIComponent(id)}/versions/${encodeURIComponent(version)}/rollback`,
      { method: 'POST', body: JSON.stringify({}) },
    )
  },

  async createAsset(input: {
    asset_id: string
    name: string
    asset_type: string
    environment?: string
    owner_team?: string
    service_id?: string
    active?: boolean
    criticality?: number
    tags?: Record<string, string>
    ip_address?: string
    notes?: string
  }): Promise<Asset> {
    const row = await fetchJson<ApiAssetRead>(ASSET_REGISTRY_BASE, '/api/v1/assets', {
      method: 'POST',
      body: JSON.stringify(input),
    })
    return normalizeAssetRead(row)
  },

  async updateAsset(
    assetId: string,
    input: {
      name?: string
      asset_type?: string
      environment?: string
      owner_team?: string
      service_id?: string
      active?: boolean
    },
  ): Promise<Asset> {
    const row = await fetchJson<ApiAssetRead>(
      ASSET_REGISTRY_BASE,
      `/api/v1/assets/${encodeURIComponent(assetId)}`,
      { method: 'PATCH', body: JSON.stringify(input) },
    )
    return normalizeAssetRead(row)
  },

  async deleteAsset(assetId: string): Promise<void> {
    await fetchJson(ASSET_REGISTRY_BASE, `/api/v1/assets/${encodeURIComponent(assetId)}`, {
      method: 'DELETE',
    })
  },

  async syncThreatIntelFeed(feed: 'kev' | 'taxii' | 'misp'): Promise<Record<string, unknown>> {
    const headers: Record<string, string> = {}
    return fetchJson(THREAT_INTEL_BASE, `/api/v1/feeds/${feed}/sync`, {
      method: 'POST',
      headers,
      body: JSON.stringify({}),
    })
  },

  async uploadStixBundle(bundle: Record<string, unknown>): Promise<Record<string, unknown>> {
    const headers: Record<string, string> = {}
    return fetchJson(THREAT_INTEL_BASE, '/api/v1/indicators/upload-stix', {
      method: 'POST',
      headers,
      body: JSON.stringify(bundle),
    })
  },

  async testNotification(input: {
    channels: string[]
    title?: string
    severity?: string
    email_to?: string
    webhook_url?: string
  }): Promise<Record<string, unknown>> {
    const headers: Record<string, string> = {}
    return fetchJson(NOTIFICATION_BASE, '/api/v1/notifications/test', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        incident_id: `test-${Date.now()}`,
        title: input.title ?? 'Ops console test notification',
        severity: input.severity ?? 'low',
        summary: 'Manual test from Administration',
        channels: input.channels,
        email_to: input.email_to,
        webhook_url: input.webhook_url,
      }),
    })
  },

  async listNotificationOutbox(): Promise<
    Array<{ id: number; tenant_id: string; recipient: string; subject: string; status: string; delivery_mode: string; attempt_count: number; last_error?: string | null; retryable: boolean }>
  > {
    const headers: Record<string, string> = {}
    const body = await fetchJson<{
      items: Array<{
        id: number
        tenant_id: string
        recipient: string
        subject: string
        status: string
        delivery_mode: string
        attempt_count: number
        last_error?: string | null
        retryable: boolean
      }>
    }>(NOTIFICATION_BASE, '/api/v1/notifications/outbox', { headers })
    return body.items ?? []
  },

  async retryNotificationOutbox(id: number): Promise<void> {
    await fetchJson(NOTIFICATION_BASE, `/api/v1/notifications/outbox/${id}/retry`, {
      method: 'POST',
      body: JSON.stringify({}),
    })
  },

  async flushNotificationOutbox(): Promise<Record<string, unknown>> {
    const headers: Record<string, string> = {}
    return fetchJson(NOTIFICATION_BASE, '/api/v1/notifications/outbox/flush', {
      method: 'POST',
      headers,
      body: JSON.stringify({}),
    })
  },

  async listPlaybooks(): Promise<Array<{ playbook_id: string; title?: string; description?: string; asset_scoped: boolean }>> {
    const body = await fetchJson<{ items: Array<Record<string, unknown>> }>(
      RESPONSE_ORCHESTRATOR_BASE,
      '/api/v1/playbooks',
    )
    return (body.items ?? []).map((p) => ({
      playbook_id: String(p.playbook_id ?? p.id ?? ''),
      title: p.title != null ? String(p.title) : p.name != null ? String(p.name) : undefined,
      description: p.description != null ? String(p.description) : undefined,
      asset_scoped: p.asset_scoped === true,
    }))
  },

  async createResponseRequest(input: {
    incident_id: string
    playbook_id: string
    asset_id?: string
    action?: string
    dry_run?: boolean
  }): Promise<{ request_id: string; status: string }> {
    return fetchJson(RESPONSE_ORCHESTRATOR_BASE, '/api/v1/response/request', {
      method: 'POST',
      body: JSON.stringify({
        incident_id: input.incident_id,
        playbook_id: input.playbook_id,
        action: input.action ?? 'execute',
        dry_run: input.dry_run ?? true,
        actor: undefined,
        payload: {
          response_mode: input.dry_run === false ? 'execute' : 'suggest_only',
          ...(input.asset_id ? { asset_id: input.asset_id } : {}),
        },
      }),
    })
  },

  async listResponseAudit(limit = 50): Promise<
    Array<{ id: string; request_id: string; action: string; actor?: string; created_at?: string }>
  > {
    const body = await fetchJson<{ items: Array<Record<string, unknown>> }>(
      RESPONSE_ORCHESTRATOR_BASE,
      `/api/v1/response/audit?limit=${limit}`,
    )
    return (body.items ?? []).map((r, index) => ({
      id: r.id != null ? String(r.id) : `${String(r.request_id ?? 'audit')}-${index}`,
      request_id: String(r.request_id ?? ''),
      action: String(r.action ?? r.event_type ?? ''),
      actor: r.actor != null ? String(r.actor) : undefined,
      created_at: r.created_at != null ? String(r.created_at) : undefined,
    }))
  },

  async patchSecurityProfile(
    profileId: string,
    input: {
      name?: string
      selected_packs?: string[]
      enabled_surfaces?: string[]
      active?: boolean
    },
  ): Promise<SecurityProfile> {
    return apiFetch(`/api/v1/security-profiles/${encodeURIComponent(profileId)}`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    })
  },

  async deleteSecurityProfile(profileId: string): Promise<void> {
    await apiFetch(`/api/v1/security-profiles/${encodeURIComponent(profileId)}`, {
      method: 'DELETE',
    })
  },

  async createProfileException(
    profileId: string,
    input: { check_id: string; rationale: string; owner?: string },
  ): Promise<{ exception_id: string; status: string }> {
    return apiFetch(`/api/v1/security-profiles/${encodeURIComponent(profileId)}/exceptions`, {
      method: 'POST',
      body: JSON.stringify(input),
    })
  },

  async createIncident(input: {
    title: string
    severity: string
    summary?: string
    assets?: string[]
    services?: string[]
  }): Promise<Incident> {
    const now = new Date().toISOString()
    return apiFetch('/api/v1/incidents', {
      method: 'POST',
      body: JSON.stringify({
        title: input.title,
        severity: input.severity,
        summary: input.summary ?? '',
        status: 'open',
        first_seen: now,
        last_seen: now,
        assets: input.assets ?? [],
        services: input.services ?? [],
        risk_score: 0,
      }),
    })
  },

  async upsertDeployment(input: {
    deployment_id: string
    service_id: string
    environment?: string
    version?: string
    commit?: string
  }): Promise<DeploymentEvent> {
    return apiFetch('/api/v1/deployments', {
      method: 'POST',
      body: JSON.stringify({
        deployment_id: input.deployment_id,
        service_id: input.service_id,
        environment: input.environment ?? 'prod',
        version: input.version,
        commit_sha: input.commit,
        status: 'succeeded',
        deployed_at: new Date().toISOString(),
      }),
    })
  },
}

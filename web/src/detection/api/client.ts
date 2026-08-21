import { mockApi } from './mocks'
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
  VectorHuntResult,
} from './contracts'

export type HuntHit = {
  doc_type: 'finding' | 'incident'
  id: string
  title: string
  summary?: string
  severity?: string
}

const USE_MOCK = (import.meta.env.VITE_DETECTION_USE_MOCK ?? 'false').toLowerCase() === 'true'
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
/** Grafana Explore links only render when VITE_GRAFANA_URL is configured (or in mock mode). */
const GRAFANA_ENABLED = Boolean(GRAFANA_URL) || USE_MOCK
/** TheHive / Velociraptor links require the hub proxy to be explicitly enabled. */
const INTEGRATION_HUB_ENABLED =
  (import.meta.env.VITE_INTEGRATION_HUB_ENABLED ?? 'true').toLowerCase() !== 'false'

const KNOWN_MODEL_IDS = ['log-model', 'metrics-model', 'network-model', 'code-model'] as const

type ApiFinding = {
  finding_id: string
  finding_type?: string
  asset_id?: string
  service_id?: string | null
  model_name?: string
  calibrated_score?: number
  raw_score?: number
  severity_hint?: string | null
  window?: { start?: string; end?: string }
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
  if (t.includes('log')) return 'logs'
  if (t.includes('net') || t.includes('flow')) return 'network'
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
  const incidentId =
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
    incident_id: incidentId,
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

function findingToEvidence(raw: ApiFinding): EvidenceItem {
  const payload = raw.payload ?? {}
  const title =
    typeof payload.title === 'string'
      ? payload.title
      : `${raw.finding_type ?? 'finding'} on ${raw.asset_id ?? 'unknown'}`
  const detail =
    typeof payload.summary === 'string'
      ? payload.summary
      : String(payload.summary ?? raw.model_name ?? raw.finding_id)
  return {
    kind: kindFromFindingType(raw.finding_type),
    model: raw.model_name ?? 'unknown',
    title,
    detail,
    score: Number(raw.calibrated_score ?? raw.raw_score ?? 0),
    timestamp: raw.window?.start ?? new Date().toISOString(),
    raw: {
      ...payload,
      finding_id: raw.finding_id,
      finding_type: raw.finding_type,
      context: raw.context,
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
    const text = await res.text().catch(() => "")
    throw new Error(`API ${res.status}: ${text || res.statusText}`)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  return fetchJson<T>(API_BASE, path, init)
}

function delay<T>(value: T, ms = 80): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms))
}

function normalizeIncident(raw: Incident): Incident {
  const evidence = Array.isArray(raw.evidence) ? raw.evidence : []
  const models =
    raw.models?.length
      ? raw.models
      : [...new Set(evidence.map((e) => e.model).filter(Boolean))]
  return {
    ...raw,
    category: raw.category ?? [],
    assets: raw.assets ?? [],
    services: raw.services ?? [],
    finding_ids: raw.finding_ids ?? [],
    evidence,
    context: raw.context ?? {},
    models,
    summary: raw.summary ?? '',
  }
}

async function enrichIncidentEvidence(row: Incident): Promise<Incident> {
  const existing = Array.isArray(row.evidence) ? row.evidence : []
  if (existing.length > 0) return normalizeIncident(row)
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
    last_inference: new Date(0).toISOString(),
    findings_24h: 0,
    avg_latency_ms: 0,
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
  useMock: USE_MOCK,
  apiBase: API_BASE,
  grafanaEnabled: GRAFANA_ENABLED,
  integrationHubEnabled: INTEGRATION_HUB_ENABLED,

  async listIncidents(): Promise<Incident[]> {
    if (USE_MOCK) return delay(mockApi.listIncidents())
    return listIncidentsFromApi()
  },

  async getIncident(id: string): Promise<Incident> {
    if (USE_MOCK) {
      const row = mockApi.getIncident(id)
      if (!row) throw new Error('incident not found')
      return delay(row)
    }
    const row = await apiFetch<Incident>(`/api/v1/incidents/${id}`)
    return enrichIncidentEvidence(row)
  },

  async getTimeline(id: string): Promise<TimelineEntry[]> {
    if (USE_MOCK) return delay(mockApi.getTimeline(id))
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
    return rows.map((e, i) => ({
      entry_id: e.entry_id || `${id}-tl-${i}`,
      incident_id: id,
      tenant_id: e.tenant_id ?? '',
      event_type: e.event_type,
      detail: e.detail ?? e.refs ?? { summary: e.summary },
      actor: e.actor ?? null,
      created_at: e.created_at ?? e.occurred_at ?? new Date().toISOString(),
    }))
  },

  async listRelated(id: string): Promise<Incident[]> {
    if (USE_MOCK) {
      const all = mockApi.listIncidents()
      const current = mockApi.getIncident(id)
      if (!current) return []
      return delay(
        all.filter(
          (inc) =>
            inc.incident_id !== id &&
            (inc.assets.some((a) => current.assets.includes(a)) ||
              inc.services.some((s) => current.services.includes(s))),
        ),
      )
    }
    const payload = await apiFetch<Incident[] | { items?: Incident[] }>(
      `/api/v1/incidents/${id}/related`,
    )
    return unwrapItems(payload).map(normalizeIncident)
  },

  async getComments(id: string): Promise<Comment[]> {
    if (USE_MOCK) return delay(mockApi.getComments(id))
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
    if (USE_MOCK) {
      const row = mockApi.acknowledge(id, null)
      if (!row) throw new Error('incident not found')
      return delay(row)
    }
    return apiFetch<Incident>(`/api/v1/incidents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status: 'acknowledged' }),
    })
  },

  async assign(id: string, assigned_to: string): Promise<Incident> {
    if (USE_MOCK) {
      const row = mockApi.assign(id, assigned_to, null)
      if (!row) throw new Error('incident not found')
      return delay(row)
    }
    return apiFetch<Incident>(`/api/v1/incidents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ assigned_to, status: 'acknowledged' }),
    })
  },

  async comment(id: string, author: string, body: string): Promise<Comment> {
    if (USE_MOCK) {
      const row = mockApi.comment(id, author, body)
      if (!row) throw new Error('incident not found')
      return delay(row)
    }
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
    if (USE_MOCK) {
      const row = mockApi.disposition(id, disposition, null, note)
      if (!row) throw new Error('incident not found')
      return delay(row)
    }
    return apiFetch<Incident>(`/api/v1/incidents/${id}/disposition`, {
      method: 'POST',
      body: JSON.stringify({ disposition, note }),
    })
  },

  async resolve(id: string): Promise<Incident> {
    if (USE_MOCK) {
      const row = mockApi.resolve(id, null)
      if (!row) throw new Error('incident not found')
      return delay(row)
    }
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
    if (USE_MOCK) {
      const findings = mockApi.listFindings()
      const incidents = mockApi.listIncidents()
      const needle = query.toLowerCase()
      const hits: HuntHit[] = []
      for (const f of findings) {
        const blob = `${f.finding_id} ${f.title} ${f.model} ${f.asset_id}`.toLowerCase()
        if (!needle || blob.includes(needle)) {
          hits.push({
            doc_type: 'finding',
            id: f.finding_id,
            title: f.title,
            summary: `${f.model} · ${f.severity}`,
            severity: f.severity,
          })
        }
      }
      for (const i of incidents) {
        const blob = `${i.incident_id} ${i.title} ${i.summary}`.toLowerCase()
        if (!needle || blob.includes(needle)) {
          hits.push({
            doc_type: 'incident',
            id: i.incident_id,
            title: i.title,
            summary: i.summary,
            severity: i.severity,
          })
        }
      }
      return delay({ hits: hits.slice(0, size), total: hits.length })
    }
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
    if (USE_MOCK) {
      return delay({ dry_run: true, case_id: `mock-case-${incident.incident_id}` })
    }
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
    if (USE_MOCK) {
      return delay({ request_id: `dfir-mock-${asset}`, status: 'queued', dry_run: true })
    }
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
    if (USE_MOCK) return delay(mockApi.listFindings())
    const payload = await apiFetch<ApiFinding[] | { items?: ApiFinding[] }>('/api/v1/findings')
    return unwrapItems(payload).map(normalizeFinding)
  },

  async listAssets(): Promise<Asset[]> {
    if (USE_MOCK) return delay(mockApi.listAssets())
    const payload = await fetchJson<ApiAssetRead[] | { items?: ApiAssetRead[] }>(
      ASSET_REGISTRY_BASE,
      '/api/v1/assets',
    )
    return unwrapItems(payload).map(normalizeAssetRead)
  },

  async getAsset(id: string): Promise<Asset> {
    if (USE_MOCK) {
      const row = mockApi.getAsset(id)
      if (!row) throw new Error('asset not found')
      return delay(row)
    }
    const row = await fetchJson<ApiAssetRead>(ASSET_REGISTRY_BASE, `/api/v1/assets/${id}`)
    return normalizeAssetRead(row)
  },

  async getAssetTopology(id: string): Promise<AssetTopology> {
    if (USE_MOCK) {
      const asset = mockApi.getAsset(id)
      if (!asset) throw new Error('asset not found')
      return delay({
        asset_id: id,
        nodes: [{ id, kind: 'asset', label: asset.name }],
        edges: [],
      })
    }
    return fetchJson(ASSET_REGISTRY_BASE, `/api/v1/assets/${id}/topology`)
  },

  async getAssetBaseline(id: string, windowDays = 7): Promise<AssetBaseline> {
    if (USE_MOCK) {
      return delay({
        asset_id: id,
        window_days: windowDays,
        stats: {
          status: 'empty',
          capability: 'asset_baseline',
          reason: 'mock mode has no retained finding history',
          sample_count: 0,
          mean_score: null,
          p95_score: null,
        },
      })
    }
    return fetchJson(
      ASSET_REGISTRY_BASE,
      `/api/v1/assets/${id}/baseline?window_days=${windowDays}`,
    )
  },

  async listModels(): Promise<ModelInfo[]> {
    if (USE_MOCK) return delay(mockApi.listModels())
    return loadModelsLive()
  },

  async getModel(id: string): Promise<ModelInfo> {
    if (USE_MOCK) {
      const row = mockApi.getModel(id)
      if (!row) throw new Error('model not found')
      return delay(row)
    }
    const all = await this.listModels()
    const row = all.find((m) => m.model_id === id)
    if (!row) throw new Error('model not found')
    return row
  },

  async getModelDrift(id: string): Promise<ModelDrift> {
    if (USE_MOCK) {
      return delay({
        model_name: id,
        computed_at: new Date().toISOString(),
        input_drift: {},
        output_drift: {},
        concept_drift: {},
        overall_score: 0,
        recommendation: 'mock_data_unavailable',
      })
    }
    return fetchJson(TRAINING_API_BASE, `/api/v1/models/${id}/drift`)
  },

  async listModelVersions(id: string): Promise<ModelVersionInfo[]> {
    if (USE_MOCK) return delay([])
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
    if (USE_MOCK) throw new Error('model promotion is unavailable in mock mode')
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
    if (USE_MOCK) return delay(mockApi.listDataHealth())
    const fromOps = await loadDataHealthFromOps()
    if (fromOps) return fromOps
    return probeDataHealthTargets()
  },

  async listThreatIntelFeeds(): Promise<ThreatIntelFeedHealth[]> {
    if (USE_MOCK) return delay(mockApi.listThreatIntelFeeds())
    const body = await fetchJson<{ feeds?: ThreatIntelFeedHealth[] }>(
      THREAT_INTEL_BASE,
      '/api/v1/feeds/health',
    )
    return Array.isArray(body.feeds) ? body.feeds : []
  },

  async listNotificationSettings(): Promise<NotificationSetting[]> {
    if (USE_MOCK) return delay([])
    return apiFetch('/api/v1/settings/notifications')
  },

  async saveNotificationSetting(input: {
    setting_id?: string
    channel: string
    enabled: boolean
    config: Record<string, unknown>
  }): Promise<NotificationSetting> {
    if (USE_MOCK) {
      const now = new Date().toISOString()
      return delay({
        setting_id: input.setting_id ?? `setting-${input.channel}`,
        tenant_id: 'mock-tenant',
        channel: input.channel,
        enabled: input.enabled,
        config: input.config,
        updated_by: 'mock-user',
        created_at: now,
        updated_at: now,
      })
    }
    const settingId = input.setting_id ?? `setting-${input.channel}`
    return apiFetch(`/api/v1/settings/notifications/${encodeURIComponent(settingId)}`, {
      method: 'PUT',
      body: JSON.stringify({ ...input, setting_id: settingId }),
    })
  },

  async listDeployments(serviceId?: string): Promise<DeploymentEvent[]> {
    if (USE_MOCK) return delay([])
    const query = serviceId ? `?service_id=${encodeURIComponent(serviceId)}` : ''
    return apiFetch(`/api/v1/deployments${query}`)
  },

  async listSavedHunts(): Promise<SavedHunt[]> {
    if (USE_MOCK) return delay([])
    return apiFetch('/api/v1/saved-hunts')
  },

  async saveHunt(input: {
    hunt_id?: string
    name: string
    query: string
    query_type: string
    filters?: Record<string, unknown>
  }): Promise<SavedHunt> {
    if (USE_MOCK) throw new Error('saved hunts are unavailable in mock mode')
    return apiFetch('/api/v1/saved-hunts', {
      method: 'POST',
      body: JSON.stringify(input),
    })
  },

  async createAnalystFeedback(
    incidentId: string,
    input: { finding_id?: string; label: string; note?: string },
  ): Promise<AnalystFeedback> {
    if (USE_MOCK) throw new Error('analyst feedback persistence is unavailable in mock mode')
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
    if (USE_MOCK) return delay(mockApi.analyzeMalware(input))
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
  }): Promise<string> {
    if (USE_MOCK) return delay(mockApi.queueMalwareSandbox(input))
    await fetchJson(MALWARE_GATEWAY_BASE, '/api/v1/malware/submit', {
      method: 'POST',
      body: JSON.stringify({
        sha256: input.sha256,
        file_name: input.file_name,
        machine_profile: input.machine_profile ?? 'win10-office',
        queue_sandbox: true,
        policy_allow_detonate: true,
      }),
    })
    return `Queued ${input.sha256.slice(0, 12)}… for sandbox`
  },

  async listSecurityPacks(): Promise<{ items: SecurityPack[]; presets: SecurityPreset[] }> {
    if (USE_MOCK) return delay(mockApi.listSecurityPacks())
    return apiFetch('/api/v1/security-packs')
  },

  async listSecurityProfiles(): Promise<SecurityProfile[]> {
    if (USE_MOCK) return delay(mockApi.listSecurityProfiles())
    const body = await apiFetch<{ items: SecurityProfile[] }>('/api/v1/security-profiles')
    return body.items ?? []
  },

  async createSecurityProfile(input: {
    name: string
    selected_packs: string[]
    enabled_surfaces?: string[]
  }): Promise<SecurityProfile> {
    if (USE_MOCK) return delay(mockApi.createSecurityProfile(input))
    return apiFetch('/api/v1/security-profiles', {
      method: 'POST',
      body: JSON.stringify(input),
    })
  },

  async getSecurityProfileCoverage(profileId: string): Promise<ProfileCoverage> {
    if (USE_MOCK) return delay(mockApi.getSecurityProfileCoverage(profileId))
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
    if (USE_MOCK) return delay(mockApi.getSecurityProfileCoverage(profileId))
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
    if (USE_MOCK) return delay(mockApi.attestSecurityCheck(profileId, checkId, note))
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
    if (USE_MOCK) return delay(mockApi.generateCertificationPackage(profileId, target))
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
    if (USE_MOCK) return delay([])
    const body = await apiFetch<{
      items: Array<{ exception_id: string; check_id: string; rationale: string; status: string }>
    }>(`/api/v1/security-profiles/${profileId}/exceptions`)
    return body.items ?? []
  },

  async listSimilarFindings(findingId: string): Promise<SimilarHit[]> {
    if (USE_MOCK) return delay(mockApi.listSimilarFindings(findingId))
    const body = await apiFetch<{ items: SimilarHit[] } & Partial<CapabilityState>>(
      `/api/v1/findings/${findingId}/similar`,
    )
    if (body.status && body.status !== 'ready') {
      throw new Error(`${body.capability ?? 'similarity'} ${body.status}: ${body.reason ?? 'unavailable'}`)
    }
    return body.items ?? []
  },

  async listSimilarIncidents(incidentId: string): Promise<SimilarHit[]> {
    if (USE_MOCK) {
      return delay([
        {
          id: 'inc-similar',
          title: 'Similar correlated campaign',
          score: 0.84,
          source: 'qdrant',
        },
      ])
    }
    const body = await apiFetch<{ items: SimilarHit[] } & Partial<CapabilityState>>(
      `/api/v1/incidents/${incidentId}/similar`,
    )
    if (body.status && body.status !== 'ready') {
      throw new Error(`${body.capability ?? 'similarity'} ${body.status}: ${body.reason ?? 'unavailable'}`)
    }
    return body.items ?? []
  },

  async federatedHunt(q: string): Promise<FederatedHuntResult> {
    if (USE_MOCK) return delay(mockApi.federatedHunt(q))
    return apiFetch('/api/v1/hunt/federated', {
      method: 'POST',
      body: JSON.stringify({ query: q, size: 50 }),
    })
  },

  async huntVector(q: string): Promise<VectorHuntResult> {
    if (USE_MOCK) return delay(mockApi.huntVector(q))
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
    if (USE_MOCK) return delay(mockApi.getRunbookSuggestions(incidentId))
    const body = await apiFetch<
      { items: { title: string; score: number; path: string }[] } & Partial<CapabilityState>
    >(`/api/v1/incidents/${incidentId}/runbooks`)
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
    if (USE_MOCK) {
      return delay([
        {
          request_id: 'resp-mock-1',
          incident_id: 'inc-1',
          playbook_id: 'isolate-host',
          action: 'execute',
          status: 'pending',
          dry_run: true,
          payload: { response_mode: 'suggest_only', auto_execute: false },
        },
      ])
    }
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

  async approveResponse(requestId: string, actor?: string): Promise<void> {
    if (USE_MOCK) return delay(undefined)
    await fetchJson(RESPONSE_ORCHESTRATOR_BASE, `/api/v1/response/${requestId}/approve`, {
      method: 'POST',
      body: JSON.stringify(actor ? { actor } : {}),
    })
  },

  async rejectResponse(requestId: string, actor?: string): Promise<void> {
    if (USE_MOCK) return delay(undefined)
    await fetchJson(RESPONSE_ORCHESTRATOR_BASE, `/api/v1/response/${requestId}/reject`, {
      method: 'POST',
      body: JSON.stringify(actor ? { actor } : {}),
    })
  },

  async startTrainingJob(
    modelId: string,
    input?: { dataset_id?: string; run_async?: boolean },
  ): Promise<{
    job_id: string
    status: string
    version?: string
    message?: string
  }> {
    if (USE_MOCK) {
      return delay({
        job_id: `job-mock-${modelId}`,
        status: 'completed',
        version: '0.1.1',
        message: 'mock training complete',
      })
    }
    return fetchJson(TRAINING_API_BASE, `/api/v1/models/${encodeURIComponent(modelId)}/training-jobs`, {
      method: 'POST',
      body: JSON.stringify({
        dataset_id: input?.dataset_id ?? null,
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
  }> {
    if (USE_MOCK) {
      return delay({ job_id: jobId, status: 'completed', version: '0.1.1' })
    }
    return fetchJson(TRAINING_API_BASE, `/api/v1/training-jobs/${encodeURIComponent(jobId)}`)
  },

  async rollbackModelVersion(id: string, version: string): Promise<void> {
    if (USE_MOCK) throw new Error('model rollback is unavailable in mock mode')
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
    if (USE_MOCK) {
      return delay({
        asset_id: input.asset_id,
        name: input.name,
        kind: input.asset_type,
        environment: input.environment ?? 'unknown',
        owner: input.owner_team ?? 'unknown',
        services: input.service_id ? [input.service_id] : [],
        last_seen: new Date().toISOString(),
        status: input.active === false ? 'degraded' : 'healthy',
      })
    }
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
    if (USE_MOCK) throw new Error('asset update is unavailable in mock mode')
    const row = await fetchJson<ApiAssetRead>(
      ASSET_REGISTRY_BASE,
      `/api/v1/assets/${encodeURIComponent(assetId)}`,
      { method: 'PATCH', body: JSON.stringify(input) },
    )
    return normalizeAssetRead(row)
  },

  async deleteAsset(assetId: string): Promise<void> {
    if (USE_MOCK) return delay(undefined)
    await fetchJson(ASSET_REGISTRY_BASE, `/api/v1/assets/${encodeURIComponent(assetId)}`, {
      method: 'DELETE',
    })
  },

  async syncThreatIntelFeed(feed: 'kev' | 'taxii' | 'misp'): Promise<Record<string, unknown>> {
    if (USE_MOCK) return delay({ status: 'ok', feed })
    const headers: Record<string, string> = {}
    return fetchJson(THREAT_INTEL_BASE, `/api/v1/feeds/${feed}/sync`, {
      method: 'POST',
      headers,
      body: JSON.stringify({}),
    })
  },

  async uploadStixBundle(bundle: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (USE_MOCK) return delay({ status: 'ok', imported: 0 })
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
    if (USE_MOCK) return delay({ results: { mock: true } })
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
    Array<{ id: number; tenant_id: string; recipient: string; subject: string; status: string }>
  > {
    if (USE_MOCK) return delay([])
    const headers: Record<string, string> = {}
    const body = await fetchJson<{
      items: Array<{
        id: number
        tenant_id: string
        recipient: string
        subject: string
        status: string
      }>
    }>(NOTIFICATION_BASE, '/api/v1/notifications/outbox', { headers })
    return body.items ?? []
  },

  async flushNotificationOutbox(): Promise<Record<string, unknown>> {
    if (USE_MOCK) return delay({ flushed: 0 })
    const headers: Record<string, string> = {}
    return fetchJson(NOTIFICATION_BASE, '/api/v1/notifications/outbox/flush', {
      method: 'POST',
      headers,
      body: JSON.stringify({}),
    })
  },

  async listPlaybooks(): Promise<Array<{ playbook_id: string; title?: string; description?: string }>> {
    if (USE_MOCK) {
      return delay([{ playbook_id: 'isolate-host', title: 'Isolate host', description: 'mock' }])
    }
    const body = await fetchJson<{ items: Array<Record<string, unknown>> }>(
      RESPONSE_ORCHESTRATOR_BASE,
      '/api/v1/playbooks',
    )
    return (body.items ?? []).map((p) => ({
      playbook_id: String(p.playbook_id ?? p.id ?? ''),
      title: p.title != null ? String(p.title) : p.name != null ? String(p.name) : undefined,
      description: p.description != null ? String(p.description) : undefined,
    }))
  },

  async createResponseRequest(input: {
    incident_id: string
    playbook_id: string
    action?: string
    dry_run?: boolean
  }): Promise<{ request_id: string; status: string }> {
    if (USE_MOCK) {
      return delay({ request_id: `resp-mock-${Date.now()}`, status: 'pending' })
    }
    return fetchJson(RESPONSE_ORCHESTRATOR_BASE, '/api/v1/response/request', {
      method: 'POST',
      body: JSON.stringify({
        incident_id: input.incident_id,
        playbook_id: input.playbook_id,
        action: input.action ?? 'execute',
        dry_run: input.dry_run ?? true,
        actor: undefined,
        payload: { response_mode: input.dry_run === false ? 'execute' : 'suggest_only' },
      }),
    })
  },

  async listResponseAudit(limit = 50): Promise<
    Array<{ id: string; request_id: string; action: string; actor?: string; created_at?: string }>
  > {
    if (USE_MOCK) return delay([])
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
    if (USE_MOCK) throw new Error('profile patch is unavailable in mock mode')
    return apiFetch(`/api/v1/security-profiles/${encodeURIComponent(profileId)}`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    })
  },

  async deleteSecurityProfile(profileId: string): Promise<void> {
    if (USE_MOCK) return delay(undefined)
    await apiFetch(`/api/v1/security-profiles/${encodeURIComponent(profileId)}`, {
      method: 'DELETE',
    })
  },

  async createProfileException(
    profileId: string,
    input: { check_id: string; rationale: string; owner?: string },
  ): Promise<{ exception_id: string; status: string }> {
    if (USE_MOCK) {
      return delay({ exception_id: `exc-mock-${input.check_id}`, status: 'open' })
    }
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
    if (USE_MOCK) throw new Error('incident create is unavailable in mock mode')
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
    if (USE_MOCK) throw new Error('deployment upsert is unavailable in mock mode')
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

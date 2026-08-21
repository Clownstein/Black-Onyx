export type IncidentStatus =
  | 'open'
  | 'acknowledged'
  | 'investigating'
  | 'resolved'
  | 'closed'
  | 'suppressed'

export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical'

export type IncidentDisposition =
  | 'true_positive'
  | 'false_positive'
  | 'expected_change'
  | 'maintenance'
  | 'benign_anomaly'
  | 'duplicate'
  | 'unknown'

export type EvidenceKind =
  | 'logs'
  | 'code'
  | 'network'
  | 'metrics'
  | 'correlation'
  | 'malware'
  | 'host_state'
  | 'firewall'

export interface CapabilityState {
  status: 'ready' | 'disabled' | 'degraded' | 'empty'
  capability: string
  reason?: string | null
  retry_after_seconds?: number | null
}

export interface MalwareReport {
  finding_type: 'malware_analysis'
  sample: {
    sha256: string
    sha1?: string | null
    md5?: string | null
    file_type?: string | null
    names: string[]
    size_bytes?: number | null
  }
  scores: {
    static_ember?: number | null
    static_heuristic?: number | null
    sandbox_score?: number | null
    clamav?: string | null
  }
  yara: { rule: string; tags?: string[]; engine?: string }[]
  capabilities: {
    name: string
    'att&ck'?: string[]
    source?: string
    engine?: string
  }[]
  mitre_techniques: string[]
  stage: 'static' | 'dynamic' | 'emulation'
  strings_sample?: string[]
  analysis?: {
    static_scorer?: string
    ember?: boolean
    yara_engine?: string
    capabilities_engine?: string
    strings_engine?: string
    clamav?: boolean
  }
  network?: { dns?: string[]; hosts?: string[]; pcap_uri?: string | null }
}

export interface EvidenceItem {
  kind: EvidenceKind
  model: string
  title: string
  detail: string
  score?: number
  timestamp: string
  raw?: Record<string, unknown>
}

export interface TimelineEntry {
  entry_id: string
  incident_id: string
  tenant_id: string
  event_type: string
  detail: Record<string, unknown>
  actor: string | null
  created_at: string
}

export interface Comment {
  comment_id: string
  incident_id: string
  tenant_id: string
  author: string
  body: string
  created_at: string
}

export interface Incident {
  incident_id: string
  tenant_id: string
  title: string
  status: IncidentStatus
  severity: IncidentSeverity
  risk_score: number
  category: string[]
  first_seen: string
  last_seen: string
  assets: string[]
  services: string[]
  deployment_id: string | null
  commit: string | null
  finding_ids: string[]
  summary: string
  evidence: EvidenceItem[]
  assigned_to: string | null
  disposition: IncidentDisposition | null
  fingerprint: string | null
  context: Record<string, unknown>
  models: string[]
}

export interface CodeEnrichmentInfo {
  status?: string
  cwe_ids?: string[]
  human_review_required?: boolean
  model_ran?: boolean
  degraded?: boolean
  file_hits?: Array<{ path?: string; cwe_ids?: string[]; title?: string }>
  advisory?: string
}

export interface Finding {
  finding_id: string
  model: string
  kind: EvidenceKind
  severity: IncidentSeverity
  risk_score: number
  title: string
  asset_id: string
  service: string
  first_seen: string
  last_seen: string
  incident_id: string | null
  summary: string
  enrichment?: CodeEnrichmentInfo | null
  cwe_ids?: string[]
}

export interface Asset {
  asset_id: string
  name: string
  kind: string
  environment: string
  owner: string
  services: string[]
  last_seen: string
  status: 'healthy' | 'degraded' | 'unknown'
}

export interface AssetTopology {
  asset_id: string
  nodes: Array<{ id: string; kind: string; label?: string | null }>
  edges: Array<{ source: string; target: string; relation: string }>
}

export interface AssetBaseline {
  asset_id: string
  window_days: number
  stats: CapabilityState & {
    sample_count: number
    mean_score: number | null
    p95_score: number | null
  }
}

export type ProfileCheckStatus =
  | 'pass'
  | 'fail'
  | 'unknown'
  | 'not_applicable'
  | 'attested'

export interface SecurityPackCheck {
  check_id: string
  title: string
  surfaces: string[]
  automation: 'auto' | 'hybrid' | 'manual'
  severity_default?: string
  mitre_techniques?: string[]
}

export interface SecurityPack {
  pack_id: string
  kind: string
  version: string
  title: string
  description?: string
  check_count: number
  checks: SecurityPackCheck[]
}

export interface SecurityPreset {
  id: string
  name: string
  packs: string[]
  description?: string
}

export interface SecurityProfile {
  profile_id: string
  tenant_id: string
  name: string
  selected_packs: string[]
  asset_scope: string[]
  enabled_surfaces: string[]
  schedule: string
  strictness: string
  merge_policy: string
  active: boolean
  preview?: {
    auto_count?: number
    manual_count?: number
    hybrid_count?: number
    checks?: SecurityPackCheck[]
  } | null
}

export interface ProfileCoverageCheck {
  check_id: string
  title: string
  status: ProfileCheckStatus
  automation: string
  surfaces: string[]
  reason?: string
}

export interface ProfileCoverage {
  profile_id: string
  checks: ProfileCoverageCheck[]
  summary: Record<string, number>
}

export interface SimilarHit {
  id: string
  title: string
  score: number
  source: string
  summary?: string
}

export interface FederatedHuntHit {
  source: 'opensearch' | 'qdrant' | 'ti_exact' | 'ti_semantic'
  id: string
  title: string
  score: number
  summary?: string
}

export interface FederatedHuntResult {
  hits: FederatedHuntHit[]
  warnings: string[]
  status?: CapabilityState['status']
  capability?: string
  reason?: string
}

export interface VectorHuntHit {
  source: string
  id: string
  title: string
  score: number
  summary?: string
}

export interface VectorHuntResult {
  hits: VectorHuntHit[]
  status?: CapabilityState['status']
  capability?: string
  reason?: string
}

export interface ModelInfo {
  model_id: string
  name: string
  modality: EvidenceKind
  version: string
  status: 'ready' | 'training' | 'degraded' | 'offline'
  last_inference: string
  findings_24h: number
  avg_latency_ms: number
}

export interface ModelVersionInfo {
  version: string
  aliases: string[]
  created_at: string
}

export interface ModelDrift {
  model_name: string
  computed_at: string
  input_drift: Record<string, number>
  output_drift: Record<string, number>
  concept_drift: Record<string, number | boolean>
  overall_score: number
  recommendation: string
}

export interface DataHealthSource {
  source_id: string
  name: string
  modality: string
  lag_seconds: number | null
  lag_records: number | null
  events_per_min: number | null
  status: 'ok' | 'lagging' | 'stale' | 'error'
  last_event: string | null
  reason?: string
}

export interface ThreatIntelFeedHealth {
  feed_name: string
  last_sync_at: string | null
  last_status: string
  last_error: string | null
  indicator_count: number
}

export interface DeploymentEvent {
  deployment_id: string
  tenant_id: string
  service_id: string
  environment: string
  commit_sha: string | null
  version: string | null
  status: string
  deployed_at: string
  payload: Record<string, unknown>
}

export interface SavedHunt {
  hunt_id: string
  tenant_id: string
  name: string
  query: string
  query_type: string
  filters: Record<string, unknown>
  created_by: string
  created_at: string
  updated_at: string
}

export interface AnalystFeedback {
  feedback_id: string
  tenant_id: string
  incident_id: string
  finding_id: string | null
  label: string
  note: string | null
  actor: string
  created_at: string
}

export interface NotificationSetting {
  setting_id: string
  tenant_id: string
  channel: string
  enabled: boolean
  config: Record<string, unknown>
  updated_by: string
  created_at: string
  updated_at: string
}

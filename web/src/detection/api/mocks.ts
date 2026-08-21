import type {
  Asset,
  Comment,
  DataHealthSource,
  FederatedHuntResult,
  Finding,
  Incident,
  IncidentDisposition,
  MalwareReport,
  ModelInfo,
  ProfileCoverage,
  ProfileCheckStatus,
  SecurityPack,
  SecurityPreset,
  SecurityProfile,
  SimilarHit,
  ThreatIntelFeedHealth,
  TimelineEntry,
  VectorHuntResult,
} from './contracts'


const TENANT = 'tenant-demo'

function isoMinutesAgo(minutes: number): string {
  return new Date(Date.now() - minutes * 60_000).toISOString()
}

const incidents: Incident[] = [
  {
    incident_id: 'inc-01HZ9K2M7Q',
    tenant_id: TENANT,
    title: 'Elevated error rate with suspicious egress on checkout-api',
    status: 'open',
    severity: 'critical',
    risk_score: 0.94,
    category: ['availability', 'security'],
    first_seen: isoMinutesAgo(95),
    last_seen: isoMinutesAgo(4),
    assets: ['host-checkout-03', 'pod-checkout-api-7f2'],
    services: ['checkout-api'],
    deployment_id: 'deploy-2026-07-26-14',
    commit: 'a3f8c12',
    finding_ids: ['fnd-log-001', 'fnd-net-002', 'fnd-met-003', 'fnd-code-004'],
    summary:
      'Log model spiked on auth failures, metrics show p99 latency climb, and network model flagged unusual DNS + egress volume correlated to the latest checkout-api deploy.',
    evidence: [
      {
        kind: 'logs',
        model: 'log-model',
        title: 'Auth failure burst',
        detail: 'Template T-882 spiked 18x vs baseline in checkout-api pods.',
        score: 0.91,
        timestamp: isoMinutesAgo(90),
        raw: {
          template_id: 'T-882',
          count: 1842,
          sequence: [
            { template_id: 'T-110', text: 'request started', anomalous: false },
            { template_id: 'T-882', text: 'auth failure for user *', anomalous: true },
            { template_id: 'T-882', text: 'auth failure for user *', anomalous: true },
            { template_id: 'T-901', text: 'token refresh retry', anomalous: true },
            { template_id: 'T-220', text: 'request completed status=401', anomalous: false },
          ],
          contributors: [
            { name: 'T-882 auth failure', contribution: 0.62 },
            { name: 'T-901 token refresh retry', contribution: 0.21 },
            { name: 'session burst window', contribution: 0.17 },
          ],
        },
      },
      {
        kind: 'metrics',
        model: 'metrics-model',
        title: 'p99 latency anomaly',
        detail: 'checkout_request_duration_p99 rose from 180ms to 2.4s.',
        score: 0.88,
        timestamp: isoMinutesAgo(70),
        raw: {
          metric: 'checkout_request_duration_p99',
          observed: 2.4,
          expected: 0.18,
          expected_band: { low: 0.12, high: 0.35 },
          unit: 's',
          series: [
            { t: '-60m', observed: 0.17, expected: 0.18 },
            { t: '-45m', observed: 0.22, expected: 0.19 },
            { t: '-30m', observed: 0.9, expected: 0.18 },
            { t: '-15m', observed: 2.1, expected: 0.18 },
            { t: 'now', observed: 2.4, expected: 0.18 },
          ],
        },
      },
      {
        kind: 'network',
        model: 'network-model',
        title: 'Unusual egress destination',
        detail: 'Flows to 203.0.113.44:443 from host-checkout-03 (new peer).',
        score: 0.86,
        timestamp: isoMinutesAgo(55),
        raw: {
          dst: '203.0.113.44',
          bytes: 42000000,
          peers: [
            { peer: '203.0.113.44:443', role: 'destination', service: 'unknown-egress', contribution: 0.55 },
            { peer: 'host-checkout-03', role: 'source', service: 'checkout-api', contribution: 0.28 },
            { peer: 'dns:cdn.example.com', role: 'related', service: 'edge-proxy', contribution: 0.17 },
          ],
        },
      },
      {
        kind: 'code',
        model: 'code-model',
        title: 'Risky commit in auth path',
        detail: 'Commit a3f8c12 touched token refresh retry loop and timeout handling.',
        score: 0.72,
        timestamp: isoMinutesAgo(120),
        raw: {
          commit: 'a3f8c12',
          files: [
            { path: 'auth/refresh.go', line: 142, risk: 'retry storm' },
            { path: 'middleware/timeout.go', line: 58, risk: 'timeout widening' },
          ],
          advisory:
            'Code findings are advisory risk signals correlated to deployments; they are not proof of a vulnerability or exploit.',
        },
      },
      {
        kind: 'correlation',
        model: 'correlation-engine',
        title: 'Multi-model fusion',
        detail: 'Four modality findings share fingerprint fp-checkout-auth-egress.',
        score: 0.94,
        timestamp: isoMinutesAgo(50),
      },
    ],
    assigned_to: null,
    disposition: null,
    fingerprint: 'fp-checkout-auth-egress',
    context: {
      region: 'us-east-1',
      cluster: 'prod-a',
      site_id: 'us-east-1',
      mitre_techniques: ['T1071', 'T1048'],
      code_enrichment: {
        status: 'completed_degraded',
        cwe_ids: ['CWE-287'],
        human_review_required: true,
        model_ran: false,
        degraded: true,
        file_hits: [{ path: 'auth/refresh.go', cwe_ids: ['CWE-287'], title: 'Auth bypass lead' }],
        advisory: 'Antares results are file-level leads for human review only.',
      },
      threat_intel: {
        matched_indicators: [
          {
            id: 'ind-203-0-113-44',
            type: 'ipv4',
            value: '203.0.113.44',
            confidence: 85,
            source: 'lab-stix',
            tlp: 'amber',
            mitre_techniques: ['T1048'],
          },
        ],
        campaigns: ['lab-sample'],
        tlp: 'amber',
      },
    },
    models: ['log-model', 'metrics-model', 'network-model', 'code-model', 'correlation-engine'],
  },
  {
    incident_id: 'inc-01HZ9K8N3R',
    tenant_id: TENANT,
    title: 'Disk saturation foreshadow on payments-db',
    status: 'acknowledged',
    severity: 'high',
    risk_score: 0.81,
    category: ['capacity'],
    first_seen: isoMinutesAgo(240),
    last_seen: isoMinutesAgo(18),
    assets: ['rds-payments-primary'],
    services: ['payments-db', 'billing-worker'],
    deployment_id: null,
    commit: null,
    finding_ids: ['fnd-met-010', 'fnd-log-011'],
    summary:
      'Metrics model projects disk fill in ~6h; log model shows increasing WAL checkpoint warnings on payments-db.',
    evidence: [
      {
        kind: 'metrics',
        model: 'metrics-model',
        title: 'Disk fill forecast',
        detail: 'Free disk trending to <5% within 6 hours.',
        score: 0.84,
        timestamp: isoMinutesAgo(200),
      },
      {
        kind: 'logs',
        model: 'log-model',
        title: 'WAL checkpoint warnings',
        detail: 'checkpoint_warning template rising steadily.',
        score: 0.71,
        timestamp: isoMinutesAgo(180),
      },
      {
        kind: 'correlation',
        model: 'correlation-engine',
        title: 'Capacity correlation',
        detail: 'Metrics + logs fused for payments-db capacity risk.',
        score: 0.81,
        timestamp: isoMinutesAgo(170),
      },
    ],
    assigned_to: 'alex.ops',
    disposition: null,
    fingerprint: 'fp-payments-disk',
    context: { region: 'us-east-1' },
    models: ['metrics-model', 'log-model', 'correlation-engine'],
  },
  {
    incident_id: 'inc-01HZ9KB4P2',
    tenant_id: TENANT,
    title: 'Benign deploy noise on inventory-svc',
    status: 'investigating',
    severity: 'medium',
    risk_score: 0.58,
    category: ['change'],
    first_seen: isoMinutesAgo(40),
    last_seen: isoMinutesAgo(12),
    assets: ['pod-inventory-svc-2b1'],
    services: ['inventory-svc'],
    deployment_id: 'deploy-2026-07-26-18',
    commit: '91bc0ee',
    finding_ids: ['fnd-code-020', 'fnd-met-021'],
    summary:
      'Code and metrics findings after canary deploy; likely expected change pending confirmation.',
    evidence: [
      {
        kind: 'code',
        model: 'code-model',
        title: 'Schema migration in canary',
        detail: 'Migration alters inventory index rebuild path.',
        score: 0.55,
        timestamp: isoMinutesAgo(38),
      },
      {
        kind: 'metrics',
        model: 'metrics-model',
        title: 'Transient CPU spike',
        detail: 'CPU briefly 2.1x baseline during migration window.',
        score: 0.52,
        timestamp: isoMinutesAgo(30),
      },
    ],
    assigned_to: 'jamie.sre',
    disposition: null,
    fingerprint: 'fp-inventory-canary',
    context: { canary: true },
    models: ['code-model', 'metrics-model'],
  },
  {
    incident_id: 'inc-01HZ9KC1T8',
    tenant_id: TENANT,
    title: 'Resolved: DNS flap in edge-proxy',
    status: 'resolved',
    severity: 'low',
    risk_score: 0.34,
    category: ['network'],
    first_seen: isoMinutesAgo(1440),
    last_seen: isoMinutesAgo(900),
    assets: ['edge-proxy-01'],
    services: ['edge-proxy'],
    deployment_id: null,
    commit: null,
    finding_ids: ['fnd-net-030'],
    summary: 'Short-lived NXDOMAIN burst; auto-resolved after upstream DNS recovered.',
    evidence: [
      {
        kind: 'network',
        model: 'network-model',
        title: 'NXDOMAIN burst',
        detail: 'Brief elevation in failed DNS lookups for cdn.example.com.',
        score: 0.4,
        timestamp: isoMinutesAgo(1400),
      },
    ],
    assigned_to: 'alex.ops',
    disposition: 'benign_anomaly',
    fingerprint: 'fp-edge-dns',
    context: {},
    models: ['network-model'],
  },
]

const timelineStore = new Map<string, TimelineEntry[]>()
const commentStore = new Map<string, Comment[]>()

function seedTimeline(incident: Incident): TimelineEntry[] {
  const base: TimelineEntry[] = [
    {
      entry_id: `${incident.incident_id}-tl-1`,
      incident_id: incident.incident_id,
      tenant_id: TENANT,
      event_type: 'created',
      detail: { title: incident.title, severity: incident.severity },
      actor: 'correlation-engine',
      created_at: incident.first_seen,
    },
  ]
  for (const [i, ev] of incident.evidence.entries()) {
    base.push({
      entry_id: `${incident.incident_id}-tl-ev-${i}`,
      incident_id: incident.incident_id,
      tenant_id: TENANT,
      event_type: 'evidence',
      detail: { kind: ev.kind, model: ev.model, title: ev.title },
      actor: ev.model,
      created_at: ev.timestamp,
    })
  }
  if (incident.assigned_to) {
    base.push({
      entry_id: `${incident.incident_id}-tl-assign`,
      incident_id: incident.incident_id,
      tenant_id: TENANT,
      event_type: 'assigned',
      detail: { assigned_to: incident.assigned_to },
      actor: 'system',
      created_at: incident.last_seen,
    })
  }
  if (incident.status === 'resolved' || incident.disposition) {
    base.push({
      entry_id: `${incident.incident_id}-tl-res`,
      incident_id: incident.incident_id,
      tenant_id: TENANT,
      event_type: incident.disposition ? 'disposition' : 'status_change',
      detail: {
        status: incident.status,
        disposition: incident.disposition,
      },
      actor: incident.assigned_to ?? 'system',
      created_at: incident.last_seen,
    })
  }
  return base.sort((a, b) => a.created_at.localeCompare(b.created_at))
}

for (const incident of incidents) {
  timelineStore.set(incident.incident_id, seedTimeline(incident))
  commentStore.set(incident.incident_id, [])
}

export const findings: Finding[] = [
  {
    finding_id: 'fnd-log-001',
    model: 'log-model',
    kind: 'logs',
    severity: 'critical',
    risk_score: 0.91,
    title: 'Auth failure burst',
    asset_id: 'pod-checkout-api-7f2',
    service: 'checkout-api',
    first_seen: isoMinutesAgo(90),
    last_seen: isoMinutesAgo(4),
    incident_id: 'inc-01HZ9K2M7Q',
    summary: 'Template T-882 spiked 18x vs baseline.',
  },
  {
    finding_id: 'fnd-net-002',
    model: 'network-model',
    kind: 'network',
    severity: 'high',
    risk_score: 0.86,
    title: 'Unusual egress destination',
    asset_id: 'host-checkout-03',
    service: 'checkout-api',
    first_seen: isoMinutesAgo(55),
    last_seen: isoMinutesAgo(8),
    incident_id: 'inc-01HZ9K2M7Q',
    summary: 'Flows to new peer 203.0.113.44:443.',
  },
  {
    finding_id: 'fnd-met-003',
    model: 'metrics-model',
    kind: 'metrics',
    severity: 'high',
    risk_score: 0.88,
    title: 'p99 latency anomaly',
    asset_id: 'pod-checkout-api-7f2',
    service: 'checkout-api',
    first_seen: isoMinutesAgo(70),
    last_seen: isoMinutesAgo(6),
    incident_id: 'inc-01HZ9K2M7Q',
    summary: 'p99 climbed to 2.4s.',
  },
  {
    finding_id: 'fnd-code-004',
    model: 'code-model',
    kind: 'code',
    severity: 'medium',
    risk_score: 0.72,
    title: 'Risky commit in auth path',
    asset_id: 'repo-checkout-api',
    service: 'checkout-api',
    first_seen: isoMinutesAgo(120),
    last_seen: isoMinutesAgo(120),
    incident_id: 'inc-01HZ9K2M7Q',
    summary: 'Token refresh retry loop changed in a3f8c12.',
    cwe_ids: ['CWE-287'],
    enrichment: {
      status: 'completed_degraded',
      cwe_ids: ['CWE-287'],
      human_review_required: true,
      model_ran: false,
      degraded: true,
      file_hits: [{ path: 'auth/refresh.go', cwe_ids: ['CWE-287'], title: 'Auth bypass lead' }],
      advisory: 'Antares results are file-level leads for human review only.',
    },
  },
  {
    finding_id: 'fnd-met-010',
    model: 'metrics-model',
    kind: 'metrics',
    severity: 'high',
    risk_score: 0.84,
    title: 'Disk fill forecast',
    asset_id: 'rds-payments-primary',
    service: 'payments-db',
    first_seen: isoMinutesAgo(200),
    last_seen: isoMinutesAgo(18),
    incident_id: 'inc-01HZ9K8N3R',
    summary: 'Free disk trending to <5% within 6 hours.',
  },
  {
    finding_id: 'fnd-log-011',
    model: 'log-model',
    kind: 'logs',
    severity: 'medium',
    risk_score: 0.71,
    title: 'WAL checkpoint warnings',
    asset_id: 'rds-payments-primary',
    service: 'payments-db',
    first_seen: isoMinutesAgo(180),
    last_seen: isoMinutesAgo(20),
    incident_id: 'inc-01HZ9K8N3R',
    summary: 'checkpoint_warning template rising.',
  },
  {
    finding_id: 'fnd-code-020',
    model: 'code-model',
    kind: 'code',
    severity: 'medium',
    risk_score: 0.55,
    title: 'Schema migration in canary',
    asset_id: 'repo-inventory-svc',
    service: 'inventory-svc',
    first_seen: isoMinutesAgo(38),
    last_seen: isoMinutesAgo(38),
    incident_id: 'inc-01HZ9KB4P2',
    summary: 'Index rebuild path altered.',
  },
  {
    finding_id: 'fnd-met-021',
    model: 'metrics-model',
    kind: 'metrics',
    severity: 'medium',
    risk_score: 0.52,
    title: 'Transient CPU spike',
    asset_id: 'pod-inventory-svc-2b1',
    service: 'inventory-svc',
    first_seen: isoMinutesAgo(30),
    last_seen: isoMinutesAgo(12),
    incident_id: 'inc-01HZ9KB4P2',
    summary: 'CPU briefly 2.1x baseline.',
  },
  {
    finding_id: 'fnd-net-030',
    model: 'network-model',
    kind: 'network',
    severity: 'low',
    risk_score: 0.4,
    title: 'NXDOMAIN burst',
    asset_id: 'edge-proxy-01',
    service: 'edge-proxy',
    first_seen: isoMinutesAgo(1400),
    last_seen: isoMinutesAgo(900),
    incident_id: 'inc-01HZ9KC1T8',
    summary: 'Short-lived DNS failures for cdn.example.com.',
  },
]

export const assets: Asset[] = [
  {
    asset_id: 'host-checkout-03',
    name: 'host-checkout-03',
    kind: 'host',
    environment: 'prod',
    owner: 'payments-team',
    services: ['checkout-api'],
    last_seen: isoMinutesAgo(2),
    status: 'degraded',
  },
  {
    asset_id: 'pod-checkout-api-7f2',
    name: 'checkout-api-7f2',
    kind: 'pod',
    environment: 'prod',
    owner: 'payments-team',
    services: ['checkout-api'],
    last_seen: isoMinutesAgo(1),
    status: 'degraded',
  },
  {
    asset_id: 'rds-payments-primary',
    name: 'payments-db-primary',
    kind: 'database',
    environment: 'prod',
    owner: 'data-platform',
    services: ['payments-db'],
    last_seen: isoMinutesAgo(3),
    status: 'degraded',
  },
  {
    asset_id: 'pod-inventory-svc-2b1',
    name: 'inventory-svc-2b1',
    kind: 'pod',
    environment: 'prod',
    owner: 'catalog-team',
    services: ['inventory-svc'],
    last_seen: isoMinutesAgo(5),
    status: 'healthy',
  },
  {
    asset_id: 'edge-proxy-01',
    name: 'edge-proxy-01',
    kind: 'host',
    environment: 'prod',
    owner: 'edge-team',
    services: ['edge-proxy'],
    last_seen: isoMinutesAgo(1),
    status: 'healthy',
  },
]

export const models: ModelInfo[] = [
  {
    model_id: 'log-model',
    name: 'Log Anomaly Model',
    modality: 'logs',
    version: '1.4.2',
    status: 'ready',
    last_inference: isoMinutesAgo(1),
    findings_24h: 42,
    avg_latency_ms: 38,
  },
  {
    model_id: 'metrics-model',
    name: 'Metrics Anomaly Model',
    modality: 'metrics',
    version: '2.1.0',
    status: 'ready',
    last_inference: isoMinutesAgo(1),
    findings_24h: 31,
    avg_latency_ms: 22,
  },
  {
    model_id: 'network-model',
    name: 'Network Flow Model',
    modality: 'network',
    version: '1.2.5',
    status: 'ready',
    last_inference: isoMinutesAgo(2),
    findings_24h: 17,
    avg_latency_ms: 45,
  },
  {
    model_id: 'code-model',
    name: 'Code Change Risk Model',
    modality: 'code',
    version: '0.9.1',
    status: 'degraded',
    last_inference: isoMinutesAgo(15),
    findings_24h: 8,
    avg_latency_ms: 120,
  },
  {
    model_id: 'correlation-engine',
    name: 'Correlation Engine',
    modality: 'correlation',
    version: '0.3.0',
    status: 'ready',
    last_inference: isoMinutesAgo(3),
    findings_24h: 6,
    avg_latency_ms: 12,
  },
]

export const dataHealth: DataHealthSource[] = [
  {
    source_id: 'src-logs',
    name: 'logs.raw',
    modality: 'logs',
    lag_seconds: 12,
    lag_records: 12,
    events_per_min: 18400,
    status: 'ok',
    last_event: isoMinutesAgo(0.2),
  },
  {
    source_id: 'src-metrics',
    name: 'metrics.samples',
    modality: 'metrics',
    lag_seconds: 45,
    lag_records: 45,
    events_per_min: 9200,
    status: 'ok',
    last_event: isoMinutesAgo(0.5),
  },
  {
    source_id: 'src-flows',
    name: 'network.flows',
    modality: 'network',
    lag_seconds: 180,
    lag_records: 180,
    events_per_min: 4100,
    status: 'lagging',
    last_event: isoMinutesAgo(3),
  },
  {
    source_id: 'src-code',
    name: 'code.events',
    modality: 'code',
    lag_seconds: 920,
    lag_records: 920,
    events_per_min: 12,
    status: 'stale',
    last_event: isoMinutesAgo(15),
  },
  {
    source_id: 'src-threat-intel',
    name: 'threat-intel-service',
    modality: 'threat-intel',
    lag_seconds: 30,
    lag_records: 30,
    events_per_min: 0,
    status: 'ok',
    last_event: isoMinutesAgo(5),
  },
]

export const threatIntelFeeds: ThreatIntelFeedHealth[] = [
  {
    feed_name: 'cisa-kev',
    last_sync_at: isoMinutesAgo(60),
    last_status: 'ok',
    last_error: null,
    indicator_count: 1240,
  },
  {
    feed_name: 'taxii-demo',
    last_sync_at: isoMinutesAgo(15),
    last_status: 'ok',
    last_error: null,
    indicator_count: 86,
  },
  {
    feed_name: 'misp',
    last_sync_at: isoMinutesAgo(120),
    last_status: 'skipped',
    last_error: 'MISP_URL unset',
    indicator_count: 0,
  },
]

const securityPacks: SecurityPack[] = [
  {
    pack_id: 'cis-v8-ig1',
    kind: 'framework',
    version: '1.0',
    title: 'CIS Controls v8 IG1',
    description: 'Implementation Group 1 baseline',
    check_count: 2,
    checks: [
      {
        check_id: 'cis.v8.8.audit-log-management',
        title: 'Audit log management',
        surfaces: ['host', 'network'],
        automation: 'auto',
        mitre_techniques: ['T1070'],
      },
      {
        check_id: 'cis.v8.5.account-management',
        title: 'Account management',
        surfaces: ['identity'],
        automation: 'hybrid',
      },
    ],
  },
  {
    pack_id: 'pci-dss-4',
    kind: 'framework',
    version: '1.0',
    title: 'PCI DSS 4.0',
    check_count: 1,
    checks: [
      {
        check_id: 'pci.1.cde-segmentation',
        title: 'CDE network segmentation',
        surfaces: ['network'],
        automation: 'auto',
      },
    ],
  },
  {
    pack_id: 'hipaa',
    kind: 'industry',
    version: '1.0',
    title: 'HIPAA Security Rule',
    check_count: 1,
    checks: [
      {
        check_id: 'hipaa.access-control',
        title: 'ePHI access control',
        surfaces: ['identity', 'host'],
        automation: 'manual',
      },
    ],
  },
  {
    pack_id: 'mitre-attack-core',
    kind: 'framework',
    version: '1.0',
    title: 'MITRE ATT&CK core',
    check_count: 1,
    checks: [
      {
        check_id: 'attack.t1059',
        title: 'Command and scripting interpreter coverage',
        surfaces: ['host'],
        automation: 'auto',
        mitre_techniques: ['T1059'],
      },
    ],
  },
]

const securityPresets: SecurityPreset[] = [
  {
    id: 'baseline-smb',
    name: 'Baseline SMB',
    packs: ['cis-v8-ig1', 'mitre-attack-core'],
    description: 'Small business CIS + ATT&CK core',
  },
  {
    id: 'payment',
    name: 'Payment',
    packs: ['cis-v8-ig1', 'pci-dss-4'],
    description: 'PCI-oriented merchant profile',
  },
  {
    id: 'healthcare',
    name: 'Healthcare',
    packs: ['cis-v8-ig1', 'hipaa'],
    description: 'HIPAA additive on CIS baseline',
  },
]

let securityProfiles: SecurityProfile[] = [
  {
    profile_id: 'spf-mock-baseline',
    tenant_id: TENANT,
    name: 'Lab CIS baseline',
    selected_packs: ['cis-v8-ig1', 'mitre-attack-core'],
    asset_scope: [],
    enabled_surfaces: ['network', 'host', 'identity', 'code'],
    schedule: 'on_demand',
    strictness: 'baseline',
    merge_policy: 'union_strictest',
    active: true,
    preview: { auto_count: 2, manual_count: 0, hybrid_count: 1 },
  },
]

function cloneIncident(incident: Incident): Incident {
  return {
    ...incident,
    category: [...incident.category],
    assets: [...incident.assets],
    services: [...incident.services],
    finding_ids: [...incident.finding_ids],
    evidence: incident.evidence.map((e) => ({ ...e, raw: e.raw ? { ...e.raw } : undefined })),
    context: { ...incident.context },
    models: [...incident.models],
  }
}

function pushTimeline(
  incidentId: string,
  event_type: string,
  detail: Record<string, unknown>,
  actor: string | null,
): void {
  const list = timelineStore.get(incidentId) ?? []
  list.push({
    entry_id: `${incidentId}-tl-${Date.now()}-${list.length}`,
    incident_id: incidentId,
    tenant_id: TENANT,
    event_type,
    detail,
    actor,
    created_at: new Date().toISOString(),
  })
  timelineStore.set(incidentId, list)
}

export const mockApi = {
  listIncidents(): Incident[] {
    return incidents.map(cloneIncident)
  },

  getIncident(id: string): Incident | undefined {
    const found = incidents.find((i) => i.incident_id === id)
    return found ? cloneIncident(found) : undefined
  },

  getTimeline(id: string): TimelineEntry[] {
    return (timelineStore.get(id) ?? []).map((e) => ({ ...e, detail: { ...e.detail } }))
  },

  getComments(id: string): Comment[] {
    return (commentStore.get(id) ?? []).map((c) => ({ ...c }))
  },

  acknowledge(id: string, actor: string | null): Incident | undefined {
    const row = incidents.find((i) => i.incident_id === id)
    if (!row) return undefined
    row.status = 'acknowledged'
    row.last_seen = new Date().toISOString()
    pushTimeline(id, 'status_change', { status: 'acknowledged' }, actor)
    return cloneIncident(row)
  },

  assign(id: string, assigned_to: string, actor: string | null): Incident | undefined {
    const row = incidents.find((i) => i.incident_id === id)
    if (!row) return undefined
    row.assigned_to = assigned_to
    if (row.status === 'open') row.status = 'acknowledged'
    row.last_seen = new Date().toISOString()
    pushTimeline(id, 'assigned', { assigned_to }, actor)
    return cloneIncident(row)
  },

  comment(id: string, author: string, body: string): Comment | undefined {
    if (!incidents.some((i) => i.incident_id === id)) return undefined
    const comment: Comment = {
      comment_id: `cmt-${Date.now()}`,
      incident_id: id,
      tenant_id: TENANT,
      author,
      body,
      created_at: new Date().toISOString(),
    }
    const list = commentStore.get(id) ?? []
    list.push(comment)
    commentStore.set(id, list)
    pushTimeline(id, 'comment', { author, body }, author)
    return { ...comment }
  },

  disposition(
    id: string,
    disposition: IncidentDisposition,
    actor: string | null,
    note?: string,
  ): Incident | undefined {
    const row = incidents.find((i) => i.incident_id === id)
    if (!row) return undefined
    row.disposition = disposition
    row.last_seen = new Date().toISOString()
    pushTimeline(id, 'disposition', { disposition, note: note ?? null }, actor)
    return cloneIncident(row)
  },

  resolve(id: string, actor: string | null): Incident | undefined {
    const row = incidents.find((i) => i.incident_id === id)
    if (!row) return undefined
    row.status = 'resolved'
    row.last_seen = new Date().toISOString()
    pushTimeline(id, 'status_change', { status: 'resolved' }, actor)
    return cloneIncident(row)
  },

  listFindings(): Finding[] {
    return findings.map((f) => ({ ...f }))
  },

  listAssets(): Asset[] {
    return assets.map((a) => ({ ...a, services: [...a.services] }))
  },

  getAsset(id: string): Asset | undefined {
    const a = assets.find((x) => x.asset_id === id)
    return a ? { ...a, services: [...a.services] } : undefined
  },

  listModels(): ModelInfo[] {
    return models.map((m) => ({ ...m }))
  },

  getModel(id: string): ModelInfo | undefined {
    const m = models.find((x) => x.model_id === id)
    return m ? { ...m } : undefined
  },

  listDataHealth(): DataHealthSource[] {
    return dataHealth.map((d) => ({ ...d }))
  },

  listThreatIntelFeeds(): ThreatIntelFeedHealth[] {
    return threatIntelFeeds.map((f) => ({ ...f }))
  },

  analyzeMalware(input: {
    sha256?: string
    file_name?: string
    content_base64?: string
  }): MalwareReport {
    const sha =
      input.sha256 ||
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    const hasPe = Boolean(input.content_base64)
    return {
      finding_type: 'malware_analysis',
      sample: {
        sha256: sha,
        file_type: hasPe ? 'pe' : 'unknown',
        names: input.file_name ? [input.file_name] : ['sample.bin'],
        size_bytes: hasPe ? 128 : 0,
      },
      scores: {
        static_heuristic: null,
        static_ember: hasPe ? 0.62 : 0.12,
        sandbox_score: null,
        clamav: hasPe ? 'OK' : null,
      },
      yara: hasPe
        ? [{ rule: 'Suspicious_PE_MZ', tags: ['pe'], engine: 'python-yara' }]
        : [],
      capabilities: hasPe
        ? [
            {
              name: 'allocate memory',
              'att&ck': ['T1055'],
              source: 'capa',
              engine: 'capa',
            },
          ]
        : [],
      mitre_techniques: hasPe ? ['T1055'] : [],
      strings_sample: hasPe ? ['VirtualAlloc', 'http://example.test'] : [],
      analysis: {
        static_scorer: 'ember',
        ember: true,
        yara_engine: 'python-yara',
        capabilities_engine: 'capa',
        strings_engine: 'floss',
        clamav: true,
      },
      stage: 'static',
      network: { dns: [], hosts: [], pcap_uri: null },
    }
  },

  queueMalwareSandbox(input: {
    sha256: string
    file_name?: string
    machine_profile?: string
  }): string {
    return `Queued ${input.sha256.slice(0, 12)}… for ${input.machine_profile ?? 'win10-office'} (mock)`
  },

  listSecurityPacks(): { items: SecurityPack[]; presets: SecurityPreset[] } {
    return {
      items: securityPacks.map((p) => ({ ...p, checks: p.checks.map((c) => ({ ...c })) })),
      presets: securityPresets.map((p) => ({ ...p, packs: [...p.packs] })),
    }
  },

  listSecurityProfiles(): SecurityProfile[] {
    return securityProfiles.map((p) => ({
      ...p,
      selected_packs: [...p.selected_packs],
      enabled_surfaces: [...p.enabled_surfaces],
    }))
  },

  createSecurityProfile(input: {
    name: string
    selected_packs: string[]
    enabled_surfaces?: string[]
  }): SecurityProfile {
    const profile: SecurityProfile = {
      profile_id: `spf-mock-${Date.now()}`,
      tenant_id: TENANT,
      name: input.name,
      selected_packs: [...input.selected_packs],
      asset_scope: [],
      enabled_surfaces: input.enabled_surfaces ?? ['network', 'host', 'code', 'identity'],
      schedule: 'on_demand',
      strictness: 'baseline',
      merge_policy: 'union_strictest',
      active: true,
      preview: {
        auto_count: input.selected_packs.length,
        manual_count: 2,
        hybrid_count: 1,
        checks: securityPacks
          .filter((p) => input.selected_packs.includes(p.pack_id))
          .flatMap((p) => p.checks),
      },
    }
    securityProfiles = [profile, ...securityProfiles]
    return { ...profile, selected_packs: [...profile.selected_packs] }
  },

  getSecurityProfileCoverage(profileId: string): ProfileCoverage {
    const profile = securityProfiles.find((p) => p.profile_id === profileId)
    const checks = securityPacks
      .filter((p) => (profile?.selected_packs ?? ['cis-v8-ig1']).includes(p.pack_id))
      .flatMap((p) =>
        p.checks.map((c, i) => ({
          check_id: c.check_id,
          title: c.title,
          status: (i % 4 === 0 ? 'pass' : i % 4 === 1 ? 'fail' : i % 4 === 2 ? 'attested' : 'unknown') as ProfileCheckStatus,
          automation: c.automation,
          surfaces: [...c.surfaces],
          reason: i % 4 === 3 ? 'telemetry_missing' : undefined,
        })),
      )
    const summary: Record<string, number> = { pass: 0, fail: 0, attested: 0, unknown: 0 }
    for (const c of checks) summary[c.status] = (summary[c.status] ?? 0) + 1
    return { profile_id: profileId, checks, summary }
  },

  attestSecurityCheck(
    profileId: string,
    checkId: string,
    note?: string,
  ): { attestation_id: string; check_id: string; note?: string } {
    return {
      attestation_id: `att-${Date.now()}`,
      check_id: checkId,
      note: note ?? `Attested on ${profileId}`,
    }
  },

  generateCertificationPackage(
    profileId: string,
    target: string,
  ): { package_id: string; target: string; disclaimer: string; control_count: number } {
    return {
      package_id: `cert-${profileId}-${target}`,
      target,
      disclaimer:
        'Evidence assistance only — this package is not a SOC 2 / PCI / CMMC certificate.',
      control_count: 12,
    }
  },

  listSimilarFindings(_findingId: string): SimilarHit[] {
    return [
      {
        id: 'finding-log-2',
        title: 'Similar log burst pattern',
        score: 0.91,
        source: 'qdrant',
        summary: 'Neighbor finding via SecureBERT dense search (mock)',
      },
    ]
  },

  federatedHunt(q: string): FederatedHuntResult {
    const base = this.listFindings()
      .filter((f) => !q || f.title.toLowerCase().includes(q.toLowerCase()))
      .slice(0, 5)
      .map((f) => ({
        source: 'opensearch' as const,
        id: f.finding_id,
        title: f.title,
        score: 1,
        summary: f.summary,
      }))
    return {
      hits: [
        ...base,
        {
          source: 'qdrant',
          id: 'vec-1',
          title: 'Vector neighbor: lateral movement narrative',
          score: 0.88,
          summary: q || 'example',
        },
        {
          source: 'ti_exact',
          id: 'ti-1',
          title: 'Exact IOC match',
          score: 1,
          summary: '192.0.2.10',
        },
      ],
      warnings: [],
    }
  },

  huntVector(q: string): VectorHuntResult {
    const needle = q.trim().toLowerCase()
    const hits = this.listFindings()
      .filter((f) => !needle || `${f.title} ${f.summary} ${f.asset_id}`.toLowerCase().includes(needle))
      .slice(0, 8)
      .map((f, i) => ({
        source: 'qdrant',
        id: f.finding_id,
        title: f.title,
        score: Math.max(0.5, 0.95 - i * 0.05),
        summary: f.summary,
      }))
    return {
      status: 'ready',
      capability: 'vector_search',
      reason: 'mock',
      hits,
    }
  },

  getRunbookSuggestions(_incidentId: string): { items: { title: string; score: number; path: string }[] } {
    return {
      items: [
        { title: 'Isolate host playbook', score: 0.86, path: 'docs/operations/runbooks/isolate-host.md' },
        { title: 'TI enrichment checklist', score: 0.71, path: 'docs/operations/runbooks/ti-enrich.md' },
      ],
    }
  },
}

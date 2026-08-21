import { GalleryTile } from "./types";

/**
 * Hand-maintained gallery view-model for every built-in Black Onyx route.
 *
 * Kept in sync with `navigationGroups` and the admin-only Control section in
 * web/src/main.tsx by hand, not derived from them at runtime: those tuples
 * are `[label, path, glyph]` and don't carry the section/subtitle/preview
 * metadata a tile needs, and unifying the two shapes isn't worth the churn
 * for ~23 rows. When a new page is added to the app, add its tile here too.
 *
 * Role visibility is NOT set per-tile here — GalleryHub filters this list
 * through rbac.ts's `visibleFor(role, tile.href)`, the same predicate the
 * classic sidebar nav uses, so there is exactly one place role-gating is
 * decided. (An earlier revision carried a redundant `roles` field on each
 * tile that nothing ever read; don't reintroduce it.)
 */
export const BUILTIN_TILES: GalleryTile[] = [
  {
    id: "route:/dashboard", kind: "builtin", href: "/dashboard", section: "operations",
    title: "Dashboard", subtitle: "Collection, ingestion, and vector health at a glance.",
    glyph: "OV", preview: "metric",
  },
  {
    id: "route:/analytics", kind: "builtin", href: "/analytics", section: "operations",
    title: "Analytics", subtitle: "Disposition-aware MTTA/MTTR/FPR and ATT&CK sightings.",
    glyph: "AN", preview: "metric",
  },
  {
    id: "route:/trends", kind: "builtin", href: "/trends", section: "operations",
    title: "Trends", subtitle: "Cross-source movement, actor heuristics, and news desks.",
    glyph: "TR", preview: "metric",
  },
  {
    id: "route:/jobs", kind: "builtin", href: "/jobs", section: "operations",
    title: "Jobs", subtitle: "Active and recent ingestion jobs.",
    glyph: "JB", preview: "metric",
  },
  {
    id: "route:/ingest", kind: "builtin", href: "/ingest", section: "investigate",
    title: "Ingest", subtitle: "Import files or a directory tree into a collection.",
    glyph: "IN", preview: "metric",
  },
  {
    id: "route:/search", kind: "builtin", href: "/search", section: "investigate",
    title: "Search", subtitle: "Semantic search across indexed evidence.",
    glyph: "SE", preview: "list",
  },
  {
    id: "route:/query", kind: "builtin", href: "/query", section: "investigate",
    title: "Query", subtitle: "KQL/SPL-style filters over alerts, cases, and evidence.",
    glyph: "QY", preview: "list",
  },
  {
    id: "route:/image-search", kind: "builtin", href: "/image-search", section: "investigate",
    title: "Image search", subtitle: "Image-to-image search over ingested evidence.",
    glyph: "IM", preview: "list",
  },
  {
    id: "route:/collections", kind: "builtin", href: "/collections", section: "investigate",
    title: "Collections", subtitle: "Browse and manage vector store collections.",
    glyph: "CO", preview: "metric",
  },
  {
    id: "route:/chat", kind: "builtin", href: "/chat", section: "investigate",
    title: "Chat", subtitle: "RAG analyst chat sessions.",
    glyph: "CH", preview: "metric",
  },
  {
    id: "route:/iocs", kind: "builtin", href: "/iocs", section: "intelligence",
    title: "IOC workbench", subtitle: "Extract, enrich, and score indicators.",
    glyph: "IO", preview: "list",
  },
  {
    id: "route:/attack", kind: "builtin", href: "/attack", section: "intelligence",
    title: "ATT&CK", subtitle: "MITRE ATT&CK technique mapping and heatmap.",
    glyph: "AT", preview: "color",
  },
  {
    id: "route:/graph", kind: "builtin", href: "/graph", section: "intelligence",
    title: "Graph", subtitle: "Entity relationship graph over indexed evidence.",
    glyph: "GR", preview: "metric",
  },
  {
    id: "route:/rules", kind: "builtin", href: "/rules", section: "intelligence",
    title: "Rules", subtitle: "Generate Sigma and YARA detection rules.",
    glyph: "RU", preview: "list",
  },
  {
    id: "route:/reports", kind: "builtin", href: "/reports", section: "intelligence",
    title: "Reports", subtitle: "Generated intelligence reports.",
    glyph: "RE", preview: "metric",
  },
  {
    id: "route:/content", kind: "builtin", href: "/content", section: "intelligence",
    title: "Content", subtitle: "Reports library, digests, and playbook docs.",
    glyph: "CT", preview: "list",
  },
  {
    id: "route:/triage", kind: "builtin", href: "/triage", section: "operations",
    title: "Triage", subtitle: "Unified alerts and connector detections queue.",
    glyph: "TQ", preview: "metric",
  },
  {
    id: "route:/cases", kind: "builtin", href: "/cases", section: "operations",
    title: "Cases", subtitle: "Investigation cases, notes, and timelines.",
    glyph: "CA", preview: "metric",
  },
  {
    id: "route:/watchlists", kind: "builtin", href: "/watchlists", section: "operations",
    title: "Watchlists", subtitle: "Monitored indicators and alerts.",
    glyph: "WA", preview: "metric",
  },
  {
    id: "route:/assets", kind: "builtin", href: "/assets", section: "operations",
    title: "Assets", subtitle: "CMDB inventory and posture findings.",
    glyph: "AS", preview: "metric",
  },
  {
    id: "route:/feeds", kind: "builtin", href: "/feeds", section: "operations",
    title: "Feeds", subtitle: "RSS, Atom, TAXII, and webhook ingestion sources.",
    glyph: "FE", preview: "metric",
  },
  {
    id: "route:/detections", kind: "builtin", href: "/detections", section: "operations",
    title: "Detections", subtitle: "Pull-based SIEM/EDR connectors and what they've pulled in.",
    glyph: "DT", preview: "metric",
  },
  {
    id: "route:/detection", kind: "builtin", href: "/detection", section: "operations",
    title: "Detection overview", subtitle: "Streaming anomaly spine — correlated incidents and modality health.",
    glyph: "DX", preview: "metric",
  },
  {
    id: "route:/detection-services", kind: "builtin", href: "/detection-services", section: "operations",
    title: "Detection services", subtitle: "Service health, ownership, and dependency status.",
    glyph: "DS", preview: "metric",
  },
  {
    id: "route:/data-health", kind: "builtin", href: "/data-health", section: "operations",
    title: "Data health", subtitle: "Ingestion and modality freshness across the detection spine.",
    glyph: "DH", preview: "metric",
  },
  {
    id: "route:/models", kind: "builtin", href: "/models", section: "operations",
    title: "Models", subtitle: "Model readiness, versions, drift, and training operations.",
    glyph: "ML", preview: "list",
  },
  {
    id: "route:/attack-coverage", kind: "builtin", href: "/attack-coverage", section: "intelligence",
    title: "ATT&CK coverage", subtitle: "Detection coverage mapped to ATT&CK techniques.",
    glyph: "AC", preview: "color",
  },
  {
    id: "route:/detection/metrics", kind: "builtin", href: "/detection/metrics", section: "operations",
    title: "Metrics detection", subtitle: "Metric anomalies and contributing evidence.",
    glyph: "MT", preview: "metric",
  },
  {
    id: "route:/detection/network", kind: "builtin", href: "/detection/network", section: "operations",
    title: "Network detection", subtitle: "Network topology and anomaly findings.",
    glyph: "NW", preview: "list",
  },
  {
    id: "route:/detection/code-changes", kind: "builtin", href: "/detection/code-changes", section: "operations",
    title: "Code changes", subtitle: "Scanner findings and code-change risk evidence.",
    glyph: "CD", preview: "list",
  },
  {
    id: "route:/incidents", kind: "builtin", href: "/incidents", section: "operations",
    title: "Incidents", subtitle: "Correlated multi-model incidents from the detection plane.",
    glyph: "IC", preview: "list",
  },
  {
    id: "route:/findings", kind: "builtin", href: "/findings", section: "operations",
    title: "Findings", subtitle: "Raw modality findings before and after correlation.",
    glyph: "FD", preview: "list",
  },
  {
    id: "route:/hunt", kind: "builtin", href: "/hunt", section: "investigate",
    title: "Hunt", subtitle: "Federated OpenSearch and vector hunt over findings and incidents.",
    glyph: "HU", preview: "list",
  },
  {
    id: "route:/response-queue", kind: "builtin", href: "/response-queue", section: "operations",
    title: "Response queue", subtitle: "SOAR approvals before automated containment actions.",
    glyph: "RQ", preview: "list",
  },
  {
    id: "route:/malware", kind: "builtin", href: "/malware", section: "operations",
    title: "Malware", subtitle: "Malware triage and external lab detonation status.",
    glyph: "MW", preview: "metric",
  },
  {
    id: "route:/security-profiles", kind: "builtin", href: "/security-profiles", section: "operations",
    title: "Security profiles", subtitle: "Continuous compliance packs, coverage, and exceptions.",
    glyph: "SP", preview: "metric",
  },
  {
    id: "route:/playbooks", kind: "builtin", href: "/playbooks", section: "operations",
    title: "Playbooks", subtitle: "Automated response playbooks.",
    glyph: "PB", preview: "list",
  },
  {
    id: "route:/publishing", kind: "builtin", href: "/publishing", section: "operations",
    title: "Publishing", subtitle: "MISP and TAXII publishing integrations.",
    glyph: "TX", preview: "list",
  },
  {
    id: "route:/decay", kind: "builtin", href: "/decay", section: "operations",
    title: "Decay", subtitle: "IOC freshness and confidence decay.",
    glyph: "DE", preview: "metric",
  },
  {
    id: "route:/bookmarks", kind: "builtin", href: "/bookmarks", section: "operations",
    title: "Bookmarks", subtitle: "Your saved investigation points.",
    glyph: "BO", preview: "metric",
  },
  {
    id: "route:/system", kind: "builtin", href: "/system", section: "operations",
    title: "System", subtitle: "Configured providers and capability flags.",
    glyph: "SY", preview: "metric",
  },
  {
    id: "route:/profile", kind: "builtin", href: "/profile", section: "operations",
    title: "Profile", subtitle: "Password and MFA settings for your account.",
    glyph: "PR", preview: "color",
  },
  {
    id: "route:/admin", kind: "builtin", href: "/admin", section: "control",
    title: "Administration", subtitle: "Users, invitations, and audit trail.",
    glyph: "AD", preview: "metric",
  },
  {
    id: "route:/settings", kind: "builtin", href: "/settings", section: "control",
    title: "Settings", subtitle: "Provider, ingestion, and enrichment configuration.",
    glyph: "ST", preview: "metric",
  },
];

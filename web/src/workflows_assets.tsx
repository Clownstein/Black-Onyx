import React, { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useToast } from "./components/toast";
import { Donut } from "./components/charts";
import { OpsSurfaceKpis } from "./components/ops_kpis";
import { useUser } from "./user_context";
import { isOperational } from "./rbac";
import { DataTable, EmptyState, ErrorState, Heading, formatWhen, humanizeLabel } from "./ui";

export function AssetsWorkflow() {
  const user = useUser();
  const toast = useToast();
  const qc = useQueryClient();
  const [selected, setSelected] = useState<any | null>(null);
  const [form, setForm] = useState({ hostname: "", ip_address: "", notes: "", asset_type: "host", criticality: "medium", tags: "" });
  const [csv, setCsv] = useState("");
  const [caseId, setCaseId] = useState("");

  const assets = useQuery({
    queryKey: ["assets"],
    // Active inventory comes from the registry; SQLite rows are migration candidates only.
    queryFn: () => api<{ assets: any[]; sor: "asset_registry"; n: number; legacy_candidates: any[]; legacy_n: number }>("/assets"),
  });
  const posture = useQuery({
    queryKey: ["assets-posture"],
    queryFn: () => api<any>("/assets/posture/board"),
  });
  const detail = useQuery({
    queryKey: ["asset-detail", selected?.asset_id],
    queryFn: () => api<{
      findings: any[];
      case_links?: any[];
      related_alerts?: any[];
      related_detections?: any[];
      related_iocs?: any[];
    }>(`/assets/${selected.asset_id}`),
    enabled: Boolean(selected?.asset_id),
  });

  const create = useMutation({
    mutationFn: async () => {
      const hostname = form.hostname.trim();
      const tags = form.tags.split(",").map((t) => t.trim()).filter(Boolean);
      return api("/assets", { method: "POST", body: JSON.stringify({
        hostname,
        asset_type: form.asset_type,
        criticality: form.criticality,
        tags,
        ip_address: form.ip_address.trim() || undefined,
        notes: form.notes.trim() || undefined,
      }) });
    },
    onSuccess: () => {
      toast.push("Asset created in Postgres asset registry", "ok");
      setForm({ hostname: "", ip_address: "", notes: "", asset_type: "host", criticality: "medium", tags: "" });
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (err) => toast.push(err instanceof Error ? err.message : "Create failed", "bad"),
  });

  const migrateTip = useMutation({
    mutationFn: () => api<{ migrated: number; errors?: string[] }>("/assets/migrate", { method: "POST" }),
    onSuccess: (data) => {
      toast.push(`Migrated ${data.migrated ?? 0} TIP asset(s) to Postgres`, "ok");
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (err) => toast.push(err instanceof Error ? err.message : "Migration failed", "bad"),
  });
  const importCsv = useMutation({
    mutationFn: () => api("/assets/import/csv", { method: "POST", body: JSON.stringify({ csv }) }),
    onSuccess: (data: any) => {
      const n = data.registry_created ?? data.imported ?? data.created ?? data.count ?? 0;
      toast.push(`Imported ${n} asset(s) into registry`, "ok");
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (err) => toast.push(err instanceof Error ? err.message : "Import failed", "bad"),
  });

  const linkCase = useMutation({
    mutationFn: () => api(`/assets/${selected.asset_id}/cases`, {
      method: "POST",
      body: JSON.stringify({ case_id: caseId.trim() }),
    }),
    onSuccess: () => {
      toast.push("Linked to case", "ok");
      setCaseId("");
      qc.invalidateQueries({ queryKey: ["asset-detail", selected?.asset_id] });
    },
    onError: (err) => toast.push(err instanceof Error ? err.message : "Link failed", "bad"),
  });

  const tipRows = (assets.data?.legacy_candidates || []) as any[];
  const registryFromApi = (assets.data?.assets || []) as any[];
  const rows = registryFromApi;
  const critical = rows.filter((r: any) => {
    const c = r.criticality;
    return c === "critical" || c === "high" || Number(c) >= 0.75;
  }).length;
  const criticalitySeries = Object.entries(
    rows.reduce((acc: Record<string, number>, row: any) => {
      const key = String(row.criticality ?? row.status ?? "unknown");
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {}),
  ).map(([label, value]) => ({ label, value: Number(value) }));
  function onCreate(e: FormEvent) {
    e.preventDefault();
    create.mutate();
  }

  return <>
    <Heading
      kicker="Operations"
      title="Assets / CMDB"
      subtitle="Postgres asset-registry is the inventory SoR. TIP SQLite remains for posture/case-link helpers until migrated; create/CSV write registry only."
      actions={<Link className="button secondary compact" to="/">Gallery sites</Link>}
    />
    <ErrorState error={assets.error || posture.error} />
    <OpsSurfaceKpis extras={[
      { label: "Registry assets", value: rows.length, href: "/assets" },
      { label: "High/critical", value: critical, href: "/assets", tone: critical ? "warn" : undefined },
      { label: "TIP inventory", value: tipRows.length, href: "/assets" },
      { label: "Open findings", value: posture.data?.n ?? posture.data?.open_findings?.length ?? "—", href: "/assets" },
    ]} />
    <div className="widget-grid">
      <section className="card widget-span-4">
        <div className="section-head"><div><span className="section-kicker">Exposure</span><h2>Criticality mix</h2></div></div>
        <Donut data={criticalitySeries} />
      </section>
    </div>
    <div className="result-grid">
      <section className="card">
        <div className="section-head"><div><span className="section-kicker">SoR</span><h2>Asset registry (Postgres)</h2></div><span className="count-badge">{rows.length}</span></div>
        <DataTable
          searchable
          columns={[
            { key: "name", label: "Name", clip: true, render: (row: any) => (
              <button type="button" className="ghost compact" onClick={() => setSelected({ ...row, asset_id: row.asset_id || row.id, hostname: row.name || row.hostname })}>{row.name || row.hostname || row.asset_id || row.id}</button>
            ) },
            { key: "kind", label: "Kind", render: (row: any) => humanizeLabel(row.kind || row.asset_type || "") },
            { key: "environment", label: "Env" },
            { key: "owner", label: "Owner", clip: true },
            { key: "status", label: "Status" },
            { key: "last_seen", label: "Last seen", nowrap: true, render: (row: any) => formatWhen(row.last_seen) },
          ]}
          rows={rows}
          rowKey={(row: any, i) => row.asset_id || row.id || String(i)}
          empty={<EmptyState title="Detection registry empty" description="Create an asset below, or migrate TIP inventory after starting asset-registry." compact />}
        />
        <div className="section-head" style={{ marginTop: "1.25rem" }}>
          <div><span className="section-kicker">Legacy</span><h2>TIP inventory (SQLite)</h2></div>
          <span className="count-badge">{tipRows.length}</span>
        </div>
        <DataTable
          searchable
          columns={[
            { key: "hostname", label: "Hostname", render: (row: any) => <button type="button" className="ghost compact" onClick={() => setSelected(row)}>{row.hostname || row.name || row.ip_address}</button> },
            { key: "asset_type", label: "Type", render: (row: any) => humanizeLabel(row.asset_type || row.type || "") },
            { key: "criticality", label: "Criticality", sortable: true },
            { key: "last_seen", label: "Last seen", nowrap: true, render: (row: any) => formatWhen(row.last_seen || row.updated_at) },
            { key: "tags", label: "Tags", render: (row: any) => (row.tags || []).join(", ") || "—" },
          ]}
          rows={tipRows}
          rowKey={(row: any) => row.asset_id || row.id}
          empty={<EmptyState title="No TIP assets" description="Legacy SQLite inventory is empty." compact />}
        />
      </section>
      <div className="stack">
        {isOperational(user.role) && <form className="card" onSubmit={onCreate}>
          <div className="section-head"><div><span className="section-kicker">Create</span><h2>Registry asset</h2></div></div>
          <label>Hostname<input value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} required /></label>
          <label>IP address<input value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} /></label>
          <label>Type<select value={form.asset_type} onChange={(e) => setForm({ ...form, asset_type: e.target.value })}><option value="host">Host</option><option value="user">User</option><option value="app">App</option><option value="cloud">Cloud resource</option></select></label>
          <label>Criticality<select value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
          <label>Tags<input value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="comma,separated" /></label>
          <label>Notes<textarea rows={3} value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></label>
          <button disabled={create.isPending}>Create in Postgres</button>
        </form>}
        {isOperational(user.role) && tipRows.length > 0 && <section className="card">
          <div className="section-head"><div><span className="section-kicker">Cutover</span><h2>Migrate TIP → registry</h2></div></div>
          <p className="muted">Copies SQLite TIP assets into Postgres asset-registry (idempotent by hostname/asset_id).</p>
          <button type="button" className="secondary" disabled={migrateTip.isPending} onClick={() => migrateTip.mutate()}>
            {migrateTip.isPending ? "Migrating…" : `Migrate ${tipRows.length} asset(s)`}
          </button>
        </section>}
        {isOperational(user.role) && <section className="card">
          <div className="section-head"><div><span className="section-kicker">Import</span><h2>CSV (registry)</h2></div></div>
          <label>CSV<textarea rows={5} value={csv} onChange={(e) => setCsv(e.target.value)} placeholder={"hostname,asset_type,criticality,tags\nweb-01,host,high,prod"} /></label>
          <button type="button" className="secondary" disabled={!csv.trim() || importCsv.isPending} onClick={() => importCsv.mutate()}>Import CSV</button>
        </section>}
        <section className="card">
          <div className="section-head"><div><span className="section-kicker">Posture</span><h2>Findings board</h2></div></div>
          <DataTable
            columns={[
              { key: "title", label: "Finding", clip: true },
              { key: "severity", label: "Severity" },
              { key: "category", label: "Category" },
            ]}
            rows={posture.data?.open_findings || posture.data?.findings || []}
            rowKey={(row: any, i) => row.finding_id || String(i)}
            empty={<EmptyState title="No open findings" description="Posture misconfigs and vulns appear here." compact />}
          />
        </section>
        <section className="card">
          <div className="section-head"><div><span className="section-kicker">Detail</span><h2>{selected?.hostname || selected?.name || "Asset"}</h2></div>
            {selected && <Link className="button secondary compact" to="/cases">Cases</Link>}
          </div>
          {!selected ? <EmptyState title="Select an asset" description="Related cases, alerts, detections, and posture findings appear here." compact /> : <>
            <p className="muted">{humanizeLabel(selected.asset_type || "")} · {selected.criticality}</p>
            {isOperational(user.role) && <>
              <label>Link case ID<input value={caseId} onChange={(e) => setCaseId(e.target.value)} placeholder="case uuid" /></label>
              <button type="button" className="secondary compact" disabled={!caseId.trim() || linkCase.isPending} onClick={() => linkCase.mutate()}>Link to case</button>
            </>}
            <h3>Case links</h3>
            <DataTable
              columns={[{ key: "case_id", label: "Case" }]}
              rows={detail.data?.case_links || []}
              rowKey={(row: any, i) => row.case_id || String(i)}
              empty={<EmptyState title="No case links" description="Link this asset to an investigation case." compact />}
            />
            <h3>Related alerts</h3>
            <DataTable
              columns={[
                { key: "ioc_value", label: "IOC", clip: true },
                { key: "watchlist_name", label: "Watchlist" },
                { key: "disposition", label: "Disposition", render: (row: any) => row.disposition ? humanizeLabel(String(row.disposition)) : "—" },
                { key: "triggered_at", label: "When", nowrap: true, render: (row: any) => formatWhen(row.triggered_at) },
              ]}
              rows={detail.data?.related_alerts || []}
              rowKey={(row: any, i) => row.alert_id || String(i)}
              empty={<EmptyState title="No related alerts" description="Watchlist hits matching this hostname or IP appear here." compact />}
            />
            <h3>Related detections</h3>
            <DataTable
              columns={[
                { key: "title", label: "Title", clip: true },
                { key: "connector", label: "Connector" },
                { key: "severity", label: "Severity" },
                { key: "event_time", label: "When", nowrap: true, render: (row: any) => formatWhen(row.event_time) },
              ]}
              rows={detail.data?.related_detections || []}
              rowKey={(row: any, i) => row.detection_key || String(i)}
              empty={<EmptyState title="No related detections" description="Connector detections for this host appear after ingest." compact />}
            />
            <h3>Related IOCs</h3>
            <DataTable
              columns={[
                { key: "ioc_type", label: "Type" },
                { key: "ioc_value", label: "Value", clip: true },
              ]}
              rows={detail.data?.related_iocs || []}
              rowKey={(row: any, i) => `${row.ioc_type}:${row.ioc_value}:${i}`}
              empty={<EmptyState title="No related IOCs" description="Indicators from related alerts list here." compact />}
            />
            <h3>Posture findings</h3>
            <ErrorState error={detail.error} />
            <DataTable
              columns={[
                { key: "title", label: "Finding", clip: true },
                { key: "severity", label: "Severity" },
                { key: "category", label: "Category" },
              ]}
              rows={detail.data?.findings || []}
              rowKey={(row: any, i) => row.finding_id || String(i)}
              empty={<EmptyState title="No findings" description="Posture misconfigs and vulns will list here." compact />}
            />
          </>}
        </section>
      </div>
    </div>
  </>;
}

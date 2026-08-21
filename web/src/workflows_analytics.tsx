import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import WorldMap from "react-svg-worldmap";
import { api } from "./api";
import { CalendarHeatmap, Donut, HorizontalBars, StackedBar, TimeSeriesArea } from "./components/charts";
import { KpiRow } from "./components/kpi";
import { useToast } from "./components/toast";
import { useUser } from "./user_context";
import { DataTable, EmptyState, ErrorState, Heading, formatCount, formatWhen } from "./ui";

type Range = "24h" | "7d" | "30d" | "90d";
type AnalyticsTab = "volume" | "response" | "quality" | "cti" | "attack" | "cases";
type SavedView = {
  view_id?: string;
  name: string;
  range: Range;
  tab: AnalyticsTab;
  role_default?: string | null;
  owned?: boolean;
};

const SAVED_VIEWS_KEY = "blackonyx_analytics_views_v1";

function loadLocalViews(): SavedView[] {
  try {
    const raw = localStorage.getItem(SAVED_VIEWS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((v) => v?.name && v?.range && v?.tab) : [];
  } catch {
    return [];
  }
}

function useAnalytics<T>(path: string, enabled = true) {
  return useQuery({
    queryKey: ["analytics", path],
    queryFn: () => api<T>(path),
    enabled,
  });
}

function toSeries(payload: any): { label: string; value: number }[] {
  return (payload?.points || payload?.series || payload?.items || payload?.buckets || []).map((p: any) => ({
    label: String(p.label || p.key || p.bucket || p.day || p.ts || ""),
    value: Number(p.value ?? p.count ?? 0),
  }));
}

export function AnalyticsWorkflow() {
  const user = useUser();
  const [range, setRange] = useState<Range>("30d");
  const [tab, setTab] = useState<AnalyticsTab>("volume");
  const [savedViews, setSavedViews] = useState<SavedView[]>([]);
  const [viewName, setViewName] = useState("");
  const [asRoleDefault, setAsRoleDefault] = useState(false);
  const toast = useToast();
  const navigate = useNavigate();
  const overview = useAnalytics<any>(`/analytics/overview?range=${range}`);
  const timeseries = useAnalytics<any>(`/analytics/timeseries?metric=alerts&group_by=day&range=${range}`);
  const casesTs = useAnalytics<any>(`/analytics/timeseries?metric=cases&group_by=day&range=${range}`);
  const webhookTs = useAnalytics<any>(`/analytics/timeseries?metric=webhooks&group_by=day&range=${range}`);
  const taxiiTs = useAnalytics<any>(`/analytics/timeseries?metric=taxii&group_by=day&range=${range}`);
  const mttaTs = useAnalytics<any>(`/analytics/timeseries?metric=mtta&group_by=day&range=${range}`);
  const mttiTs = useAnalytics<any>(`/analytics/timeseries?metric=mtti&group_by=day&range=${range}`);
  const mttrTs = useAnalytics<any>(`/analytics/timeseries?metric=mttr&group_by=day&range=${range}`);
  const ingestTs = useAnalytics<any>(`/analytics/timeseries?metric=ingest_latency&group_by=day&range=${range}`);
  const fprTs = useAnalytics<any>(`/analytics/timeseries?metric=fpr&group_by=day&range=${range}`);
  const dispositions = useAnalytics<any>(`/analytics/distributions?metric=disposition&range=${range}`);
  const assetCriticality = useAnalytics<any>(`/analytics/distributions?metric=asset_criticality&range=${range}`);
  const iocTypes = useAnalytics<any>(`/analytics/distributions?metric=ioc_type&range=${range}`);
  const alertSources = useAnalytics<any>(`/analytics/distributions?metric=alert_source&range=${range}`);
  const severities = useAnalytics<any>(`/analytics/distributions?metric=severity&range=${range}`);
  const heatmap = useAnalytics<any>(`/analytics/distributions?metric=hour_weekday&range=${range}`);
  const noisyIocs = useAnalytics<any>(`/analytics/distributions?metric=noisy_ioc&range=${range}`);
  const enrichmentVerdicts = useAnalytics<any>(`/analytics/distributions?metric=enrichment_verdict&range=${range}`);
  const assignees = useAnalytics<any>(`/analytics/distributions?metric=assignee&range=${range}`);
  const slaAging = useAnalytics<any>(`/analytics/distributions?metric=sla_aging&range=${range}`);
  const timeInStatus = useAnalytics<any>(`/analytics/distributions?metric=time_in_status&range=${range}`);
  const webhookVolume = useAnalytics<any>(`/analytics/distributions?metric=webhook_volume&range=${range}`);
  const dedup = useAnalytics<any>(`/analytics/distributions?metric=dedup_savings&range=${range}`);
  const detectionsByConnector = useAnalytics<any>(`/analytics/distributions?metric=detections_by_connector&range=${range}`);
  const intelAge = useAnalytics<any>(`/analytics/distributions?metric=intel_age_at_match&range=${range}`);
  const enrichCoverage = useAnalytics<any>(`/analytics/distributions?metric=enrichment_coverage&range=${range}`);
  const freshIocTs = useAnalytics<any>(`/analytics/timeseries?metric=fresh_iocs&group_by=day&range=${range}`);
  const staleIocTs = useAnalytics<any>(`/analytics/timeseries?metric=stale_iocs&group_by=day&range=${range}`);
  const kpis = useAnalytics<any>(`/analytics/kpis?metrics=mtta,mtti,mttr,ingest_latency,fpr,alert_case_ratio,fresh_ioc_ratio,closure_rate,escalation_rate,reopen_rate,intel_hit_rate,automation_success,sla_breach_rate&range=${range}`);
  const attack = useAnalytics<any>(`/analytics/attack/coverage?range=${range}`);
  const cti = useAnalytics<any>(`/analytics/cti/impact?range=${range}`);
  const connectors = useAnalytics<any>("/analytics/connectors/health");
  const playbooks = useAnalytics<any>(`/analytics/playbooks?range=${range}`);

  const refreshViews = useCallback(async (applyDefault = false) => {
    try {
      let data = await api<{ views: SavedView[] }>("/analytics/views");
      let views = data.views || [];
      if (!views.length) {
        const local = loadLocalViews();
        for (const view of local) {
          try {
            await api("/analytics/views", { method: "POST", body: JSON.stringify({ name: view.name, range: view.range, tab: view.tab }) });
          } catch { /* ignore migrate failures */ }
        }
        if (local.length) {
          data = await api<{ views: SavedView[] }>("/analytics/views");
          views = data.views || [];
          localStorage.removeItem(SAVED_VIEWS_KEY);
        }
      }
      setSavedViews(views);
      if (applyDefault) {
        const preferred = views.find((v) => v.role_default === user.role) || views.find((v) => v.owned && v.role_default);
        if (preferred?.range && preferred?.tab) {
          setRange(preferred.range as Range);
          setTab(preferred.tab as AnalyticsTab);
        }
      }
    } catch {
      setSavedViews(loadLocalViews());
    }
  }, [user.role]);

  useEffect(() => { void refreshViews(true); }, [refreshViews]);

  function hunt(query: string) {
    const q = query.trim();
    if (!q) return;
    navigate(`/search?q=${encodeURIComponent(q)}`);
  }

  const alertSeries = toSeries(timeseries.data);
  const caseSeries = toSeries(casesTs.data);
  const dispositionSeries = toSeries(dispositions.data);
  const techniqueRows = attack.data?.techniques || attack.data?.leaderboard || [];
  const heatCells = (heatmap.data?.cells || []).map((c: any) => ({
    weekday: Number(c.weekday ?? c.dow ?? 0),
    hour: Number(c.hour ?? 0),
    value: Number(c.value ?? c.count ?? 0),
  }));
  const geoData = (cti.data?.geo || cti.data?.countries || overview.data?.geo || []).map((row: any) => ({
    country: String(row.country || row.code || "").toUpperCase(),
    value: Number(row.value ?? row.count ?? 0),
  })).filter((row: any) => row.country.length === 2);

  const kpiItems = useMemo(() => {
    const metrics = kpis.data?.metrics || {};
    const pick = (key: string, label: string, href?: string) => {
      const row = metrics[key] || {};
      const value = row.value ?? row.seconds ?? row.ratio ?? row.rate ?? "—";
      const display = typeof value === "number"
        ? (key.includes("ratio") || key === "fpr" || key.endsWith("_rate")
          ? `${(value * 100).toFixed(1)}%`
          : key.startsWith("mtt") ? `${Math.round(value / 60)}m` : formatCount(value))
        : value;
      return { label, value: display, n: row.n, hint: row.hint, href, sparkline: row.sparkline };
    };
    return [
      pick("mtta", "MTTA", "/triage"),
      pick("mtti", "MTTI", "/cases"),
      pick("mttr", "MTTR", "/cases"),
      pick("ingest_latency", "Ingest latency", "/detections"),
      pick("fpr", "False positive rate", "/analytics"),
      pick("alert_case_ratio", "Alert→case", "/triage"),
      pick("intel_hit_rate", "Intel hit rate", "/watchlists"),
      pick("automation_success", "Automation success", "/playbooks"),
      pick("closure_rate", "Closure rate", "/cases"),
      pick("sla_breach_rate", "SLA breach rate", "/cases"),
      pick("reopen_rate", "Reopen rate", "/cases"),
      pick("fresh_ioc_ratio", "Fresh IOC ratio", "/decay"),
    ];
  }, [kpis.data]);

  const pickDisplay = (key: string) => {
    const row = kpis.data?.metrics?.[key] || {};
    const value = row.value ?? row.seconds ?? row.ratio ?? row.rate;
    if (typeof value !== "number") return "—";
    if (key.startsWith("mtt") || key === "ingest_latency") return `${Math.round(value / 60)}m`;
    if (key.includes("ratio") || key === "fpr" || key.endsWith("_rate") || key.endsWith("_success")) return `${(value * 100).toFixed(1)}%`;
    return formatCount(value);
  };

  return <>
    <Heading
      kicker="Analytics"
      title="Blue-team analytics"
      subtitle="Disposition-aware volume, response timing, CTI impact, and risk-weighted ATT&CK sightings — not vanity coverage scores."
      actions={<>
        <label>Range<select value={range} onChange={(e) => setRange(e.target.value as Range)}><option value="24h">24h</option><option value="7d">7d</option><option value="30d">30d</option><option value="90d">90d</option></select></label>
        <label>Saved view
          <select value="" onChange={(e) => {
            const view = savedViews.find((v) => (v.view_id || v.name) === e.target.value || v.name === e.target.value);
            if (!view) return;
            setRange(view.range);
            setTab(view.tab);
          }}>
            <option value="">Apply…</option>
            {savedViews.map((v) => (
              <option key={v.view_id || v.name} value={v.view_id || v.name}>
                {v.name}{v.role_default ? ` (role:${v.role_default})` : ""}{v.owned === false ? " · shared" : ""}
              </option>
            ))}
          </select>
        </label>
        <label className="compact">Name<input value={viewName} onChange={(e) => setViewName(e.target.value)} placeholder="My view" /></label>
        <label className="check setting-toggle compact"><input type="checkbox" checked={asRoleDefault} onChange={(e) => setAsRoleDefault(e.target.checked)} /> Role default</label>
        <button type="button" className="secondary compact" onClick={async () => {
          const name = viewName.trim();
          if (!name) { toast.push("Name the view first", "bad"); return; }
          try {
            await api("/analytics/views", {
              method: "POST",
              body: JSON.stringify({
                name, range, tab,
                role_default: asRoleDefault ? user.role : null,
              }),
            });
            await refreshViews();
            setViewName("");
            setAsRoleDefault(false);
            toast.push(`Saved view “${name}”`, "ok");
          } catch (err) {
            toast.push(err instanceof Error ? err.message : "Save failed", "bad");
          }
        }}>Save view</button>
        {savedViews.some((v) => v.owned !== false) && <button type="button" className="ghost compact" onClick={async () => {
          const named = viewName.trim();
          const target = (named
            ? savedViews.find((v) => v.owned !== false && v.name === named)
            : undefined)
            || [...savedViews].reverse().find((v) => v.owned !== false);
          if (!target?.view_id) { toast.push("Select an owned view to remove", "bad"); return; }
          try {
            await api(`/analytics/views/${target.view_id}`, { method: "DELETE" });
            await refreshViews();
            toast.push(`Removed “${target.name}”`, "ok");
          } catch (err) {
            toast.push(err instanceof Error ? err.message : "Remove failed", "bad");
          }
        }}>Remove view</button>}
      </>}
    />
    <ErrorState error={overview.error || timeseries.error || kpis.error || attack.error || cti.error || connectors.error || playbooks.error} />
    <KpiRow items={kpiItems} />
    <div className="tabs" role="tablist">
      {([
        ["volume", "Volume"],
        ["response", "Response"],
        ["quality", "Quality"],
        ["cti", "CTI impact"],
        ["attack", "ATT&CK"],
        ["cases", "Cases / IR"],
      ] as const).map(([id, label]) => (
        <button key={id} type="button" role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>{label}</button>
      ))}
    </div>

    {tab === "volume" && <div className="widget-grid">
      <section className="card widget-span-8">
        <div className="section-head"><div><span className="section-kicker">Volume</span><h2>Alerts over time</h2></div><Link className="button secondary compact" to="/triage">Open triage</Link></div>
        <TimeSeriesArea data={alertSeries} onPointClick={(p) => hunt(String(p.label))} />
        <p className="muted">Click a day to hunt that bucket in Search.</p>
      </section>
      <section className="card widget-span-4">
        <div className="section-head"><div><span className="section-kicker">Sources</span><h2>Alerts by watchlist</h2></div></div>
        <HorizontalBars data={toSeries(alertSources.data)} onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">IOC types</span><h2>Indicator mix</h2></div></div>
        <HorizontalBars data={toSeries(iocTypes.data)} onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Severity</span><h2>Case severity</h2></div></div>
        <Donut data={toSeries(severities.data)} onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Detections</span><h2>By connector</h2></div><Link className="button secondary compact" to="/detections">Detections</Link></div>
        <HorizontalBars data={toSeries(detectionsByConnector.data)} onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Webhooks</span><h2>Inbound events</h2></div></div>
        <TimeSeriesArea data={toSeries(webhookTs.data)} color="#f2bd68" onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Webhooks</span><h2>By source</h2></div></div>
        <HorizontalBars data={toSeries(webhookVolume.data)} onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-12">
        <div className="section-head"><div><span className="section-kicker">Timing</span><h2>Hour × weekday heatmap</h2></div></div>
        {heatCells.length ? <CalendarHeatmap cells={heatCells} onCellClick={(c) => hunt(`${["Sun","Mon","Tue","Wed","Thu","Fri","Sat"][c.weekday]} ${c.hour}:00`)} /> : <EmptyState title="No heatmap cells" description="Alert timestamps populate this matrix as volume grows." compact />}
      </section>
      <section className="card widget-span-12">
        <div className="section-head"><div><span className="section-kicker">Connectors</span><h2>Health</h2></div><Link className="button secondary compact" to="/detections">Detections</Link></div>
        <DataTable
          searchable
          columns={[
            { key: "name", label: "Connector", render: (row: any) => <button type="button" className="ghost compact" onClick={() => hunt(String(row.name || ""))}>{row.name}</button> },
            { key: "status", label: "Status", render: (row: any) => <span className={`status ${row.status || row.last_poll_status || "active"}`}>{row.status || row.last_poll_status || "unknown"}</span> },
            { key: "last_poll", label: "Last poll", nowrap: true, render: (row: any) => formatWhen(row.last_poll || row.last_poll_at || row.updated_at) },
            { key: "detections", label: "Detections", render: (row: any) => formatCount(row.detections ?? row.count ?? 0) },
          ]}
          rows={connectors.data?.connectors || connectors.data || []}
          rowKey={(row: any, i) => row.id || row.name || String(i)}
          empty={<EmptyState title="No connector health" description="Configure connectors to populate ingest health." compact />}
        />
      </section>
    </div>}

    {tab === "response" && <div className="widget-grid">
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Response</span><h2>Cases opened over time</h2></div></div>
        <TimeSeriesArea data={caseSeries} color="#A78BFA" onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Timing KPIs</span><h2>MTTA / MTTI / MTTR / MTTD</h2></div></div>
        <KpiRow items={[
          { label: "MTTA", value: pickDisplay("mtta"), href: "/triage", n: kpis.data?.metrics?.mtta?.n },
          { label: "MTTI", value: pickDisplay("mtti"), href: "/cases", n: kpis.data?.metrics?.mtti?.n },
          { label: "MTTR", value: pickDisplay("mttr"), href: "/cases", n: kpis.data?.metrics?.mttr?.n },
          { label: "Ingest latency", value: pickDisplay("ingest_latency"), href: "/detections", n: kpis.data?.metrics?.ingest_latency?.n },
        ]} />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Trend</span><h2>MTTA (minutes)</h2></div></div>
        <TimeSeriesArea data={toSeries(mttaTs.data).map((p) => ({ ...p, value: Math.round(p.value / 60) }))} color="#6C3CF2" />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Trend</span><h2>MTTR (minutes)</h2></div></div>
        <TimeSeriesArea data={toSeries(mttrTs.data).map((p) => ({ ...p, value: Math.round(p.value / 60) }))} color="#A78BFA" />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Trend</span><h2>MTTI (minutes)</h2></div></div>
        <TimeSeriesArea data={toSeries(mttiTs.data).map((p) => ({ ...p, value: Math.round(p.value / 60) }))} color="#a78bfa" />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Trend</span><h2>Ingest latency (minutes)</h2></div></div>
        <TimeSeriesArea data={toSeries(ingestTs.data).map((p) => ({ ...p, value: Math.round(p.value / 60) }))} color="#f2bd68" />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Ratios</span><h2>Escalation / closure / reopen</h2></div></div>
        <Donut data={[
          { label: "Escalated", value: Number(kpis.data?.metrics?.escalation_rate?.escalated ?? 0) },
          { label: "Closed", value: Number(kpis.data?.metrics?.closure_rate?.closed ?? 0) },
          { label: "Reopened", value: Number(kpis.data?.metrics?.reopen_rate?.reopened ?? 0) },
          { label: "Other", value: Math.max(0, Number(overview.data?.cases?.n ?? 0) - Number(kpis.data?.metrics?.closure_rate?.closed ?? 0)) },
        ].filter((d) => d.value > 0)} />
        <p className="muted">Reopen rate: {pickDisplay("reopen_rate")} (n={kpis.data?.metrics?.reopen_rate?.n ?? 0})</p>
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">SLA</span><h2>Open-case aging</h2></div></div>
        <HorizontalBars data={toSeries(slaAging.data)} onPointClick={(p) => hunt(`sla ${p.label}`)} />
      </section>
    </div>}

    {tab === "quality" && <div className="widget-grid">
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Quality</span><h2>Disposition mix</h2></div></div>
        <Donut data={dispositionSeries} onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Quality</span><h2>FPR over time</h2></div></div>
        <TimeSeriesArea data={toSeries(fprTs.data).map((p) => ({ ...p, value: Number((p.value * 100).toFixed(1)) }))} color="#f07178" />
        <p className="muted">Daily false-positive rate among disposed alerts (%).</p>
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Enrichment</span><h2>Verdict mix</h2></div></div>
        <Donut data={toSeries(enrichmentVerdicts.data)} onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-8">
        <div className="section-head"><div><span className="section-kicker">Noise</span><h2>Noisy IOC leaderboard</h2></div></div>
        <HorizontalBars data={toSeries(noisyIocs.data).slice(0, 15)} onPointClick={(p) => {
          const value = String(p.label).includes(":") ? String(p.label).split(":").slice(1).join(":") : String(p.label);
          hunt(value);
        }} />
      </section>
      <section className="card widget-span-4">
        <div className="section-head"><div><span className="section-kicker">Dedup</span><h2>Connector skip savings</h2></div></div>
        <KpiRow items={[{ label: "Skipped duplicates", value: formatCount(dedup.data?.n ?? 0), href: "/detections" }]} />
        <HorizontalBars data={toSeries(dedup.data)} />
      </section>
    </div>}

    {tab === "cti" && <div className="widget-grid">
      <section className="card widget-span-4">
        <div className="section-head"><div><span className="section-kicker">Funnel</span><h2>Intel → case</h2></div></div>
        <HorizontalBars data={[
          { label: "Alerts", value: Number(cti.data?.funnel?.watchlist_alerts ?? 0) },
          { label: "True positives", value: Number(cti.data?.funnel?.true_positives ?? 0) },
          { label: "False positives", value: Number(cti.data?.funnel?.false_positives ?? 0) },
          { label: "Promoted", value: Number(cti.data?.funnel?.promoted_to_case ?? 0) },
        ].filter((d) => d.value > 0)} />
      </section>
      <section className="card widget-span-4">
        <div className="section-head"><div><span className="section-kicker">CTI impact</span><h2>Intel yield</h2></div><Link className="button secondary compact" to="/watchlists">Watchlists</Link></div>
        <HorizontalBars data={(cti.data?.feeds || cti.data?.items || []).map((p: any) => ({ label: String(p.label || p.name || "feed"), value: Number(p.value ?? p.hits ?? 0) }))} onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-4">
        <div className="section-head"><div><span className="section-kicker">Decay</span><h2>Fresh vs stale</h2></div><Link className="button secondary compact" to="/decay">Decay</Link></div>
        <Donut data={[
          { label: "Fresh", value: Number(cti.data?.ioc_freshness?.fresh ?? 0) },
          { label: "Stale", value: Number(cti.data?.ioc_freshness?.stale ?? 0) },
        ].filter((d) => d.value > 0)} />
      </section>
      <section className="card widget-span-4">
        <div className="section-head"><div><span className="section-kicker">Intel age</span><h2>Age at match</h2></div></div>
        <HorizontalBars data={toSeries(intelAge.data)} />
        <p className="muted">Watchlist item age when the alert fired.</p>
      </section>
      <section className="card widget-span-4">
        <div className="section-head"><div><span className="section-kicker">Enrichment</span><h2>Coverage</h2></div><Link className="button secondary compact" to="/iocs">IOCs</Link></div>
        <Donut data={toSeries(enrichCoverage.data)} />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Decay trend</span><h2>Fresh IOCs over time</h2></div></div>
        <TimeSeriesArea data={toSeries(freshIocTs.data)} color="#6C3CF2" />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Decay trend</span><h2>Stale IOCs over time</h2></div></div>
        <TimeSeriesArea data={toSeries(staleIocTs.data)} color="#f07178" />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Geo</span><h2>Sighting geography</h2></div></div>
        {geoData.length ? (
          <div className="chart-frame geo-map">
            <WorldMap color="var(--accent)" valueSuffix=" hits" size="responsive" data={geoData} />
          </div>
        ) : (
          <EmptyState title="No geo rows yet" description="Country codes from enrichments or CTI impact feed this map when present." compact />
        )}
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">TAXII</span><h2>Publish volume</h2></div><Link className="button secondary compact" to="/publishing">Publishing</Link></div>
        <TimeSeriesArea data={toSeries(taxiiTs.data)} color="#a78bfa" />
      </section>
      <section className="card widget-span-12">
        <div className="section-head"><div><span className="section-kicker">CVE board</span><h2>Risk board (EPSS × KEV)</h2></div><Link className="button secondary compact" to="/iocs">IOCs</Link></div>
        <StackedBar
          data={(cti.data?.cves || overview.data?.cves || []).map((p: any) => ({
            label: String(p.cve_id || p.label || "").slice(0, 14),
            epss: Number(p.epss || 0),
            kev: Number(p.kev ? 1 : 0),
            value: Number(p.score || p.epss || 0),
          }))}
          keys={["epss", "kev"]}
        />
        {!((cti.data?.cves || overview.data?.cves || []).length) && <EmptyState title="No CVE risk rows" description="Enrich IOCs with NVD/EPSS/KEV to populate this board." compact />}
      </section>
    </div>}

    {tab === "attack" && <div className="widget-grid">
      <section className="card widget-span-12">
        <div className="section-head"><div><span className="section-kicker">ATT&CK</span><h2>Sightings vs coverage gaps</h2></div>
          <button type="button" className="secondary compact" onClick={() => {
            const payload = attack.data?.navigator || attack.data;
            if (!payload) return;
            const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
            const a = document.createElement("a"); a.href = url; a.download = "attack-navigator.json"; a.click(); URL.revokeObjectURL(url);
          }}>Export Navigator JSON</button>
        </div>
        <p className="muted">Coverage index is risk-weighted from org sightings — never a chase for 100% technique coverage. Click a technique to hunt in Search.</p>
        <DataTable
          searchable
          columns={[
            { key: "technique_id", label: "Technique", sortable: true },
            { key: "name", label: "Name", clip: true },
            { key: "sightings", label: "Sightings", sortable: true },
            { key: "risk_weight", label: "Risk weight", sortable: true },
            { key: "gap", label: "Gap", render: (row: any) => row.covered === false ? "Gap" : (row.covered ? "Covered" : "Sighted") },
          ]}
          rows={techniqueRows}
          rowKey={(row: any) => row.technique_id || row.id}
          empty={<EmptyState title="No ATT&CK sightings" description="Map detections and cases to techniques to populate coverage gaps." compact />}
        />
        <div className="actions">
          {(techniqueRows as any[]).slice(0, 12).map((row) => (
            <button key={row.technique_id || row.id} type="button" className="ghost compact" onClick={() => navigate(`/search?q=${encodeURIComponent(row.technique_id || row.id || "")}`)}>
              {row.technique_id || row.id}
            </button>
          ))}
        </div>
      </section>
    </div>}

    {tab === "cases" && <div className="widget-grid">
      <section className="card widget-span-4">
        <div className="section-head"><div><span className="section-kicker">Assets</span><h2>Criticality exposure</h2></div><Link className="button secondary compact" to="/assets">Assets</Link></div>
        <Donut data={toSeries(assetCriticality.data).length ? toSeries(assetCriticality.data) : Object.entries(overview.data?.assets_by_criticality || {}).map(([label, value]) => ({ label, value: Number(value) }))} />
      </section>
      <section className="card widget-span-4">
        <div className="section-head"><div><span className="section-kicker">Cases</span><h2>Status funnel</h2></div><Link className="button secondary compact" to="/cases">Cases</Link></div>
        <HorizontalBars data={Object.entries(overview.data?.cases?.by_status || {}).map(([label, value]) => ({ label, value: Number(value) }))} onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-4">
        <div className="section-head"><div><span className="section-kicker">Workload</span><h2>Assignee (open cases)</h2></div></div>
        <HorizontalBars data={toSeries(assignees.data)} onPointClick={(p) => hunt(String(p.label))} />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">SLA</span><h2>Aging buckets</h2></div></div>
        <Donut data={toSeries(slaAging.data)} />
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Dwell</span><h2>Mean hours in status</h2></div></div>
        <HorizontalBars data={toSeries(timeInStatus.data)} />
        <p className="muted">From status_change timeline events (hours).</p>
      </section>
      <section className="card widget-span-6">
        <div className="section-head"><div><span className="section-kicker">Automation</span><h2>Playbooks & rules</h2></div>
          <div className="actions">
            <Link className="button secondary compact" to="/playbooks">Playbooks</Link>
            <Link className="button secondary compact" to="/rules">Sigma / YARA</Link>
          </div>
        </div>
        <KpiRow items={[
          { label: "Playbook success", value: (playbooks.data?.success_rate ?? overview.data?.playbook_success_rate) != null ? `${(Number(playbooks.data?.success_rate ?? overview.data?.playbook_success_rate) * 100).toFixed(0)}%` : "—", n: playbooks.data?.n ?? overview.data?.playbook_n, href: "/playbooks" },
          { label: "Avg run duration", value: playbooks.data?.avg_duration_seconds != null ? `${Math.round(Number(playbooks.data.avg_duration_seconds))}s` : "—", href: "/playbooks" },
          { label: "Avg approval wait", value: playbooks.data?.avg_approval_wait_seconds != null ? `${Math.round(Number(playbooks.data.avg_approval_wait_seconds))}s` : "—", href: "/playbooks" },
          { label: "Open cases", value: overview.data?.open_cases ?? "—", href: "/cases" },
        ]} />
      </section>
    </div>}
  </>;
}

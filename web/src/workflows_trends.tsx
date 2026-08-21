import React, { useMemo } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { TimeSeriesArea, HorizontalBars } from "./components/charts";
import { EmptyState, ErrorState, Heading, Notice, formatCount } from "./ui";

type Range = "7d" | "30d";

function toSeries(payload: any): { label: string; value: number }[] {
  return (payload?.points || payload?.series || payload?.items || payload?.buckets || []).map((p: any) => ({
    label: String(p.label || p.key || p.bucket || p.day || p.ts || ""),
    value: Number(p.value ?? p.count ?? 0),
  }));
}

const LOOK_FOR = [
  {
    title: "Feed volume vs watchlist hits",
    meaning: "A spike in feed items without matching watchlist alerts usually means new reporting noise, not active targeting of your environment.",
    action: "Compare Feeds → Active with Watchlists and Triage. Promote only IOCs that match your assets or cases.",
    href: "/feeds",
  },
  {
    title: "Fresh vs stale IOC ratio",
    meaning: "Rising stale% means indicators are aging out of usefulness. Sudden fresh% jumps often follow a large vendor advisory ingest (for example MSRC).",
    action: "Open Decay, recalculate, and prune watchlist items that never hit.",
    href: "/decay",
  },
  {
    title: "Inbound webhook / connector silence",
    meaning: "Zero detections and flat webhook series means the product has CTI context but no live SIEM/EDR telemetry to correlate against.",
    action: "Configure Detections connectors or POST to an inbound webhook. Without this, MTTA/MTTR stay empty.",
    href: "/detections",
  },
  {
    title: "Open alerts with no dispositions",
    meaning: "KPIs like MTTA, FPR, and alert→case% need analyst dispositions. Open alerts alone do not create response timing samples.",
    action: "Work Triage: acknowledge, mark TP/FP, and promote true positives into Cases.",
    href: "/triage",
  },
  {
    title: "ATT&CK / playbook empty states",
    meaning: "Coverage and automation charts need technique IDs on cases/rules and executed playbook runs — they will not fill from RSS alone.",
    action: "Refresh ATT&CK cache in Administration, tag cases with techniques, and run a playbook once.",
    href: "/attack",
  },
];

const ACTOR_HINTS = [
  {
    who: "Commodity ransomware / initial access brokers",
    signals: "Phishing domains, loader hashes, and CVE advisories clustering in the same week across news + MSRC/Exploit-DB.",
    news: ["The Hacker News", "BleepingComputer", "Krebs on Security"],
  },
  {
    who: "Nation-state / APT reporting (context only)",
    signals: "Long-form vendor research (Unit 42, Securelist, Talos) naming shared infrastructure — treat as strategic context until your telemetry confirms.",
    news: ["Unit 42", "Securelist", "Cisco Talos", "Google Threat Intelligence"],
  },
  {
    who: "Opportunistic exploit churn",
    signals: "MSRC / Exploit-DB item surges after Patch Tuesday; pair with KEV/EPSS enrichment on CVEs in the IOC workbench.",
    news: ["MSRC Security Updates", "Exploit-DB", "SANS Internet Storm Center"],
  },
];

const NEWS_CATALOG = [
  { name: "Microsoft Security Blog", url: "https://www.microsoft.com/en-us/security/blog/", focus: "Product security + threat research" },
  { name: "MSRC Security Updates", url: "https://msrc.microsoft.com/", focus: "Patch / CVE advisories" },
  { name: "Cisco Talos", url: "https://blog.talosintelligence.com/", focus: "Malware + vulnerability research" },
  { name: "Unit 42", url: "https://unit42.paloaltonetworks.com/", focus: "APT / campaign analysis" },
  { name: "Google Threat Intelligence", url: "https://cloud.google.com/blog/topics/threat-intelligence", focus: "Mandiant-style campaigns" },
  { name: "Check Point Research", url: "https://research.checkpoint.com/", focus: "Malware & vulnerability deep dives" },
  { name: "Securelist", url: "https://securelist.com/", focus: "Kaspersky APT / malware" },
  { name: "WeLiveSecurity", url: "https://www.welivesecurity.com/", focus: "ESET research" },
  { name: "Fortinet Threat Research", url: "https://www.fortinet.com/blog/threat-research", focus: "FortiGuard labs" },
  { name: "Red Canary", url: "https://redcanary.com/blog/", focus: "Detection engineering" },
  { name: "Rapid7 Blog", url: "https://www.rapid7.com/blog/", focus: "Vuln + SOC practice" },
  { name: "SANS ISC", url: "https://isc.sans.edu/", focus: "Daily handler diaries" },
  { name: "The Hacker News", url: "https://thehackernews.com/", focus: "Breaking cyber news" },
  { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/", focus: "Ransomware / breach news" },
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/", focus: "Investigative reporting" },
  { name: "The Record", url: "https://therecord.media/", focus: "Geopolitical cyber news" },
  { name: "Exploit-DB", url: "https://www.exploit-db.com/", focus: "Public exploits" },
];

export function TrendsWorkflow() {
  const range: Range = "30d";
  const overview = useQuery({ queryKey: ["trends-overview", range], queryFn: () => api<any>(`/analytics/overview?range=${range}`) });
  const alertsTs = useQuery({ queryKey: ["trends-alerts", range], queryFn: () => api<any>(`/analytics/timeseries?metric=alerts&group_by=day&range=${range}`) });
  const casesTs = useQuery({ queryKey: ["trends-cases", range], queryFn: () => api<any>(`/analytics/timeseries?metric=cases&group_by=day&range=${range}`) });
  const freshTs = useQuery({ queryKey: ["trends-fresh", range], queryFn: () => api<any>(`/analytics/timeseries?metric=fresh_iocs&group_by=day&range=${range}`) });
  const staleTs = useQuery({ queryKey: ["trends-stale", range], queryFn: () => api<any>(`/analytics/timeseries?metric=stale_iocs&group_by=day&range=${range}`) });
  const webhooksTs = useQuery({ queryKey: ["trends-webhooks", range], queryFn: () => api<any>(`/analytics/timeseries?metric=webhooks&group_by=day&range=${range}`) });
  const cti = useQuery({ queryKey: ["trends-cti", range], queryFn: () => api<any>(`/analytics/cti/impact?range=${range}`) });
  const feeds = useQuery({ queryKey: ["trends-feeds"], queryFn: () => api<any>("/feeds") });
  const connectors = useQuery({ queryKey: ["trends-connectors"], queryFn: () => api<any>("/connectors"), retry: false });
  const capabilities = useQuery({ queryKey: ["trends-caps"], queryFn: () => api<any>("/capabilities") });

  const feedBars = useMemo(() => {
    const rows = (cti.data?.feeds || []).map((f: any) => ({
      label: String(f.label || f.name || "feed"),
      value: Number(f.value ?? f.hits ?? 0),
    }));
    return rows.sort((a: any, b: any) => b.value - a.value).slice(0, 12);
  }, [cti.data]);

  const feedHealth = useMemo(() => {
    const list = feeds.data?.feeds || [];
    const ok = list.filter((f: any) => f.last_status === "ok").length;
    const failed = list.filter((f: any) => f.last_status === "failed").length;
    return { total: list.length, ok, failed, list };
  }, [feeds.data]);

  const connectorCount = (connectors.data?.connectors || connectors.data || []).length || 0;
  const enrichmentProviders = capabilities.data?.enrichment_providers || [];
  const webSearchOn = Boolean(capabilities.data?.features?.web_search);
  const gaps = [
    connectorCount === 0 ? "No SIEM/EDR connectors — detections analytics stay empty until you add one under Detections." : null,
    (overview.data?.kpis?.mtta?.n || 0) === 0 ? "MTTA has n=0 — acknowledge alerts in Triage to start the clock." : null,
    (overview.data?.kpis?.fpr?.n || 0) === 0 ? "FPR has no TP/FP samples — disposition alerts as true/false positive." : null,
    (overview.data?.playbook_n || 0) === 0 ? "No playbook runs — automation success trend cannot populate." : null,
    feedHealth.failed > 0 ? `${feedHealth.failed} feed(s) failing (often vendor WAF blocks — CISA RSS returns 403 from many datacenter IPs).` : null,
  ].filter(Boolean) as string[];

  const error = overview.error || alertsTs.error || cti.error || feeds.error;

  return (
    <>
      <Heading
        kicker="Overview"
        title="Cross-source trends"
        subtitle="How feeds, watchlists, webhooks, enrichment, and response KPIs move together — what it means, who typically drives it, and which news desks to read."
        actions={<Link className="button secondary compact" to="/analytics">Full analytics</Link>}
      />
      <ErrorState error={error} />

      <section className="card">
        <div className="section-head">
          <div>
            <span className="section-kicker">Pulse</span>
            <h2>Workspace pulse ({range})</h2>
          </div>
        </div>
        <div className="stat-row">
          <ul>
            <li><small>Open alerts</small><strong>{formatCount(overview.data?.open_alerts_n ?? overview.data?.open_alerts)}</strong></li>
            <li><small>Open cases</small><strong>{formatCount(overview.data?.open_cases)}</strong></li>
            <li><small>Fresh IOC %</small><strong>{overview.data?.fresh_ioc_pct != null ? `${overview.data.fresh_ioc_pct}%` : "—"}</strong></li>
            <li><small>Active feeds</small><strong>{formatCount(feedHealth.ok)}/{formatCount(feedHealth.total)}</strong></li>
            <li><small>Connectors</small><strong>{formatCount(connectorCount)}</strong></li>
            <li><small>Webhook events (series)</small><strong>{formatCount(toSeries(webhooksTs.data).reduce((a, p) => a + p.value, 0))}</strong></li>
          </ul>
        </div>
        {gaps.length > 0 && (
          <Notice>
            <b>Why some charts stay empty</b>
            <ul style={{ margin: "0.4rem 0 0", paddingLeft: "1.1rem" }}>
              {gaps.map(item => <li key={item}>{item}</li>)}
            </ul>
          </Notice>
        )}
      </section>

      <div className="dc-row">
        <section className="card dc-col-6">
          <div className="section-head"><div><span className="section-kicker">Trend</span><h2>Alerts over time</h2></div><Link className="button ghost compact" to="/triage">Triage</Link></div>
          <p className="section-description">Watchlist + triage pressure. Flat lines with open alerts usually mean nothing is being dispositioned.</p>
          {toSeries(alertsTs.data).length ? <TimeSeriesArea data={toSeries(alertsTs.data)} /> : <EmptyState title="No alert series" description="Create watchlist items or wait for feed/watchlist matches." />}
        </section>
        <section className="card dc-col-6">
          <div className="section-head"><div><span className="section-kicker">Trend</span><h2>Cases over time</h2></div><Link className="button ghost compact" to="/cases">Cases</Link></div>
          <p className="section-description">Promotions from triage. If alerts rise but cases do not, investigations are stalling in the queue.</p>
          {toSeries(casesTs.data).length ? <TimeSeriesArea data={toSeries(casesTs.data)} color="var(--accent-glow)" /> : <EmptyState title="No case series" description="Promote a true-positive alert into a case." />}
        </section>
        <section className="card dc-col-6">
          <div className="section-head"><div><span className="section-kicker">CTI</span><h2>Fresh IOCs</h2></div><Link className="button ghost compact" to="/decay">Decay</Link></div>
          <p className="section-description">Newly sighted indicators from feeds/webhooks. Pair with stale IOCs to judge intel hygiene.</p>
          {toSeries(freshTs.data).length ? <TimeSeriesArea data={toSeries(freshTs.data)} color="#A78BFA" /> : <EmptyState title="No fresh-IOC series" description="Poll feeds or ingest webhook events with extractable IOCs." />}
        </section>
        <section className="card dc-col-6">
          <div className="section-head"><div><span className="section-kicker">CTI</span><h2>Stale IOCs</h2></div><Link className="button ghost compact" to="/iocs">IOC workbench</Link></div>
          <p className="section-description">Aging indicators. Enrich with free URLhaus / ThreatFox / KEV (already enabled) before retiring.</p>
          {toSeries(staleTs.data).length ? <TimeSeriesArea data={toSeries(staleTs.data)} color="#A9ADB6" /> : <EmptyState title="No stale-IOC series" description="Decay tracking populates after IOC sightings accumulate." />}
        </section>
        <section className="card dc-col-6">
          <div className="section-head"><div><span className="section-kicker">Ingest</span><h2>Inbound webhook events</h2></div><Link className="button ghost compact" to="/feeds">Feeds → Webhooks</Link></div>
          <p className="section-description">Machine telemetry path (SIEM/SOAR push). This is what fills Analytics → Inbound events.</p>
          {toSeries(webhooksTs.data).some(p => p.value > 0)
            ? <TimeSeriesArea data={toSeries(webhooksTs.data)} color="#6C3CF2" />
            : <EmptyState title="No webhook volume" description="Create a webhook under Feeds and POST JSON with X-Webhook-Token." />}
        </section>
        <section className="card dc-col-6">
          <div className="section-head"><div><span className="section-kicker">Sources</span><h2>Feed yield (hits)</h2></div><Link className="button ghost compact" to="/analytics">CTI impact</Link></div>
          <p className="section-description">Which configured news/research desks contributed extractable intel recently.</p>
          {feedBars.some((b: any) => b.value > 0)
            ? <HorizontalBars data={feedBars} />
            : <EmptyState title="No feed hit counts yet" description="Poll feeds after adding presets; MSRC often leads after Patch Tuesday." />}
        </section>
      </div>

      <section className="card">
        <div className="section-head"><div><span className="section-kicker">Guidance</span><h2>What to look for</h2></div></div>
        <div className="result-grid">
          {LOOK_FOR.map(item => (
            <article className="card" key={item.title}>
              <h3>{item.title}</h3>
              <p>{item.meaning}</p>
              <p className="muted">{item.action}</p>
              <Link className="button secondary compact" to={item.href}>Open</Link>
            </article>
          ))}
        </div>
      </section>

      <section className="card">
        <div className="section-head"><div><span className="section-kicker">Actors</span><h2>Who is typically behind the pattern</h2></div></div>
        <p className="section-description">
          These are analyst heuristics for reading open-source CTI — not attributions from your telemetry.
          Confirm with detections, cases, and enrichment before acting.
        </p>
        <div className="result-grid">
          {ACTOR_HINTS.map(item => (
            <article className="card" key={item.who}>
              <h3>{item.who}</h3>
              <p>{item.signals}</p>
              <div className="gallery-tile-tags">
                {item.news.map(name => <span key={name}>{name}</span>)}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="card">
        <div className="section-head">
          <div>
            <span className="section-kicker">News desks</span>
            <h2>Configured free sources</h2>
          </div>
          <Link className="button secondary compact" to="/feeds">Manage feeds</Link>
        </div>
        <p className="section-description">
          Enrichment providers online: {enrichmentProviders.length ? enrichmentProviders.join(", ") : "none"}.
          Web search (SearXNG): {webSearchOn ? "enabled" : "disabled"}.
          CISA RSS is often blocked (HTTP 403) from cloud IPs — use vendor blogs + KEV enrichment instead.
        </p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Source</th><th>Focus</th><th>In workspace</th><th>Last status</th><th></th></tr>
            </thead>
            <tbody>
              {NEWS_CATALOG.map(row => {
                const live = (feedHealth.list || []).find((f: any) => f.name === row.name);
                return (
                  <tr key={row.name}>
                    <td>{row.name}</td>
                    <td className="muted">{row.focus}</td>
                    <td>{live ? "Configured" : "Preset available"}</td>
                    <td>{live?.last_status || "—"}</td>
                    <td><a href={row.url} target="_blank" rel="noopener noreferrer">Open site</a></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card">
        <div className="section-head"><div><span className="section-kicker">Connect</span><h2>Recommended next wiring</h2></div></div>
        <ol style={{ margin: 0, paddingLeft: "1.2rem", display: "grid", gap: "0.55rem" }}>
          <li><Link to="/feeds">Feeds</Link> — keep free RSS presets polled; ignore CISA XML if it 403s.</li>
          <li><Link to="/detections">Detections</Link> — add a generic REST / MDE / Falcon connector when you have API access (not free public).</li>
          <li><Link to="/feeds">Inbound webhooks</Link> — point SIEM/SOAR at <code>/api/v1/webhooks/events</code> (demo webhook already created if you ran setup).</li>
          <li><Link to="/iocs">IOC workbench</Link> — enrich with URLhaus, ThreatFox, KEV, NVD, EPSS (no key) plus any keyed providers already stored.</li>
          <li><Link to="/triage">Triage</Link> — disposition alerts so Analytics KPIs gain sample size.</li>
          <li><Link to="/chat">Chat</Link> — web search is available when capabilities report SearXNG reachable.</li>
        </ol>
      </section>
    </>
  );
}

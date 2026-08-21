import React, { FormEvent, useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { BrowserRouter, Link, Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import { api, streamChat, User } from "./api";
import { Chips, DataTable, EmptyState, ErrorState, Heading, KeyValues, Notice, RagCollectionPicker, RawJson, formatCount, formatWhen, humanizeLabel } from "./ui";
import { GalleryHub } from "./gallery/GalleryHub";
import { UserProvider, useUser } from "./user_context";
import { isAdmin, isOperational, visibleFor } from "./rbac";
import { ThemeProvider, useTheme } from "./theme/ThemeContext";
import { ThemePanel } from "./theme/ThemePanel";
import { ToastProvider } from "./components/toast";
import { Donut, HorizontalBars, TimeSeriesArea } from "./components/charts";
import { KpiRow } from "./components/kpi";
import { Icons, NavIcon } from "./icons";
import { BrandLogo } from "./BrandLogo";
import "./styles.css";

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 10_000, refetchOnWindowFocus: true } } });
// Workflow screens carry feature-specific forms, charts, and API adapters.
// Keep them out of the initial auth/gallery shell and load each module on its
// first classic-route navigation. Named exports from a module share one chunk.
const loadAdminWorkflow = () => import("./workflows_admin");
const loadIntelligenceWorkflows = () => import("./workflows_intelligence");
const loadOperationWorkflows = () => import("./workflows_operations");
const loadDetectionsWorkflow = () => import("./workflows_detections");
const loadAutomationWorkflows = () => import("./workflows_automation");
const loadSettingsWorkflow = () => import("./workflows_settings");
const loadAnalyticsWorkflow = () => import("./workflows_analytics");
const loadTrendsWorkflow = () => import("./workflows_trends");
const loadTriageWorkflow = () => import("./workflows_triage");
const loadContentWorkflow = () => import("./workflows_content");
const loadQueryWorkflow = () => import("./workflows_query");
const loadAssetsWorkflow = () => import("./workflows_assets");
const loadDetectionWorkflow = () => import("./workflows_detection_console");
const AdminWorkflow = React.lazy(() => loadAdminWorkflow().then(module => ({ default: module.AdminWorkflow })));
const AttackWorkflow = React.lazy(() => loadIntelligenceWorkflows().then(module => ({ default: module.AttackWorkflow })));
const GraphWorkflow = React.lazy(() => loadIntelligenceWorkflows().then(module => ({ default: module.GraphWorkflow })));
const IOCWorkflow = React.lazy(() => loadIntelligenceWorkflows().then(module => ({ default: module.IOCWorkflow })));
const ImageSearchWorkflow = React.lazy(() => loadIntelligenceWorkflows().then(module => ({ default: module.ImageSearchWorkflow })));
const ReportsWorkflow = React.lazy(() => loadIntelligenceWorkflows().then(module => ({ default: module.ReportsWorkflow })));
const RulesWorkflow = React.lazy(() => loadIntelligenceWorkflows().then(module => ({ default: module.RulesWorkflow })));
const SearchWorkflow = React.lazy(() => loadIntelligenceWorkflows().then(module => ({ default: module.SearchWorkflow })));
const BookmarksWorkflow = React.lazy(() => loadOperationWorkflows().then(module => ({ default: module.BookmarksWorkflow })));
const CasesWorkflow = React.lazy(() => loadOperationWorkflows().then(module => ({ default: module.CasesWorkflow })));
const CollectionsWorkflow = React.lazy(() => loadOperationWorkflows().then(module => ({ default: module.CollectionsWorkflow })));
const DecayWorkflow = React.lazy(() => loadOperationWorkflows().then(module => ({ default: module.DecayWorkflow })));
const FeedsWorkflow = React.lazy(() => loadOperationWorkflows().then(module => ({ default: module.FeedsWorkflow })));
const IngestWorkflow = React.lazy(() => loadOperationWorkflows().then(module => ({ default: module.IngestWorkflow })));
const JobsWorkflow = React.lazy(() => loadOperationWorkflows().then(module => ({ default: module.JobsWorkflow })));
const WatchlistsWorkflow = React.lazy(() => loadOperationWorkflows().then(module => ({ default: module.WatchlistsWorkflow })));
const DetectionsWorkflow = React.lazy(() => loadDetectionsWorkflow().then(module => ({ default: module.DetectionsWorkflow })));
const PlaybooksWorkflow = React.lazy(() => loadAutomationWorkflows().then(module => ({ default: module.PlaybooksWorkflow })));
const PublishingWorkflow = React.lazy(() => loadAutomationWorkflows().then(module => ({ default: module.PublishingWorkflow })));
const SettingsWorkflow = React.lazy(() => loadSettingsWorkflow().then(module => ({ default: module.SettingsWorkflow })));
const AnalyticsWorkflow = React.lazy(() => loadAnalyticsWorkflow().then(module => ({ default: module.AnalyticsWorkflow })));
const TrendsWorkflow = React.lazy(() => loadTrendsWorkflow().then(module => ({ default: module.TrendsWorkflow })));
const TriageWorkflow = React.lazy(() => loadTriageWorkflow().then(module => ({ default: module.TriageWorkflow })));
const ContentWorkflow = React.lazy(() => loadContentWorkflow().then(module => ({ default: module.ContentWorkflow })));
const QueryWorkflow = React.lazy(() => loadQueryWorkflow().then(module => ({ default: module.QueryWorkflow })));
const AssetsWorkflow = React.lazy(() => loadAssetsWorkflow().then(module => ({ default: module.AssetsWorkflow })));
const AssetDetailWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.AssetDetailWorkflow })));
const AttackCoverageWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.AttackCoverageWorkflow })));
const DataHealthWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.DataHealthWorkflow })));
const DetectionCodeChangesWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.DetectionCodeChangesWorkflow })));
const DetectionMetricsWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.DetectionMetricsWorkflow })));
const DetectionNetworkWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.DetectionNetworkWorkflow })));
const DetectionOverviewWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.DetectionOverviewWorkflow })));
const DetectionServicesWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.DetectionServicesWorkflow })));
const FindingsWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.FindingsWorkflow })));
const HuntWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.HuntWorkflow })));
const IncidentDetailWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.IncidentDetailWorkflow })));
const IncidentsWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.IncidentsWorkflow })));
const MalwareWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.MalwareWorkflow })));
const ModelsWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.ModelsWorkflow })));
const ResponseQueueWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.ResponseQueueWorkflow })));
const SecurityProfilesWorkflow = React.lazy(() => loadDetectionWorkflow().then(module => ({ default: module.SecurityProfilesWorkflow })));
function useRef<T>(initial?: T) { return React.useRef<T | undefined>(initial); }
const PATH_ICONS: Record<string, string> = {
  "/": "home", "/dashboard": "dashboard", "/jobs": "jobs", "/ingest": "ingest", "/search": "search",
  "/image-search": "image", "/collections": "collections", "/chat": "chat", "/query": "query",
  "/iocs": "ioc", "/attack": "attack", "/graph": "graph", "/rules": "rules", "/reports": "reports",
  "/content": "content", "/cases": "cases", "/watchlists": "watchlists", "/feeds": "feeds",
  "/detections": "detections", "/triage": "triage", "/playbooks": "playbooks", "/publishing": "publishing",
  "/decay": "decay", "/bookmarks": "bookmarks", "/system": "system", "/analytics": "analytics",
  "/trends": "trends",
  "/assets": "assets", "/admin": "admin", "/settings": "settings", "/profile": "user",
  "/detection": "detections", "/incidents": "detections", "/findings": "detections",
  "/hunt": "search", "/malware": "detections", "/response-queue": "playbooks",
  "/security-profiles": "admin", "/data-health": "analytics", "/models": "jobs",
  "/detection-services": "system", "/attack-coverage": "attack",
};
const navigationGroups = [
  { label: "Overview", items: [["Gallery","/","home"],["Dashboard","/dashboard","dashboard"],["Analytics","/analytics","analytics"],["Trends","/trends","trends"],["Jobs","/jobs","jobs"]] },
  { label: "Investigate", items: [["Ingest","/ingest","ingest"],["Search","/search","search"],["Query","/query","query"],["Image search","/image-search","image"],["Collections","/collections","collections"],["Chat","/chat","chat"]] },
  { label: "Intelligence", items: [["IOCs","/iocs","ioc"],["ATT&CK","/attack","attack"],["Graph","/graph","graph"],["Rules","/rules","rules"],["Reports","/reports","reports"],["Content","/content","content"]] },
  { label: "Operations", items: [["Triage","/triage","triage"],["Cases","/cases","cases"],["Incidents","/incidents","detections"],["Findings","/findings","detections"],["Hunt","/hunt","search"],["Response","/response-queue","playbooks"],["Malware","/malware","detections"],["Watchlists","/watchlists","watchlists"],["Feeds","/feeds","feeds"],["Detections","/detections","detections"],["Assets","/assets","assets"],["Playbooks","/playbooks","playbooks"],["Profiles","/security-profiles","admin"],["Publishing","/publishing","publishing"],["Decay","/decay","decay"],["Bookmarks","/bookmarks","bookmarks"],["System","/system","system"]] },
  { label: "Detection", items: [["Overview","/detection","detections"],["Services","/detection-services","system"],["Data health","/data-health","analytics"],["Models","/models","jobs"],["ATT&CK coverage","/attack-coverage","attack"],["Metrics","/detection/metrics","analytics"],["Network","/detection/network","assets"],["Code changes","/detection/code-changes","detections"]] },
] as const;

function Login({onLogin}:{onLogin:(user:User)=>void}){const[email,setEmail]=useState("");const[password,setPassword]=useState("");const[mfa,setMfa]=useState("");const[error,setError]=useState("");async function submit(e:FormEvent){e.preventDefault();setError("");try{const value=await api<{user:User}>("/auth/login",{method:"POST",body:JSON.stringify({email:email.trim(),password,mfa_code:mfa.trim()||null})});onLogin(value.user)}catch(reason){setError(reason instanceof Error?reason.message:"Login failed")}}return <main className="auth-shell"><form className="card auth-card" onSubmit={submit}><div className="auth-brand-hero"><BrandLogo variant="hero"/><p className="auth-brand-tag">Invite-only · TIP-first · Blue team</p></div><ErrorState error={error}/><label>Email<input type="email" autoComplete="username" value={email} onChange={e=>setEmail(e.target.value)} required/></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} required/></label><label>MFA or recovery code <small>when enabled</small><input autoComplete="one-time-code" value={mfa} onChange={e=>setMfa(e.target.value)}/></label><button>Sign in</button><Link to="/forgot-password">Forgot password?</Link></form></main>}
function Register({onLogin}:{onLogin:(user:User)=>void}){const token=new URLSearchParams(location.search).get("token")||"";const[name,setName]=useState("");const[password,setPassword]=useState("");const[error,setError]=useState("");return <main className="auth-shell"><form className="card auth-card" onSubmit={async e=>{e.preventDefault();try{const value=await api<{user:User}>("/auth/register",{method:"POST",body:JSON.stringify({token,display_name:name,password})});onLogin(value.user)}catch(reason){setError(reason instanceof Error?reason.message:"Registration failed")}}}><div className="auth-brand-hero"><BrandLogo variant="hero"/><p className="eyebrow">Invitation</p><h1>Accept invitation</h1><p className="muted">Create your Black Onyx account with the invite token from your administrator.</p></div><ErrorState error={error}/><label>Display name<input autoComplete="name" value={name} onChange={e=>setName(e.target.value)} required/></label><label>Password<input type="password" autoComplete="new-password" minLength={12} maxLength={128} value={password} onChange={e=>setPassword(e.target.value)} required/></label><button>Create account</button></form></main>}
function ForgotPassword(){const[email,setEmail]=useState("");const[done,setDone]=useState(false);const[error,setError]=useState("");return <main className="auth-shell"><form className="card auth-card" onSubmit={async e=>{e.preventDefault();try{await api("/auth/password-reset/request",{method:"POST",body:JSON.stringify({email})});setDone(true)}catch(reason){setError(reason instanceof Error?reason.message:"Request failed")}}}><div className="auth-brand-hero"><BrandLogo variant="hero"/><h1>Reset password</h1><p className="muted">We email reset instructions when the account exists.</p></div>{done?<Notice>If the account exists, reset instructions have been sent.</Notice>:<><ErrorState error={error}/><label>Email<input type="email" value={email} onChange={e=>setEmail(e.target.value)} required/></label><button>Request reset</button></>}<Link to="/">Back to sign in</Link></form></main>}
function ResetPassword(){const token=new URLSearchParams(location.search).get("token")||"";const[password,setPassword]=useState("");const[done,setDone]=useState(false);const[error,setError]=useState("");return <main className="auth-shell"><form className="card auth-card" onSubmit={async e=>{e.preventDefault();try{await api("/auth/password-reset/confirm",{method:"POST",body:JSON.stringify({token,password})});setDone(true)}catch(reason){setError(reason instanceof Error?reason.message:"Reset failed")}}}><div className="auth-brand-hero"><BrandLogo variant="hero"/><h1>Choose a new password</h1></div>{done?<><Notice>Password changed and existing sessions closed.</Notice><Link to="/">Sign in</Link></>:<><ErrorState error={error}/><label>New password<input type="password" autoComplete="new-password" minLength={12} maxLength={128} value={password} onChange={e=>setPassword(e.target.value)} required/></label><button>Reset password</button></>}</form></main>}

function Dashboard(){
  const user=useUser();
  const ops=isOperational(user.role);
  const admin=isAdmin(user.role);
  const info=useQuery({queryKey:["info"],queryFn:()=>api<any>("/info")});
  const jobs=useQuery({queryKey:["jobs"],queryFn:()=>api<any>("/jobs")});
  const detections=useQuery({queryKey:["recent-detections"],queryFn:()=>api<any[]>("/connectors/detections/recent"),enabled:ops});
  const watchlistAlerts=useQuery({queryKey:["recent-alerts"],queryFn:()=>api<any>("/alerts?limit=10")});
  const kpis=useQuery({queryKey:["analytics-kpis-dash"],queryFn:()=>api<any>("/analytics/kpis?metrics=mtta,mttr,fpr,fresh_ioc_ratio&range=7d")});
  const overview=useQuery({queryKey:["analytics-overview-dash"],queryFn:()=>api<any>("/analytics/overview?range=7d")});
  const connectorHealth=useQuery({queryKey:["analytics-connectors-dash"],queryFn:()=>api<any>("/analytics/connectors/health"),enabled:admin||ops});
  const casePriority=useQuery({queryKey:["dash-case-priority"],queryFn:()=>api<any>("/analytics/distributions?metric=case_priority&range=30d")});
  const collections=(info.data?.collections||[]) as any[];
  const recent=(jobs.data?.jobs||[]).slice(0,5);
  const metrics=kpis.data?.metrics||{};
  const spark=(key:string)=>metrics[key]?.sparkline||overview.data?.sparklines?.[key]||[];
  const toSeries=(payload:any)=>((payload?.points||payload?.items||payload?.buckets||[]) as any[]).map((p)=>({label:String(p.label||p.key||""),value:Number(p.value??p.count??0)}));
  const alertSpark=(spark("alerts") as number[]).map((value,i)=>({label:String(i+1),value:Number(value)}));
  const freshPct=Number(metrics.fresh_ioc_ratio?.value??0);
  const kpiItems=[
    {label:"Open alerts",value:overview.data?.open_alerts??watchlistAlerts.data?.alerts?.length??"—",href:ops?"/triage":"/watchlists",sparkline:spark("alerts"),n:overview.data?.open_alerts_n},
    {label:"Open cases",value:overview.data?.open_cases??"—",href:"/cases",sparkline:spark("cases")},
    ...(ops?[
      {label:"Detections",value:overview.data?.detections_24h??(detections.data||[]).length,href:"/detections",sparkline:spark("detections")},
      {label:"MTTA",value:metrics.mtta?.value!=null?`${Math.round(Number(metrics.mtta.value)/60)}m`:"—",href:"/triage",n:metrics.mtta?.n,hint:"mean time to acknowledge"},
      {label:"Playbook success",value:overview.data?.playbook_success_rate!=null?`${(Number(overview.data.playbook_success_rate)*100).toFixed(0)}%`:"—",href:"/playbooks",n:overview.data?.playbook_n},
      {label:"Assets",value:overview.data?.asset_count??"—",href:"/assets"},
    ]:[]),
    {label:"Fresh IOC %",value:metrics.fresh_ioc_ratio?.value!=null?`${(Number(metrics.fresh_ioc_ratio.value)*100).toFixed(0)}%`:"—",href:"/decay",n:metrics.fresh_ioc_ratio?.n},
  ];
  return <><Heading kicker="Overview" title="Security operations overview" subtitle={ops?"Health plus disposition-aware ops KPIs. Deep-link into triage, cases, and analytics.":"Workspace health and read-only intel signals for your role."} actions={<Link className="button secondary compact" to="/analytics">Full analytics</Link>}/><ErrorState error={info.error||jobs.error}/>
  <KpiRow items={kpiItems}/>
  <div className="widget-grid">
    <section className="card widget-span-4"><div className="section-head"><div><span className="section-kicker">Volume</span><h2>Alerts (7d)</h2></div><Link className="button ghost compact" to="/analytics">Analytics</Link></div>
      {alertSpark.some((p)=>p.value>0)?<TimeSeriesArea data={alertSpark}/>:<EmptyState title="No alert volume yet" description="Watchlist alerts populate this sparkline." compact/>}
    </section>
    <section className="card widget-span-4"><div className="section-head"><div><span className="section-kicker">Cases</span><h2>By priority</h2></div><Link className="button ghost compact" to="/cases">Cases</Link></div>
      <HorizontalBars data={toSeries(casePriority.data)}/>
    </section>
    <section className="card widget-span-4"><div className="section-head"><div><span className="section-kicker">CTI</span><h2>Fresh vs stale</h2></div><Link className="button ghost compact" to="/decay">Decay</Link></div>
      <Donut data={[
        {label:"Fresh",value:Number.isFinite(freshPct)?Math.round(freshPct*100):0},
        {label:"Stale",value:Number.isFinite(freshPct)?Math.max(0,100-Math.round(freshPct*100)):0},
      ].filter((d)=>d.value>0)}/>
    </section>
  </div>
  <div className="metrics"><Metric label="Collections" value={collections.length||"—"}/><Metric label="Indexed points" value={formatCount(collections.reduce((sum:number,item:any)=>sum+(item.points_count||0),0))}/><Metric label="Active jobs" value={(jobs.data?.jobs||[]).filter((job:any)=>["queued","running","stopping"].includes(job.status)).length}/><Metric label="Qdrant" value={info.data?.qdrant_version||"Checking"}/></div>
  <div className="result-grid">
    <section className="card"><div className="section-head"><div><span className="section-kicker">Activity</span><h2>Recent jobs</h2></div><Link className="button secondary compact" to="/jobs">All jobs</Link></div>
      <DataTable
        columns={[
          {key:"job_type",label:"Type",render:(row:any)=><span className="chip">{humanizeLabel(String(row.job_type||""))}</span>},
          {key:"status",label:"Status",render:(row:any)=><span className={`status ${row.status}`}>{row.status}</span>},
          {key:"detail",label:"Progress",render:(row:any)=>row.detail?`${row.detail.processed??0}/${row.detail.total_files??0} files · ${row.detail.total_chunks??0} chunks${row.detail.errors?` · ${row.detail.errors} error(s)`:""}`:"—"},
          {key:"updated_at",label:"Updated",nowrap:true,render:(row:any)=>formatWhen(row.updated_at)},
        ]}
        rows={recent}
        rowKey={(row:any)=>row.job_id}
        empty={<EmptyState title="No jobs yet" description="Ingest evidence and its processing activity will show up here." compact/>}
      /></section>
    <section className="card"><div className="section-head"><div><span className="section-kicker">Vector store</span><h2>Collections</h2></div><Link className="button secondary compact" to="/collections">Browse</Link></div>
      <DataTable
        columns={[
          {key:"name",label:"Collection"},
          {key:"points_count",label:"Points",render:(row:any)=>formatCount(row.points_count??0)},
          {key:"vectors",label:"Vectors",render:(row:any)=>row.vectors?Object.keys(row.vectors).join(", "):"—"},
        ]}
        rows={[...collections].sort((left,right)=>(right.points_count||0)-(left.points_count||0))}
        rowKey={(row:any)=>row.name}
        empty={<EmptyState title="No collections" description="Create a collection or ingest evidence to get started." compact/>}
      /></section>
  </div>
  <div className="result-grid">
    {ops&&<section className="card"><div className="section-head"><div><span className="section-kicker">Connectors</span><h2>Recent pulled detections</h2></div><Link className="button secondary compact" to="/detections">All detections</Link></div>
      <DataTable
        columns={[
          {key:"connector",label:"Connector"},
          {key:"title",label:"Title",clip:true},
          {key:"ioc_status",label:"Status"},
          {key:"indexed_at",label:"Indexed",nowrap:true,render:(row:any)=>formatWhen(row.indexed_at)},
        ]}
        rows={detections.data||[]}
        rowKey={(row:any,index:number)=>`${row.connector}-${row.source_file}-${index}`}
        empty={<EmptyState title="No detections yet" description="Configure a connector to start pulling SIEM/EDR alerts in." compact/>}
      /></section>}
    <section className="card"><div className="section-head"><div><span className="section-kicker">Watchlists</span><h2>Recent alerts</h2></div><Link className="button secondary compact" to="/watchlists">All alerts</Link></div>
      <DataTable
        columns={[
          {key:"watchlist_name",label:"Watchlist",render:(row:any)=>row.watchlist_name||"—"},
          {key:"ioc_value",label:"Indicator",render:(row:any)=>`${row.ioc_type||"?"}: ${row.ioc_value||"—"}`,clip:true},
          {key:"disposition",label:"Disposition",render:(row:any)=>row.disposition?humanizeLabel(String(row.disposition)):"—"},
          {key:"triggered_at",label:"When",nowrap:true,render:(row:any)=>formatWhen(row.triggered_at)},
        ]}
        rows={watchlistAlerts.data?.alerts||[]}
        rowKey={(row:any)=>row.alert_id}
        empty={<EmptyState title="No alerts yet" description="Watchlist matches from ingested or pulled data will show up here." compact/>}
      /></section>
    {admin&&<section className="card"><div className="section-head"><div><span className="section-kicker">Admin</span><h2>Connector health</h2></div><Link className="button secondary compact" to="/system">System</Link></div>
      <DataTable
        columns={[
          {key:"name",label:"Connector"},
          {key:"status",label:"Status",render:(row:any)=><span className={`status ${row.status||"active"}`}>{row.status||"unknown"}</span>},
          {key:"last_poll",label:"Last poll",nowrap:true,render:(row:any)=>formatWhen(row.last_poll||row.updated_at)},
        ]}
        rows={connectorHealth.data?.connectors||connectorHealth.data||[]}
        rowKey={(row:any,i:number)=>row.id||row.name||String(i)}
        empty={<EmptyState title="No connector health" description="Configure connectors under System / Detections." compact/>}
      /></section>}
  </div></>;
}
function Metric({label,value}:{label:string;value:React.ReactNode}){return <article className="metric"><span>{label}</span><strong>{value}</strong></article>}
function Capabilities(){
  const query=useQuery({queryKey:["capabilities"],queryFn:()=>api<any>("/capabilities")});
  const data=query.data;
  const features=Object.entries(data?.features||{});
  const reasons=data?.disabled_reasons||{};
  return <><Heading title="System capabilities" subtitle="Configured providers and explicit unavailable-feature reasons." actions={<button type="button" className="secondary" onClick={()=>query.refetch()}>Refresh</button>}/><ErrorState error={query.error}/>
  {!data?<section className="card"><p className="muted">Loading capability report…</p></section>:<>
  <section className="card"><div className="section-head"><div><span className="section-kicker">Features</span><h2>Enabled capabilities</h2></div><span className="count-badge">{features.filter(([,value])=>value).length}/{features.length}</span></div>
    <DataTable
      columns={[
        {key:"feature",label:"Feature",render:(row:any)=>humanizeLabel(row.feature)},
        {key:"state",label:"State",render:(row:any)=><span className={`status ${row.enabled?"active":"failed"}`}>{row.enabled?"available":"unavailable"}</span>},
        {key:"reason",label:"Reason",render:(row:any)=>row.enabled?"—":(reasons[row.feature]||"Disabled by configuration")},
      ]}
      rows={features.map(([feature,enabled])=>({feature,enabled:!!enabled}))}
      rowKey={(row:any)=>row.feature}
    /></section>
  <div className="result-grid">
    <section className="card"><h2>Language model</h2><KeyValues items={[
      {label:"Provider",value:data.llm_provider||"—"},
      {label:"RAG",value:data.rag?.enabled?"Enabled":"Disabled"},
      {label:"RAG top K",value:data.rag?.top_k},
      {label:"RAG collections",value:(data.rag?.collections||[]).length?<Chips items={data.rag.collections}/>:"none",wide:true},
    ]}/></section>
    <section className="card"><h2>Web search</h2><KeyValues items={[
      {label:"Enabled",value:data.web_search?.enabled?"Yes":"No"},
      {label:"SearXNG reachable",value:data.web_search?.searxng_reachable?"Yes":"No"},
      {label:"Firecrawl key",value:data.web_search?.firecrawl_configured?"Configured":"Not configured"},
      {label:"Result collection",value:data.web_search?.collection||"—"},
    ]}/></section>
    <section className="card"><h2>Enrichment providers</h2>{(data.enrichment_providers||[]).length?<Chips items={data.enrichment_providers} tone="accent"/>:<p className="muted">Enrichment is disabled or no providers are configured.</p>}</section>
  </div>
  <section className="card"><RawJson data={data} label="Raw capability report"/></section></>}</>;
}

function ChatWorkflow() {
  const sessions = useQuery({queryKey:["sessions"], queryFn:()=>api<any[]>("/sessions")});
  const providers = useQuery({queryKey:["llm-providers"], queryFn:()=>api<{providers:string[]}>("/llm/providers")});
  const capabilities = useQuery({queryKey:["capabilities"], queryFn:()=>api<any>("/capabilities")});
  const [session,setSession] = useState("");
  const [provider,setProvider] = useState("local");
  const [messages,setMessages] = useState<{role:string;content:string;meta?:string}[]>([]);
  const [input,setInput] = useState("");
  const [images,setImages] = useState<File[]>([]);
  const [collections,setCollections] = useState<string[]>(["all-knowledge"]);
  const [useWebSearch,setUseWebSearch] = useState(false);
  const [sources,setSources] = useState<any[]>([]);
  const [tools,setTools] = useState<any[]>([]);
  const [error,setError] = useState("");
  const [streaming,setStreaming] = useState(false);
  const controller = useRef<AbortController>();
  const defaultsReady = useRef(false);

  useEffect(()=>{
    if(defaultsReady.current || !capabilities.data) return;
    const rag = capabilities.data?.rag?.collections;
    if(Array.isArray(rag)) { setCollections(rag); defaultsReady.current = true; }
  },[capabilities.data]);

  const webAvailable = Boolean(capabilities.data?.features?.web_search);

  async function load(id:string) {
    setSession(id); setImages([]); setSources([]); setTools([]);
    try {
      const value=await api<any>(`/sessions/${id}/messages`);
      setMessages(value.messages);
      const selected=(sessions.data||[]).find(item=>item.session_id===id);
      if(selected?.provider)setProvider(selected.provider);
    } catch(reason) { setError(reason instanceof Error?reason.message:"Load failed"); }
  }

  async function submit(e:FormEvent) {
    e.preventDefault(); const text=input.trim(); if(!text)return;
    setInput(""); setError(""); setStreaming(true); setSources([]); setTools([]);
    setMessages(old=>[...old,{role:"user",content:images.length?`${text}\n\n[${images.length} image(s) attached]`:text},{role:"assistant",content:""}]);
    try {
      if(images.length) {
        const body=new FormData();
        images.forEach(image=>body.append("images",image));
        body.append("message",text); body.append("provider",provider);
        if(session)body.append("session_id",session);
        const result=await api<any>("/chat/images",{method:"POST",body});
        setSession(result.session_id); setImages([]);
        setMessages(old=>old.map((item,index)=>index===old.length-1?{...item,content:result.response}:item));
      } else {
        controller.current=new AbortController();
        await streamChat({
          message:text,
          session_id:session||null,
          provider,
          collections,
          use_rag:collections.length>0,
          use_web_search:useWebSearch,
        },(event,data)=>{
          if(event==="session")setSession(JSON.parse(data).session_id);
          if(event==="token")setMessages(old=>old.map((item,index)=>index===old.length-1?{...item,content:item.content+data}:item));
          if(event==="source"){ try{ setSources(old=>[...old, JSON.parse(data)]); }catch{ /* ignore */ } }
          if(event==="tool"){ try{ setTools(old=>[...old, JSON.parse(data)]); }catch{ /* ignore */ } }
        },controller.current.signal);
      }
      sessions.refetch();
    } catch(reason) {
      if((reason as Error).name!=="AbortError")setError(reason instanceof Error?reason.message:"Chat failed");
    } finally { setStreaming(false); }
  }

  const footerParts = [
    images.length ? `${images.length} image${images.length===1?"":"s"} attached` : "",
    collections.length ? `RAG: ${collections.join(", ")}` : "RAG off",
    useWebSearch ? "Web search on" : "",
  ].filter(Boolean);

  const promptChips = [
    "Summarize open alerts and recommend dispositions",
    "Which IOCs should we enrich next?",
    "Draft an ops digest for the last 7 days",
  ];

  return <>
    <Heading kicker="AI assist" title="RAG analyst" subtitle="Private, provider-bound sessions with evidence rail, prompt chips, and tool status." actions={streaming?<button className="danger" onClick={()=>controller.current?.abort()}>Cancel stream</button>:undefined}/>
    <div className="chat-layout aikit">
      <section className="card session-panel">
        <div className="section-head"><div><span className="section-kicker">Workspace</span><h2>Sessions</h2></div><button className="compact" onClick={()=>{setSession("");setMessages([]);setImages([]);setSources([]);setTools([])}}>+ New</button></div>
        {(sessions.data||[]).length?<ul className="item-list session-list">{(sessions.data||[]).map(value=><li className={session===value.session_id?"selected":""} key={value.session_id}><button className="ghost" onClick={()=>load(value.session_id)}>{value.title}</button><button className="icon-danger" aria-label={`Delete ${value.title}`} onClick={async()=>{await api(`/sessions/${value.session_id}`,{method:"DELETE"});if(session===value.session_id){setSession("");setMessages([])}sessions.refetch()}}>×</button></li>)}</ul>:<EmptyState title="No conversations" description="Start a new private analyst session." compact />}
      </section>
      <section className="chat-stack">
        <div className="card chat" aria-live="polite">
          {messages.length?messages.map((item,index)=><article className={`bubble ${item.role}`} key={index}><span className="message-role">{item.role}</span><ReactMarkdown skipHtml>{item.content}</ReactMarkdown></article>):<EmptyState title="Ready for analysis" description="Ask about indexed evidence, indicators, or attach images for multimodal review." />}
        </div>
        <form className="card chat-composer" onSubmit={submit}>
          <div className="prompt-chips">{promptChips.map(chip=><button key={chip} type="button" className="ghost" onClick={()=>setInput(chip)}>{chip}</button>)}</div>
          <div className="composer-toolbar">
            <label className="composer-provider">Provider<select value={provider} disabled={!!session} onChange={e=>setProvider(e.target.value)}>{(providers.data?.providers||["local"]).map(value=><option key={value}>{value}</option>)}</select></label>
            <label className="composer-chip file-control"><span>Attach</span><input type="file" accept="image/*" multiple onChange={e=>setImages(Array.from(e.target.files||[]).slice(0,5))}/></label>
            <RagCollectionPicker values={collections} onChange={setCollections}/>
            <label className={`composer-chip ${useWebSearch?"active":""} ${!webAvailable?"disabled":""}`} title={!webAvailable?"Enable SearXNG in Settings":undefined}>
              <input type="checkbox" checked={useWebSearch} disabled={!webAvailable} onChange={e=>setUseWebSearch(e.target.checked)}/>
              Web search
            </label>
          </div>
          {images.length>0&&<p className="composer-attachment-summary">{images.length} image{images.length===1?"":"s"} ready · {images.map(file=>file.name).join(", ")}</p>}
          <label className="message-field"><span className="visually-hidden">Message</span><textarea rows={3} placeholder="Ask Black Onyx to analyze the current evidence…" value={input} onChange={e=>setInput(e.target.value)} required/></label>
          <div className="composer-footer"><small>{footerParts.join(" · ") || "Direct model reply"}</small><button disabled={streaming}>Send message</button></div>
        </form>
        <ErrorState error={error||providers.error}/>
      </section>
      <aside className="card evidence-rail">
        <div className="section-head"><div><span className="section-kicker">Evidence</span><h2>Sources & tools</h2></div></div>
        {!tools.length&&!sources.length?<EmptyState title="No evidence yet" description="RAG hits and tool calls appear here while you chat." compact/>:<>
          {!!tools.length&&<div className="evidence-rail-block"><h3>Tools</h3><ul className="item-list">{tools.map((tool,index)=><li key={`t-${index}`}><span><b>{tool.name||"tool"}</b><small>{tool.status||"running"}{tool.args?.query?` · ${tool.args.query}`:tool.args?.url?` · ${tool.args.url}`:""}</small></span></li>)}</ul></div>}
          {!!sources.length&&<div className="evidence-rail-block"><h3>Sources</h3><ul className="item-list">{sources.slice(0,12).map((source,index)=>{
            const payload=source.payload||{};
            const label=payload.title||payload.source_file||payload.url||source.id||`source ${index+1}`;
            const collection=payload.collection||source.collection||"";
            const q=encodeURIComponent(String(payload.source_file||payload.title||label).slice(0,120));
            return <li key={`s-${index}`}>
              <span><b>{String(label).slice(0,90)}</b><small>{collection?`${collection} · `:""}{source.score!=null?`score ${Number(source.score).toFixed(3)}`:"RAG hit"}</small></span>
              <div className="actions">
                <Link className="button ghost compact" to={`/search?q=${q}`}>Search</Link>
                <Link className="button ghost compact" to="/graph">Graph</Link>
              </div>
            </li>;
          })}</ul></div>}
        </>}
      </aside>
    </div>
  </>;
}

function MfaDisable(){const[password,setPassword]=useState("");const[code,setCode]=useState("");const[notice,setNotice]=useState("");const[error,setError]=useState("");return <form className="card" onSubmit={async e=>{e.preventDefault();setError("");try{await api("/auth/mfa/disable",{method:"POST",body:JSON.stringify({password,code})});setPassword("");setCode("");setNotice("MFA is disabled for this account.")}catch(reason){setError(reason instanceof Error?reason.message:"Unable to disable MFA")}}}><h2>Disable MFA</h2><p>Confirm with your password and a current authenticator or recovery code.</p><ErrorState error={error}/>{notice&&<Notice>{notice}</Notice>}<label>Password<input type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} required/></label><label>MFA or recovery code<input autoComplete="one-time-code" value={code} onChange={e=>setCode(e.target.value)} required/></label><button className="danger">Disable MFA</button></form>}

function Profile(){const[current,setCurrent]=useState("");const[next,setNext]=useState("");const[uri,setUri]=useState("");const[code,setCode]=useState("");const[recovery,setRecovery]=useState<string[]>([]);const[error,setError]=useState("");return <><Heading title="Profile" subtitle="Change your password and configure or disable TOTP MFA."/><ErrorState error={error}/><div className="result-grid"><form className="card" onSubmit={async e=>{e.preventDefault();try{await api("/auth/password/change",{method:"POST",body:JSON.stringify({current_password:current,new_password:next})});location.reload()}catch(reason){setError(reason instanceof Error?reason.message:"Change failed")}}}><h2>Change password</h2><label>Current password<input type="password" value={current} onChange={e=>setCurrent(e.target.value)} required/></label><label>New password<input type="password" minLength={12} value={next} onChange={e=>setNext(e.target.value)} required/></label><button>Change and sign out</button></form><section className="card"><h2>Authenticator MFA</h2>{!uri?<button onClick={async()=>{const value=await api<any>("/auth/mfa/begin",{method:"POST"});setUri(value.provisioning_uri)}}>Begin enrollment</button>:<><label>Provisioning URI<input readOnly value={uri}/></label><label>Verification code<input value={code} onChange={e=>setCode(e.target.value)}/></label><button onClick={async()=>{const value=await api<any>("/auth/mfa/confirm",{method:"POST",body:JSON.stringify({code})});setRecovery(value.recovery_codes)}}>Confirm MFA</button></>}{recovery.length>0&&<><h3>Save each recovery code once</h3><Chips items={recovery} tone="accent"/></>}</section><MfaDisable/></div></>}

// Route -> "Section / Page" for the top bar breadcrumb. Derived from the same
// navigationGroups the sidebar renders, so a new page gets a correct crumb by
// being added in exactly one place.
const ROUTE_CRUMBS = new Map<string,{group:string;label:string}>();
for(const group of navigationGroups) for(const [label,path] of group.items) ROUTE_CRUMBS.set(path,{group:group.label,label});
ROUTE_CRUMBS.set("/admin",{group:"Control",label:"Administration"});
ROUTE_CRUMBS.set("/settings",{group:"Control",label:"Settings"});
ROUTE_CRUMBS.set("/profile",{group:"Account",label:"Profile"});

function TopBar({user,onLogout,onOpenTheme}:{user:User;onLogout:()=>void;onOpenTheme:()=>void}){
  const {pathname}=useLocation();
  const crumb=ROUTE_CRUMBS.get(pathname);
  const [menu,setMenu]=useState<"none"|"alerts"|"profile">("none");
  const alerts=useQuery({queryKey:["topbar-alerts"],queryFn:()=>api<any>("/alerts?unacknowledged_only=true&limit=8"),refetchInterval:20_000});
  const alertRows=alerts.data?.alerts||[];
  return <header className="topbar">
    <nav className="crumbs" aria-label="Breadcrumb">
      <Link to="/">Gallery</Link>
      {crumb&&<><span className="sep" aria-hidden="true">/</span><span>{crumb.group}</span><span className="sep" aria-hidden="true">/</span><b aria-current="page">{crumb.label}</b></>}
    </nav>
    <div className="topbar-right">
      <button type="button" className="ghost compact" aria-label="Theme" onClick={onOpenTheme}><Icons.theme /></button>
      <div className="dropdown-host">
        <button type="button" className="ghost compact" aria-label="Notifications" onClick={()=>setMenu(menu==="alerts"?"none":"alerts")}><Icons.bell />{alertRows.length?<span className="count-badge">{alertRows.length}</span>:null}</button>
        {menu==="alerts"&&<div className="dropdown-menu" role="menu">
          {alertRows.length?alertRows.map((row:any)=><Link key={row.alert_id} to="/triage" onClick={()=>setMenu("none")}><span className="dropdown-item-meta"><b>{row.ioc_value||row.alert_id}</b><small>{row.watchlist_name||"Watchlist"} · {formatWhen(row.triggered_at)}</small></span></Link>):<div className="dropdown-empty">No open alerts</div>}
          <Link to="/triage" onClick={()=>setMenu("none")}>Open triage</Link>
        </div>}
      </div>
      <div className="dropdown-host">
        <button type="button" className="ghost compact" onClick={()=>setMenu(menu==="profile"?"none":"profile")}>
          <span className="avatar" aria-hidden="true">{user.display_name.slice(0,1).toUpperCase()}</span>
          <span className="topbar-user"><span>{user.display_name}</span><span className="topbar-role">{user.role}</span></span>
        </button>
        {menu==="profile"&&<div className="dropdown-menu" role="menu">
          <NavLink to="/profile" onClick={()=>setMenu("none")}><Icons.user /><span>Profile</span></NavLink>
          {isAdmin(user.role)&&<NavLink to="/settings" onClick={()=>setMenu("none")}><Icons.settings /><span>Settings</span></NavLink>}
          <button type="button" onClick={()=>{setMenu("none");onOpenTheme()}}><Icons.theme /><span>Theme</span></button>
          <button type="button" onClick={()=>{setMenu("none");onLogout()}}><Icons.logout /><span>Log out</span></button>
        </div>}
      </div>
    </div>
  </header>;
}

function ClassicShell({user,onLogout}:{user:User;onLogout:()=>void}){
  const theme=useTheme();
  const [themeOpen,setThemeOpen]=useState(false);
  const info=useQuery({queryKey:["info"],queryFn:()=>api<any>("/info")});
  return <div className={`app-shell ${theme.sidebar==="mini"?"sidebar-mini":""}`} id="main-wrapper">
    <a className="skip-link" href="#main">Skip to content</a>
    <aside>
      <div className="brand">
        <BrandLogo variant="lockup" />
        <button type="button" className="ghost compact" aria-label="Toggle sidebar" onClick={theme.toggleSidebar}>{theme.sidebar==="mini"?<Icons.chevronRight/>:<Icons.chevronLeft/>}</button>
      </div>
      <div className="nav-scroll"><nav aria-label="Primary">{navigationGroups.map(group=>{
        const items=group.items.filter(([,path])=>visibleFor(user.role,path));
        return items.length?<section className="nav-group" key={group.label}><p>{group.label}</p>{items.map(([label,path,icon])=><NavLink key={path} to={path} end={path==="/"} title={label}><NavIcon name={PATH_ICONS[path]||icon}/><span className="nav-label">{label}</span></NavLink>)}</section>:null;
      })}{isAdmin(user.role)&&<section className="nav-group"><p>Control</p><NavLink to="/admin" title="Administration"><NavIcon name="admin"/><span className="nav-label">Administration</span></NavLink><NavLink to="/settings" title="Settings"><NavIcon name="settings"/><span className="nav-label">Settings</span></NavLink></section>}</nav></div>
      <div className="shell-footer"><span className="shell-footer-copy">v{info.data?.version||"1.0.0"}</span></div>
    </aside>
    <main className="workspace" id="main">
      <TopBar user={user} onLogout={onLogout} onOpenTheme={()=>setThemeOpen(true)}/>
      <div className="workspace-inner"><React.Suspense fallback={<p>Loading detection console…</p>}><Outlet/></React.Suspense></div>
    </main>
    <ThemePanel open={themeOpen} onClose={()=>setThemeOpen(false)}/>
  </div>;
}

// The immersive gallery at "/" is deliberately routed OUTSIDE ClassicShell: it
// owns the entire viewport (full-bleed void with floating chrome), so nesting
// it in the sidebar shell would box it into the right-hand column and lose the
// immersive layout entirely. Every other route keeps the classic shell.
function Layout({user,onLogout}:{user:User;onLogout:()=>void}){const operational=isOperational(user.role);return <UserProvider user={user}><Routes><Route path="/" element={<GalleryHub onLogout={onLogout}/>}/><Route path="/hub" element={<Navigate to="/" replace/>}/><Route element={<ClassicShell user={user} onLogout={onLogout}/>}><Route path="/dashboard" element={<Dashboard/>}/><Route path="/analytics" element={<AnalyticsWorkflow/>}/><Route path="/trends" element={<TrendsWorkflow/>}/><Route path="/jobs" element={operational?<JobsWorkflow/>:<Navigate to="/"/>}/><Route path="/ingest" element={operational?<IngestWorkflow role={user.role}/>:<Navigate to="/"/>}/><Route path="/search" element={<SearchWorkflow/>}/><Route path="/query" element={operational?<QueryWorkflow/>:<Navigate to="/"/>}/><Route path="/image-search" element={<ImageSearchWorkflow/>}/><Route path="/collections" element={<CollectionsWorkflow role={user.role}/>}/><Route path="/chat" element={operational?<ChatWorkflow/>:<Navigate to="/"/>}/><Route path="/iocs" element={operational?<IOCWorkflow/>:<Navigate to="/"/>}/><Route path="/attack" element={<AttackWorkflow admin={isAdmin(user.role)}/>}/><Route path="/graph" element={<GraphWorkflow/>}/><Route path="/rules" element={operational?<RulesWorkflow/>:<Navigate to="/"/>}/><Route path="/reports" element={<ReportsWorkflow role={user.role}/>}/><Route path="/content" element={<ContentWorkflow/>}/><Route path="/triage" element={operational?<TriageWorkflow/>:<Navigate to="/"/>}/><Route path="/detection" element={operational?<DetectionOverviewWorkflow/>:<Navigate to="/"/>}/><Route path="/incidents" element={operational?<IncidentsWorkflow/>:<Navigate to="/"/>}/><Route path="/incidents/:id" element={operational?<IncidentDetailWorkflow/>:<Navigate to="/"/>}/><Route path="/findings" element={operational?<FindingsWorkflow/>:<Navigate to="/"/>}/><Route path="/findings/:id" element={operational?<FindingsWorkflow/>:<Navigate to="/"/>}/><Route path="/hunt" element={operational?<HuntWorkflow/>:<Navigate to="/"/>}/><Route path="/malware" element={operational?<MalwareWorkflow/>:<Navigate to="/"/>}/><Route path="/attack-coverage" element={<AttackCoverageWorkflow/>}/><Route path="/models" element={operational?<ModelsWorkflow/>:<Navigate to="/"/>}/><Route path="/models/:id" element={operational?<ModelsWorkflow/>:<Navigate to="/"/>}/><Route path="/detection-services" element={operational?<DetectionServicesWorkflow/>:<Navigate to="/"/>}/><Route path="/detection/metrics" element={operational?<DetectionMetricsWorkflow/>:<Navigate to="/"/>}/><Route path="/detection/network" element={operational?<DetectionNetworkWorkflow/>:<Navigate to="/"/>}/><Route path="/detection/code-changes" element={operational?<DetectionCodeChangesWorkflow/>:<Navigate to="/"/>}/><Route path="/data-health" element={operational?<DataHealthWorkflow/>:<Navigate to="/"/>}/><Route path="/response-queue" element={operational?<ResponseQueueWorkflow/>:<Navigate to="/"/>}/><Route path="/security-profiles" element={operational?<SecurityProfilesWorkflow/>:<Navigate to="/"/>}/><Route path="/detection-admin" element={<Navigate to="/admin" replace/>}/><Route path="/cases" element={<CasesWorkflow role={user.role}/>}/><Route path="/watchlists" element={<WatchlistsWorkflow role={user.role}/>}/><Route path="/feeds" element={<FeedsWorkflow role={user.role}/>}/><Route path="/detections" element={operational?<DetectionsWorkflow/>:<Navigate to="/"/>}/><Route path="/assets" element={operational?<AssetsWorkflow/>:<Navigate to="/"/>}/><Route path="/assets/:id" element={operational?<AssetDetailWorkflow/>:<Navigate to="/"/>}/><Route path="/services" element={<Navigate to="/detection-services" replace/>}/><Route path="/playbooks" element={<PlaybooksWorkflow role={user.role}/>}/><Route path="/publishing" element={<PublishingWorkflow role={user.role}/>}/><Route path="/decay" element={<DecayWorkflow role={user.role}/>}/><Route path="/bookmarks" element={<BookmarksWorkflow/>}/><Route path="/system" element={<Capabilities/>}/><Route path="/profile" element={<Profile/>}/><Route path="/admin" element={isAdmin(user.role)?<AdminWorkflow/>:<Navigate to="/"/>}/><Route path="/settings" element={isAdmin(user.role)?<SettingsWorkflow/>:<Navigate to="/"/>}/></Route><Route path="*" element={<Navigate to="/"/>}/></Routes></UserProvider>}

function Root(){const[user,setUser]=useState<User|null>(null);const[checking,setChecking]=useState(true);const navigate=useNavigate();useEffect(()=>{const expired=()=>setUser(null);window.addEventListener("blackonyx:session-expired",expired);api<{user:User}>("/auth/me").then(value=>setUser(value.user)).catch(()=>{}).finally(()=>setChecking(false));return()=>window.removeEventListener("blackonyx:session-expired",expired)},[]);if(checking)return <main className="auth-shell"><p>Loading secure workspace…</p></main>;if(location.pathname==="/register"&&!user)return <Register onLogin={value=>{setUser(value);navigate("/")}}/>;if(location.pathname==="/forgot-password"&&!user)return <ForgotPassword/>;if(location.pathname==="/reset-password"&&!user)return <ResetPassword/>;if(!user)return <Login onLogin={setUser}/>;return <Layout user={user} onLogout={async()=>{try{await api("/auth/logout",{method:"POST"})}finally{setUser(null);queryClient.clear()}}}/>}

ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><QueryClientProvider client={queryClient}><ThemeProvider><ToastProvider><BrowserRouter><Root/></BrowserRouter></ToastProvider></ThemeProvider></QueryClientProvider></React.StrictMode>);

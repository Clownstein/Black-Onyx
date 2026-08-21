import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, Role } from "./api";
import { Donut, HorizontalBars } from "./components/charts";
import { OpsSurfaceKpis } from "./components/ops_kpis";
import { Chips, CollectionSelect, DataTable, EmptyState, ErrorState, Heading, KeyValues, Notice, PayloadView, RawJson, ScoreBar, StatRow, downloadJson, formatWhen, humanizeLabel } from "./ui";
import { GraphView } from "./graph_view";
import { AttackHeatmap } from "./heatmap";

function useAction() {
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  const run = useCallback(async <T,>(operation: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true); setError(""); try { return await operation(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Request failed"); }
    finally { setBusy(false); }
  }, []);
  return { run, busy, error, setError };
}

const TOP_ATTACK_TECHNIQUES = [
  { id: "T1566", name: "Phishing", description: "Adversaries send phishing messages to gain access or execute malicious code." },
  { id: "T1059", name: "Command and Scripting Interpreter", description: "Abuse of interpreters such as PowerShell, Bash, Python, or cmd." },
  { id: "T1204", name: "User Execution", description: "Reliance on a user opening a malicious file or link." },
  { id: "T1027", name: "Obfuscated Files or Information", description: "Hiding malicious artifacts with encoding, packing, or encryption." },
  { id: "T1055", name: "Process Injection", description: "Injecting code into processes to evade defenses and escalate privileges." },
  { id: "T1003", name: "OS Credential Dumping", description: "Dumping credentials from OS memory, SAM, or LSASS." },
  { id: "T1078", name: "Valid Accounts", description: "Using compromised or existing accounts to blend in." },
  { id: "T1047", name: "Windows Management Instrumentation", description: "Abuse of WMI for execution and lateral movement." },
  { id: "T1105", name: "Ingress Tool Transfer", description: "Transferring tools or files into a compromised environment." },
  { id: "T1036", name: "Masquerading", description: "Making malicious artifacts look legitimate." },
] as const;

function parseList(raw: string): string[] {
  return raw.split(/[\s,;\n]+/).map(v => v.trim()).filter(Boolean);
}

function buildIocObject(ips: string, domains: string, urls: string, hashes: string, emails: string) {
  return {
    ips: parseList(ips),
    domains: parseList(domains),
    urls: parseList(urls),
    hashes: parseList(hashes),
    emails: parseList(emails),
  };
}

export function SearchWorkflow() {
  const [query, setQuery] = useState(""); const [collection, setCollection] = useState("all-knowledge"); const [results, setResults] = useState<any[]>([]); const action = useAction();
  async function submit(event: FormEvent) { event.preventDefault(); const response = await action.run(() => api<any>("/search", { method: "POST", body: JSON.stringify({ query, collection, limit: 25 }) })); if (response) setResults(response.results); }
  return <><Heading title="Semantic search" subtitle="Search indexed TIP evidence in Qdrant. For OpenSearch / federated detection hunt, use Hunt." actions={<Link className="button secondary compact" to="/hunt">Hunt</Link>}/><form className="card search-row" onSubmit={submit}><label className="grow">Query<input value={query} onChange={e=>setQuery(e.target.value)} required/></label><CollectionSelect value={collection} onChange={setCollection} required/><button disabled={action.busy}>Search</button></form><ErrorState error={action.error}/><div className="result-grid">{results.map(result=><article className="card" key={result.id}><h3>{result.payload?.source_file || result.id}</h3><p>{String(result.payload?.body_text || "No text preview").slice(0,800)}</p><p><b>Score:</b> {Number(result.score).toFixed(3)}</p></article>)}</div></>;
}

export function ImageSearchWorkflow() {
  const [image, setImage] = useState<File>(); const [collection, setCollection] = useState("all-knowledge"); const [data, setData] = useState<any>(); const action = useAction();
  async function submit(event: FormEvent) { event.preventDefault(); if (!image) return; const body = new FormData(); body.append("image", image); body.append("collection", collection); const result = await action.run(() => api<any>("/search/image", { method: "POST", body })); if (result) setData(result); }
  const results = data?.results || [];
  return <><Heading title="Image search" subtitle="Upload an image for collection-scoped CLIP similarity search."/><form className="card form-grid" onSubmit={submit}><CollectionSelect value={collection} onChange={setCollection} required/><label>Image<input type="file" accept="image/*" onChange={e=>setImage(e.target.files?.[0])} required/></label><button disabled={action.busy}>Search images</button></form><ErrorState error={action.error}/>
  {data&&(results.length?<div className="result-grid">{results.map((result:any)=><article className="card" key={result.id}>
    <div className="section-head"><div><span className="section-kicker">Match</span><h3>{result.payload?.source_file?.split(/[\\/]/).pop()||result.id}</h3></div><span className="status active">{Number(result.score).toFixed(3)}</span></div>
    <PayloadView payload={result.payload||{}}/>
  </article>)}</div>:<section className="card"><EmptyState title="No visual matches" description="No indexed image in this collection was similar enough to the upload. Try another collection or a different image." compact/></section>)}</>;
}

function TechniqueResults({ title, techniques }: { title: string; techniques: any[] }) {
  if (!techniques.length) return <section className="card"><EmptyState title="No techniques found" description="Nothing matched. Try a different query, or paste text that contains technique IDs such as T1059." compact/></section>;
  return <section className="card">
    <div className="section-head"><div><span className="section-kicker">Results</span><h2>{title}</h2></div><span className="count-badge">{techniques.length}</span></div>
    <div className="result-grid">{techniques.map((tech:any)=><article className="card" key={tech.technique_id}>
      <h3>{tech.technique_id} · {tech.name||"Unknown"}</h3>
      {!!(tech.tactic||[]).length&&<Chips items={tech.tactic.map((value:string)=>value.replace(/-/g," "))} tone="accent"/>}
      <p>{String(tech.description||"No description available.").slice(0,420)}</p>
      {!!(tech.platforms||[]).length&&<KeyValues items={[{label:"Platforms",value:tech.platforms.join(", ")}]}/>}
      <div className="actions"><a className="button secondary compact" href={tech.url||`https://attack.mitre.org/techniques/${String(tech.technique_id).replace(".","/")}/`} target="_blank" rel="noreferrer">Open in ATT&CK</a></div>
    </article>)}</div>
    <RawJson data={techniques}/>
  </section>;
}

export function IOCWorkflow() {
  const [text,setText]=useState(""); const [iocs,setIocs]=useState<Record<string,string[]>>({}); const [iocType,setType]=useState("ip"); const [iocValue,setValue]=useState(""); const [result,setResult]=useState<any>(); const action=useAction();
  async function extract(event:FormEvent){event.preventDefault();const data=await action.run(()=>api<any>("/ioc/extract",{method:"POST",body:JSON.stringify({text,include_defanged:true})}));if(data)setIocs(data.iocs)}
  async function enrich(){const data=await action.run(()=>api<any>("/enrich",{method:"POST",body:JSON.stringify({ioc_type:iocType,ioc_value:iocValue})}));if(data)setResult(data)}
  async function score(){const data=await action.run(()=>api<any>("/threat/score",{method:"POST",body:JSON.stringify({ioc_type:iocType,ioc_value:iocValue})}));if(data)setResult(data)}
  async function stix(){const flat=Object.entries(iocs).flatMap(([type,values])=>values.map(value=>({ioc_type:type,ioc_value:value})));const data=await action.run(()=>api<any>("/stix/export",{method:"POST",body:JSON.stringify({iocs:flat})}));if(data)downloadJson("black-onyx-stix.json",data.bundle)}
  const providers=useQuery({queryKey:["enrich-providers"],queryFn:()=>api<any>("/enrich/providers"),retry:false});
  const verdicts=useQuery({queryKey:["ioc-enrichment-verdicts"],queryFn:()=>api<any>("/analytics/distributions?metric=enrichment_verdict&range=30d")});
  const enrichCoverage=useQuery({queryKey:["ioc-enrichment-coverage"],queryFn:()=>api<any>("/analytics/distributions?metric=enrichment_coverage&range=30d")});
  const ctiImpact=useQuery({queryKey:["ioc-cti-impact"],queryFn:()=>api<any>("/analytics/cti/impact?range=30d")});
  const groups=Object.entries(iocs).filter(([,values])=>Array.isArray(values)&&values.length);
  const totalIocs=groups.reduce((sum,[,values])=>sum+values.length,0);
  const toSeries=(payload:any)=>((payload?.items||payload?.buckets||[]) as any[]).map((p)=>({label:String(p.label||p.key||""),value:Number(p.value??p.count??0)}));
  return <><Heading title="IOC workbench" subtitle="Extract, enrich, score, defang, and export indicators. Feed and webhook sightings also populate Decay."/><OpsSurfaceKpis metrics="fresh_ioc_ratio,intel_hit_rate,fpr,mtta" />
  <div className="widget-grid">
    <section className="card widget-span-4"><div className="section-head"><div><span className="section-kicker">Enrichment</span><h2>Verdict mix</h2></div></div><Donut data={toSeries(verdicts.data)} /></section>
    <section className="card widget-span-4"><div className="section-head"><div><span className="section-kicker">Coverage</span><h2>Cache outcomes</h2></div></div><Donut data={toSeries(enrichCoverage.data)} /></section>
    <section className="card widget-span-4"><div className="section-head"><div><span className="section-kicker">CVE board</span><h2>Top risk</h2></div><Link className="button ghost compact" to="/analytics">Analytics</Link></div>
      <HorizontalBars data={(ctiImpact.data?.cves||[]).slice(0,8).map((p:any)=>({label:String(p.cve_id||p.label||"").slice(0,14),value:Number(p.score||p.epss||0)}))} />
    </section>
  </div>
  <div className="ioc-layout"><div className="ioc-primary"><form className="card form-grid" onSubmit={extract}><div className="section-head"><div><span className="section-kicker">Step 1</span><h2>Extract from threat text</h2></div></div><label>Threat text<textarea rows={10} placeholder="Paste an alert, report, email, or raw intelligence…" value={text} onChange={e=>setText(e.target.value)} required/></label><button disabled={action.busy}>Extract indicators</button></form>
  <section className="card"><div className="section-head"><div><span className="section-kicker">Results</span><h2>Extracted indicators</h2></div><button type="button" className="secondary" disabled={!totalIocs} onClick={stix}>Export STIX 2.1</button></div>
  {groups.length?<>
    <StatRow items={[{label:"Indicators",value:totalIocs,tone:"ok"},{label:"Types",value:groups.length}]}/>
    <div className="entity-groups">{groups.map(([type,values])=><div className="entity-group" key={type}>
      <span className="entity-group-label">{humanizeLabel(type)} <small>{values.length}</small></span>
      <Chips items={values} max={50}/>
    </div>)}</div>
    <RawJson data={iocs}/>
  </>:<EmptyState title="No indicators yet" description="Paste threat text on the left and extract to populate IPs, domains, URLs, hashes, emails, and CVEs." compact/>}
  </section></div>
  <section className="card enrichment-panel"><div className="section-head"><div><span className="section-kicker">Step 2</span><h2>Enrich and score</h2></div></div><p className="section-description">Inspect one indicator against configured providers, then calculate its composite risk score. Configure free/paid API keys under Settings → Enrichment APIs.</p><div className="field-row"><label>IOC type<select value={iocType} onChange={e=>setType(e.target.value)}><option>ip</option><option>domain</option><option>url</option><option>hash</option><option>email</option><option>cve</option></select></label><label>IOC value<input value={iocValue} onChange={e=>setValue(e.target.value)} required/></label></div><div className="actions"><button type="button" disabled={!iocValue||action.busy} onClick={enrich}>Run enrichment</button><button type="button" className="secondary" disabled={!iocValue||action.busy} onClick={score}>Calculate score</button></div>
  <div className="result-surface">{result?<EnrichmentResult result={result}/>:<EmptyState title="No indicator inspected yet" description="Enter an indicator above, then run enrichment or calculate its composite score." compact/>}</div>
  {providers.data&&<p className="section-description">Active providers: {providers.data.enabled===false?"enrichment disabled":(providers.data.providers||[]).map((p:any)=>p.name||p).join(", ")||"none configured"}</p>}</section></div><ErrorState error={action.error}/></>;
}

function EnrichmentResult({ result }: { result: any }) {
  const providerResults=result.results||result.contributing_providers||[];
  const isScore=typeof result.score==="number";
  return <div className="enrich-result">
    <KeyValues items={[
      {label:"Indicator",value:result.ioc_value,wide:true},
      ...(result.ioc_type?[{label:"Type",value:String(result.ioc_type)}]:[]),
      ...(isScore?[{label:"Verdict",value:<span className={`status ${result.verdict==="malicious"?"failed":result.verdict==="suspicious"?"running":"active"}`}>{result.verdict}</span>}]:[]),
      ...(isScore?[{label:"Composite score",value:<ScoreBar value={result.score}/>}]:[]),
      ...(typeof result.malicious_count==="number"?[{label:"Malicious hits",value:`${result.malicious_count} of ${result.total_providers||providerResults.length}`}]:[]),
    ]}/>
    {providerResults.length?<div className="table-wrap"><table><thead><tr><th>Provider</th><th>Verdict</th><th>Detail</th></tr></thead>
      <tbody>{providerResults.map((entry:any,index:number)=>{
        const verdict=entry.verdict||(entry.malicious?"malicious":entry.error?"error":"clean");
        const detail=entry.error||entry.summary||Object.entries(entry).filter(([key,value])=>!["provider","name","verdict","malicious","error","summary","raw","ioc_value","ioc_type"].includes(key)&&value!=null&&typeof value!=="object").map(([key,value])=>`${humanizeLabel(key)}: ${value}`).join(" · ");
        return <tr key={`${entry.provider||entry.name||index}`}>
          <td>{entry.provider||entry.name||"provider"}</td>
          <td><span className={`status ${verdict==="malicious"?"failed":verdict==="error"?"failed":verdict==="suspicious"?"running":"active"}`}>{verdict}</span></td>
          <td>{detail||"—"}</td>
        </tr>;
      })}</tbody></table></div>:<p className="muted">No provider returned data. Add enrichment API keys under Settings → Enrichment APIs.</p>}
    <RawJson data={result}/>
  </div>;
}

export function AttackWorkflow({admin}:{admin:boolean}) {
  const [query,setQuery]=useState("");
  const [text,setText]=useState("");
  const [ids,setIds]=useState(TOP_ATTACK_TECHNIQUES.map(t=>t.id).join(", "));
  const [techniques,setTechniques]=useState<{title:string;items:any[]}>();
  const [heatmap,setHeatmap]=useState<any>();
  const [heatmapTitle,setHeatmapTitle]=useState("Top 10 technique heatmap");
  const [notice,setNotice]=useState("");
  const action=useAction();
  const runAction=action.run;
  useEffect(()=>{
    let cancelled=false;
    (async()=>{
      const value=await runAction(()=>api<any>("/attack/heatmap",{method:"POST",body:JSON.stringify(TOP_ATTACK_TECHNIQUES.map(t=>t.id))}));
      if(!cancelled && value) setHeatmap(value);
    })();
    return ()=>{cancelled=true};
  },[runAction]);
  async function buildHeatmap(rawIds:string,title:string){
    const list=rawIds.split(/[\s,]+/).filter(Boolean);
    const value=await action.run(()=>api<any>("/attack/heatmap",{method:"POST",body:JSON.stringify(list)}));
    if(value){setHeatmap(value);setHeatmapTitle(title)}
  }
  const orgCoverage=useQuery({queryKey:["attack-org-coverage"],queryFn:()=>api<any>("/analytics/attack/coverage?range=30d")});
  return <><Heading title="MITRE ATT&CK" subtitle="Search, extract, map, and refresh digest-pinned ATT&CK data." actions={admin?<button type="button" onClick={async()=>{const value=await action.run(()=>api<any>("/admin/attack/refresh",{method:"POST"}));if(value)setNotice(value.message||"ATT&CK cache refreshed.")}}>Refresh cache</button>:undefined}/>
  <OpsSurfaceKpis metrics="intel_hit_rate,alert_case_ratio,escalation_rate,mtta" />
  {notice&&<Notice>{notice}</Notice>}
  <section className="card"><div className="section-head"><div><span className="section-kicker">Org sightings</span><h2>Coverage vs claimed rules</h2></div>
    <button type="button" className="secondary compact" onClick={()=>{
      const payload=orgCoverage.data?.navigator||orgCoverage.data;
      if(!payload)return;
      const url=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:"application/json"}));
      const a=document.createElement("a");a.href=url;a.download="attack-navigator.json";a.click();URL.revokeObjectURL(url);
    }}>Export Navigator JSON</button>
  </div>
  <p className="muted">Risk-weighted org sightings with Sigma/YARA claimed tags. Index {orgCoverage.data?.coverage_index??"—"} — not a 100% coverage goal.</p>
  <DataTable searchable columns={[
    {key:"technique_id",label:"Technique"},
    {key:"name",label:"Name",clip:true},
    {key:"sightings",label:"Sightings",sortable:true},
    {key:"covered",label:"Claimed",render:(row:any)=>row.covered?"Yes":"No"},
    {key:"gap",label:"Gap",render:(row:any)=>row.gap?"Gap":"—"},
  ]} rows={orgCoverage.data?.techniques||[]} rowKey={(row:any)=>row.technique_id} empty={<EmptyState title="No org sightings yet" description="Cases, detections, and rule tags populate this board." compact/>}/>
  </section>
  <section className="card"><div className="section-head"><div><span className="section-kicker">Catalog</span><h2>Top 10 techniques (preconfigured)</h2></div><button type="button" className="secondary" onClick={()=>{const value=TOP_ATTACK_TECHNIQUES.map(t=>t.id).join(", ");setIds(value);buildHeatmap(value,"Top 10 technique heatmap")}}>Load into heatmap</button></div><div className="result-grid">{TOP_ATTACK_TECHNIQUES.map(tech=><article className="card" key={tech.id}><h3>{tech.id} · {tech.name}</h3><p>{tech.description}</p></article>)}</div></section>
  <div className="result-grid"><form className="card form-grid" onSubmit={async e=>{e.preventDefault();const value=await action.run(()=>api<any>(`/attack/search?q=${encodeURIComponent(query)}`));if(value)setTechniques({title:`Search results for “${query}”`,items:value.techniques||[]})}}><h2>Technique search</h2><label>Query<input value={query} onChange={e=>setQuery(e.target.value)} required/></label><button disabled={action.busy}>Search</button></form><form className="card form-grid" onSubmit={async e=>{e.preventDefault();const value=await action.run(()=>api<any>("/attack/extract",{method:"POST",body:JSON.stringify({text})}));if(value)setTechniques({title:"Techniques found in text",items:value.techniques||[]})}}><h2>Extract from text</h2><label>Text<textarea value={text} onChange={e=>setText(e.target.value)} required/></label><button disabled={action.busy}>Extract</button></form><form className="card form-grid" onSubmit={async e=>{e.preventDefault();await buildHeatmap(ids,"Technique heatmap")}}>
  <h2>Heatmap</h2><label>Technique IDs<input value={ids} onChange={e=>setIds(e.target.value)} placeholder="T1059, T1566" required/></label><button disabled={action.busy}>Build heatmap</button></form></div>
  <ErrorState error={action.error}/>
  {heatmap&&<section className="card"><div className="section-head"><div><span className="section-kicker">Coverage matrix</span><h2>{heatmapTitle}</h2></div><button type="button" className="secondary compact" onClick={()=>downloadJson("attack-heatmap.json",heatmap)}>Export JSON</button></div><AttackHeatmap data={heatmap}/></section>}
  {techniques&&<TechniqueResults title={techniques.title} techniques={techniques.items}/>}</>;
}

export function RulesWorkflow() {
  const [kind,setKind]=useState("sigma");
  const [title,setTitle]=useState("Black Onyx IOC detection");
  const [ips,setIps]=useState("203.0.113.10");
  const [domains,setDomains]=useState("");
  const [urls,setUrls]=useState("");
  const [hashes,setHashes]=useState("");
  const [emails,setEmails]=useState("");
  const [advanced,setAdvanced]=useState(false);
  const [raw,setRaw]=useState('{"ips":["203.0.113.10"]}');
  const [rule,setRule]=useState("");
  const [ruleId,setRuleId]=useState("");
  const [dryRun,setDryRun]=useState<any>();
  const action=useAction();
  const stored=useQuery({queryKey:["detection-rules"],queryFn:()=>api<any>("/detection-rules")});
  const analytics=useQuery({queryKey:["detection-rules-analytics"],queryFn:()=>api<any>("/detection-rules/analytics")});
  async function submit(event:FormEvent){
    event.preventDefault();
    let iocs:any;
    if(advanced){
      try{iocs=JSON.parse(raw)}catch{action.setError("IOCs must be valid JSON");return}
    }else{
      iocs=buildIocObject(ips,domains,urls,hashes,emails);
      if(!Object.values(iocs).some((list:any)=>list.length)){action.setError("Add at least one IP, domain, URL, hash, or email.");return}
    }
    const body=kind==="sigma"?{iocs,title,description:"Generated by Black Onyx",level:"medium"}:{iocs,rule_name:title.replace(/\W+/g,"_")};
    const data=await action.run(()=>api<any>(`/rules/${kind}`,{method:"POST",body:JSON.stringify(body)}));
    if(data?.rule){
      setRule(data.rule);
      const saved=await action.run(()=>api<any>("/detection-rules",{method:"POST",body:JSON.stringify({
        rule_type:kind, name:title, content:data.rule, tags:data.technique_ids||[], status:"draft", source:"generated",
      })}));
      if(saved?.rule_id){setRuleId(saved.rule_id);stored.refetch();analytics.refetch()}
    }
  }
  const rows=stored.data?.rules||stored.data?.items||(Array.isArray(stored.data)?stored.data:[]);
  async function runDryRun(id:string){
    setDryRun(null);
    const data=await action.run(()=>api<any>(`/detection-rules/${id}/dry-run`,{method:"POST",body:JSON.stringify({max_points:400})}));
    if(data)setDryRun(data);
  }
  async function setRuleStatus(id:string,status:string){
    const data=await action.run(()=>api<any>(`/detection-rules/${id}`,{method:"PATCH",body:JSON.stringify({status})}));
    if(data){stored.refetch();analytics.refetch()}
  }
  const pendingCount=Number(analytics.data?.by_status?.pending_approval??analytics.data?.pending??0);
  return <><Heading kicker="Detection rules" title="Sigma / YARA workspace" subtitle="Generate, version, validate, export, and evidence dry-run. Never executed as a live sensor." actions={<button type="button" className="secondary compact" onClick={async()=>{
    const csrf=(document.cookie.split("; ").find(v=>v.startsWith("blackonyx_csrf="))||"").slice("blackonyx_csrf=".length);
    const response=await fetch("/api/v1/detection-rules/export",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":decodeURIComponent(csrf)},body:JSON.stringify({})});
    if(!response.ok)throw new Error(await response.text());
    const blob=await response.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a"); a.href=url; a.download="detection-rules.zip"; a.click(); URL.revokeObjectURL(url);
  }}>Export package</button>}/><form className="card form-grid" onSubmit={submit}><label>Format<select value={kind} onChange={e=>setKind(e.target.value)}><option value="sigma">Sigma</option><option value="yara">YARA</option></select></label><label>Title or rule name<input value={title} onChange={e=>setTitle(e.target.value)} required/></label><label className="check setting-toggle"><input type="checkbox" checked={advanced} onChange={e=>setAdvanced(e.target.checked)}/> Advanced JSON editor</label>{advanced?<label>IOC JSON<textarea rows={7} value={raw} onChange={e=>setRaw(e.target.value)} required/></label>:<div className="field-row"><label>IP addresses<textarea rows={3} value={ips} onChange={e=>setIps(e.target.value)} placeholder="One per line or comma-separated"/></label><label>Domains<textarea rows={3} value={domains} onChange={e=>setDomains(e.target.value)}/></label><label>URLs<textarea rows={3} value={urls} onChange={e=>setUrls(e.target.value)}/></label><label>Hashes<textarea rows={3} value={hashes} onChange={e=>setHashes(e.target.value)}/></label><label>Emails<textarea rows={3} value={emails} onChange={e=>setEmails(e.target.value)}/></label></div>}<button disabled={action.busy}>Generate & store</button></form><ErrorState error={action.error||stored.error}/><div className="metrics"><article className="metric"><span>Stored rules</span><strong>{analytics.data?.total??analytics.data?.count??rows.length}</strong></article><article className="metric"><span>Pending approval</span><strong>{pendingCount||"—"}</strong></article><article className="metric"><span>Avg approval latency</span><strong>{analytics.data?.avg_approval_hours!=null?`${analytics.data.avg_approval_hours}h`:(analytics.data?.approval_latency_hours_avg!=null?`${Number(analytics.data.approval_latency_hours_avg).toFixed(1)}h`:"—")}</strong></article></div>{rule&&<section className="card"><div className="section-head"><div><span className="section-kicker">Generated</span><h2>{title}{ruleId?` · ${ruleId}`:""}</h2></div><div className="actions">{ruleId&&<button type="button" className="secondary compact" disabled={action.busy} onClick={()=>runDryRun(ruleId)}>Evidence dry-run</button>}{ruleId&&<button type="button" className="compact" disabled={action.busy} onClick={()=>setRuleStatus(ruleId,"pending_approval")}>Submit for approval</button>}</div></div><pre className="data">{rule}</pre><Notice>Dry-run string-matches rule literals against already ingested evidence — not live detection. Submit moves the stored draft into pending_approval.</Notice></section>}{dryRun&&<section className="card"><div className="section-head"><div><span className="section-kicker">Evidence dry-run</span><h2>{dryRun.rule_name||dryRun.rule_id}</h2></div><span className="count-badge">{dryRun.n??0}</span></div><p className="muted">{dryRun.note}</p><DataTable searchable columns={[{key:"collection",label:"Collection"},{key:"source_file",label:"Source",clip:true},{key:"matched",label:"Matched",render:(row:any)=>(row.matched||[]).join(", ")}]} rows={dryRun.matches||[]} rowKey={(row:any,i:number)=>`${row.collection}-${row.point_id}-${i}`} empty={<EmptyState title="No evidence matches" description="Literals from this rule did not appear in scrolled payloads." compact/>}/></section>}<section className="card"><div className="section-head"><div><span className="section-kicker">Library</span><h2>Versioned rules</h2></div></div><DataTable searchable columns={[{key:"name",label:"Name",clip:true,render:(row:any)=>row.name||row.title},{key:"rule_type",label:"Type",render:(row:any)=>row.rule_type||row.kind},{key:"status",label:"Status",render:(row:any)=>humanizeLabel(String(row.status||"draft"))},{key:"submitted_at",label:"Submitted",nowrap:true,render:(row:any)=>formatWhen(row.submitted_at)},{key:"created_at",label:"Created",nowrap:true,render:(row:any)=>formatWhen(row.created_at||row.updated_at)},{key:"actions",label:"",render:(row:any)=>{
    const id=row.rule_id||row.id;
    const status=String(row.status||"draft");
    return <div className="actions">
      <button type="button" className="ghost compact" onClick={()=>runDryRun(id)}>Dry-run</button>
      {status==="draft"&&<button type="button" className="ghost compact" disabled={action.busy} onClick={()=>setRuleStatus(id,"pending_approval")}>Submit</button>}
      {status==="pending_approval"&&<>
        <button type="button" className="ghost compact" disabled={action.busy} onClick={()=>setRuleStatus(id,"approved")}>Approve</button>
        <button type="button" className="ghost compact" disabled={action.busy} onClick={()=>setRuleStatus(id,"rejected")}>Reject</button>
      </>}
      {status==="approved"&&<button type="button" className="ghost compact" disabled={action.busy} onClick={()=>setRuleStatus(id,"deprecated")}>Deprecate</button>}
    </div>;
  }}]} rows={rows} rowKey={(row:any)=>row.rule_id||row.id} empty={<EmptyState title="No stored rules" description="Generate a Sigma or YARA rule to version it here." compact/>}/></section></>;
}

export function GraphWorkflow() {
  const sources=useQuery({queryKey:["graph-sources"],queryFn:()=>api<any>("/graph/sources")});
  const [mode,setMode]=useState("entities");
  const [collections,setCollections]=useState<string[]>([]);
  const [entityTypes,setEntityTypes]=useState<string[]>([]);
  const [start,setStart]=useState("");
  const [end,setEnd]=useState("");
  const [search,setSearch]=useState("");
  const [maxPoints,setMaxPoints]=useState(250);
  const [maxNodes,setMaxNodes]=useState(400);
  const [ids,setIds]=useState(TOP_ATTACK_TECHNIQUES.map(t=>t.id).join(", "));
  const [graph,setGraph]=useState<any>();
  const [defaultsReady,setDefaultsReady]=useState(false);
  const [view,setView]=useState("graph");
  const action=useAction();

  const available=useMemo(()=>sources.data?.sources||[],[sources.data]);
  const typeOptions=useMemo(()=>sources.data?.entity_types||[],[sources.data]);
  useEffect(()=>{
    if(defaultsReady||!sources.data)return;
    setCollections(available.filter((item:any)=>item.points>0).map((item:any)=>item.collection));
    setEntityTypes(typeOptions.filter((item:any)=>item.default).map((item:any)=>item.type));
    setDefaultsReady(true);
  },[sources.data,defaultsReady,available,typeOptions]);

  const selectedPoints=useMemo(()=>available.filter((item:any)=>collections.includes(item.collection)).reduce((sum:number,item:any)=>sum+item.points,0),[available,collections]);

  async function submit(event:FormEvent){
    event.preventDefault();
    if(mode==="attack"){
      const payload=ids.split(/[\s,]+/).filter(Boolean);
      const data=await action.run(()=>api<any>("/graph/attack",{method:"POST",body:JSON.stringify(payload)}));
      if(data)setGraph(data);
      return;
    }
    if(!collections.length){action.setError("Select at least one data source.");return}
    if(!entityTypes.length){action.setError("Select at least one entity type.");return}
    const data=await action.run(()=>api<any>("/graph/entities",{method:"POST",body:JSON.stringify({
      collections,
      entity_types:entityTypes,
      start_date:start||null,
      end_date:end||null,
      search:search||null,
      max_points_per_collection:maxPoints,
      max_nodes:maxNodes,
    })}));
    if(data)setGraph(data);
  }

  const nodes=graph?.nodes||[];
  const summary=graph&&mode==="entities"?<section className="card">
    <h3>Data sources</h3>
    <StatRow items={[
      {label:"Scanned",value:graph.points_scanned??0},
      {label:"Matched",value:graph.points_matched??0,tone:"ok"},
      ...(graph.points_undated?[{label:"No date",value:graph.points_undated,tone:"warn" as const}]:[]),
    ]}/>
    <ul className="graph-source-list">{(graph.sources||[]).map((item:any)=><li key={item.collection}>
      <label><span>{item.collection}</span><small>{item.matched}/{item.scanned}</small></label>
    </li>)}</ul>
    {graph.truncated&&<p className="muted">Node cap reached — raise the node limit or narrow the filters to see the rest.</p>}
  </section>:undefined;

  return <><Heading title="Relationship graph" subtitle="Correlate entities across every indexed data source, or map ATT&CK technique relationships." actions={graph?<button type="button" className="secondary" onClick={()=>downloadJson("relationship-graph.json",graph)}>Export JSON</button>:undefined}/>
  <form className="card graph-filters" onSubmit={submit}>
    <div className="section-head"><div><span className="section-kicker">Filters</span><h2>Build a graph</h2></div><span className="graph-counts">{mode==="entities"?<><strong>{collections.length}</strong> source(s) · <strong>{selectedPoints}</strong> indexed point(s)</>:<><strong>{ids.split(/[\s,]+/).filter(Boolean).length}</strong> technique(s)</>}</span></div>
    <div className="settings-fields">
      <label>Graph type<select value={mode} onChange={e=>setMode(e.target.value)}><option value="entities">Entities from data sources</option><option value="attack">ATT&CK techniques</option></select></label>
      {mode==="entities"&&<>
        <label>Ingested from<input type="date" value={start} onChange={e=>setStart(e.target.value)}/></label>
        <label>Ingested until<input type="date" value={end} onChange={e=>setEnd(e.target.value)}/></label>
        <label>Text filter <small>optional</small><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Only items containing…"/></label>
        <label>Items per source<input type="number" min={1} max={2000} value={maxPoints} onChange={e=>setMaxPoints(Number(e.target.value)||1)}/></label>
        <label>Node limit<input type="number" min={10} max={3000} value={maxNodes} onChange={e=>setMaxNodes(Number(e.target.value)||10)}/></label>
      </>}
      {mode==="attack"&&<label>Technique IDs<input value={ids} onChange={e=>setIds(e.target.value)} placeholder="T1059, T1566" required/></label>}
    </div>
    {mode==="entities"&&<div className="result-grid">
      <fieldset className="collection-multi"><legend>Data sources</legend>
        {sources.isLoading&&<p className="muted">Loading collections…</p>}
        {!sources.isLoading&&!available.length&&<p className="muted">No collections yet — ingest evidence or poll a feed first.</p>}
        <ul className="graph-source-list">{available.map((item:any)=><li key={item.collection}>
          <label><input type="checkbox" checked={collections.includes(item.collection)} onChange={e=>setCollections(current=>e.target.checked?[...current,item.collection]:current.filter(value=>value!==item.collection))}/><span>{item.collection}</span><small>{item.points}</small></label>
        </li>)}</ul>
        <div className="graph-filter-actions">
          <button type="button" className="secondary compact" onClick={()=>setCollections(available.map((item:any)=>item.collection))}>All</button>
          <button type="button" className="secondary compact" onClick={()=>setCollections(available.filter((item:any)=>item.points>0).map((item:any)=>item.collection))}>With data</button>
          <button type="button" className="secondary compact" onClick={()=>setCollections([])}>None</button>
        </div>
      </fieldset>
      <fieldset className="collection-multi"><legend>Entity types</legend>
        <ul className="graph-source-list">{typeOptions.map((item:any)=><li key={item.type}>
          <label><input type="checkbox" checked={entityTypes.includes(item.type)} onChange={e=>setEntityTypes(current=>e.target.checked?[...current,item.type]:current.filter(value=>value!==item.type))}/><span>{item.type.replace(/_/g," ")}</span></label>
        </li>)}</ul>
        <div className="graph-filter-actions">
          <button type="button" className="secondary compact" onClick={()=>setEntityTypes(typeOptions.map((item:any)=>item.type))}>All</button>
          <button type="button" className="secondary compact" onClick={()=>setEntityTypes(typeOptions.filter((item:any)=>item.default).map((item:any)=>item.type))}>Security defaults</button>
          <button type="button" className="secondary compact" onClick={()=>setEntityTypes([])}>None</button>
        </div>
      </fieldset>
    </div>}
    <button disabled={action.busy}>{action.busy?"Building…":"Build graph"}</button>
  </form>
  <ErrorState error={action.error||sources.error}/>
  {graph&&<><div className="tabs" role="tablist"><button type="button" role="tab" aria-selected={view==="graph"} onClick={()=>setView("graph")}>Node graph</button><button type="button" role="tab" aria-selected={view==="table"} onClick={()=>setView("table")}>Relationship table</button></div>
  {view==="graph"
    ?(nodes.length?<GraphView nodes={nodes} edges={graph.edges||[]} sidebar={summary}/>:<section className="card"><EmptyState title="Graph is empty" description="No entities matched. Widen the date range, add data sources or entity types, or ingest evidence that contains indicators." compact/></section>)
    :<section className="card"><h2>Relationships</h2><DataTable
        columns={[
          {key:"source",label:"From",clip:true,render:(row:any)=>String(row.source).replace(/^doc::/,"")},
          {key:"relationship",label:"Relationship",render:(row:any)=><span className="chip accent">{row.relationship||"related"}</span>},
          {key:"target",label:"To",clip:true},
          {key:"weight",label:"Seen",render:(row:any)=>row.weight??1},
        ]}
        rows={graph.edges||[]}
        rowKey={(row:any,index:number)=>`${row.source}-${row.target}-${row.relationship}-${index}`}
        empty={<EmptyState title="No relationships" description="This graph has nodes but no edges yet." compact/>}
      /><RawJson data={graph}/></section>}</>}</>;
}

export function ReportsWorkflow({role}:{role:Role}) {
  const reports=useQuery({queryKey:["reports"],queryFn:()=>api<any>("/reports")});
  const [title,setTitle]=useState("Threat Intelligence Report");
  const [format,setFormat]=useState("markdown");
  const [template,setTemplate]=useState<"intel"|"ops_digest">("intel");
  const [ips,setIps]=useState("");
  const [domains,setDomains]=useState("");
  const [urls,setUrls]=useState("");
  const [hashes,setHashes]=useState("");
  const [emails,setEmails]=useState("");
  const [advanced,setAdvanced]=useState(false);
  const [raw,setRaw]=useState('{"ips":[],"domains":[]}');
  const [report,setReport]=useState<any>();
  const [opsDigest,setOpsDigest]=useState("");
  const action=useAction();
  async function submit(event:FormEvent){
    event.preventDefault();
    if(template==="ops_digest"){
      const overview=await action.run(()=>api<any>("/analytics/overview?range=30d"));
      const kpis=await action.run(()=>api<any>("/analytics/kpis?metrics=mtta,mtti,mttr,ingest_latency,fpr,alert_case_ratio,fresh_ioc_ratio,closure_rate,intel_hit_rate,automation_success,sla_breach_rate&range=30d"));
      const attack=await action.run(()=>api<any>("/analytics/attack/coverage?range=30d"));
      const noisy=await action.run(()=>api<any>("/analytics/distributions?metric=noisy_ioc&range=30d"));
      if(!overview||!kpis)return;
      const m=kpis.metrics||{};
      const fmt=(key:string)=>{
        const row=m[key]||{};
        const value=row.value??row.seconds??row.rate??row.ratio;
        if(typeof value!=="number")return `— (n=${row.n??0})`;
        if(key.startsWith("mtt")||key==="ingest_latency")return `${Math.round(value/60)} minutes (n=${row.n??0})`;
        if(key.includes("ratio")||key==="fpr"||key.endsWith("_rate")||key.endsWith("_success"))return `${(value*100).toFixed(1)}% (n=${row.n??0})`;
        return `${value} (n=${row.n??0})`;
      };
      const topTechniques=((attack?.techniques||attack?.leaderboard||[]) as any[]).slice(0,8)
        .map((t)=>`- ${t.technique_id}: ${t.name||""} · sightings=${t.sightings??0}${t.covered?" · claimed":""}${t.gap?" · gap":""}`)
        .join("\n")||"- None yet";
      const noisyLines=((noisy?.items||noisy?.buckets||[]) as any[]).slice(0,8)
        .map((row)=>`- ${row.label||row.key}: ${row.value??row.count??0}`)
        .join("\n")||"- None yet";
      const body=[
        `# ${title||"Ops digest (30d)"}`,
        "",
        "Disposition-aware stakeholder summary. Sample sizes (`n`) are required for every KPI.",
        "",
        "## Response",
        `- MTTA: ${fmt("mtta")}`,
        `- MTTI: ${fmt("mtti")}`,
        `- MTTR: ${fmt("mttr")}`,
        `- Ingest latency (MTTD proxy): ${fmt("ingest_latency")}`,
        `- Alert→case ratio: ${fmt("alert_case_ratio")}`,
        `- Closure rate: ${fmt("closure_rate")}`,
        `- SLA breach rate: ${fmt("sla_breach_rate")}`,
        "",
        "## Quality & automation",
        `- False positive rate: ${fmt("fpr")}`,
        `- Intel hit rate: ${fmt("intel_hit_rate")}`,
        `- Automation success: ${fmt("automation_success")}`,
        `- Fresh IOC ratio: ${fmt("fresh_ioc_ratio")}`,
        "",
        "## Volume",
        `- Alerts in range: ${overview.alerts?.n??0}`,
        `- Cases in range: ${overview.cases?.n??0}`,
        `- Open alerts: ${overview.open_alerts??0}`,
        `- Open cases: ${overview.open_cases??0}`,
        `- Assets: ${overview.asset_count??0}`,
        "",
        "## Top ATT&CK techniques (risk-weighted sightings)",
        topTechniques,
        "",
        "## Noisy IOC leaderboard",
        noisyLines,
        "",
        "_Generated by Black Onyx Analytics. ATT&CK coverage is risk-weighted; 100% technique coverage is not a success metric._",
      ].join("\n");
      setOpsDigest(body);
      const saved=await action.run(()=>api<any>("/reports/generate",{method:"POST",body:JSON.stringify({title:title||"Ops digest (30d)",format:"markdown",template:"ops_digest",body_markdown:body,iocs:{}})}));
      if(saved){setReport(saved);reports.refetch()}
      else setReport({format:"markdown",content:body,download_url:undefined});
      return;
    }
    let iocs:any;
    if(advanced){
      try{iocs=JSON.parse(raw)}catch{action.setError("IOC input must be valid JSON");return}
    }else{
      iocs=buildIocObject(ips,domains,urls,hashes,emails);
    }
    const data=await action.run(()=>api<any>("/reports/generate",{method:"POST",body:JSON.stringify({title,format,iocs})}));
    if(data){setReport(data);setOpsDigest("");}
  }
  return <><Heading title="Intelligence reports" subtitle="Generate sanitized Markdown, HTML, or PDF reports — including a disposition-aware Ops digest."/>{role==="viewer"?<Notice>Viewer accounts can read and download shared reports but cannot generate them.</Notice>:<form className="card form-grid" onSubmit={submit}><label>Template<select value={template} onChange={e=>setTemplate(e.target.value as "intel"|"ops_digest")}><option value="intel">Intel brief</option><option value="ops_digest">Ops digest (MTTA/MTTR/FPR)</option></select></label><label>Title<input value={title} onChange={e=>setTitle(e.target.value)} required/></label>{template==="intel"&&<><label>Format<select value={format} onChange={e=>setFormat(e.target.value)}><option>markdown</option><option>html</option><option>pdf</option></select></label><label className="check setting-toggle"><input type="checkbox" checked={advanced} onChange={e=>setAdvanced(e.target.checked)}/> Advanced JSON editor</label>{advanced?<label>IOC JSON<textarea rows={7} value={raw} onChange={e=>setRaw(e.target.value)} required/></label>:<div className="field-row"><label>IP addresses<textarea rows={3} value={ips} onChange={e=>setIps(e.target.value)}/></label><label>Domains<textarea rows={3} value={domains} onChange={e=>setDomains(e.target.value)}/></label><label>URLs<textarea rows={3} value={urls} onChange={e=>setUrls(e.target.value)}/></label><label>Hashes<textarea rows={3} value={hashes} onChange={e=>setHashes(e.target.value)}/></label><label>Emails<textarea rows={3} value={emails} onChange={e=>setEmails(e.target.value)}/></label></div>}</>}<button disabled={action.busy}>{template==="ops_digest"?"Generate ops digest":"Generate report"}</button></form>}<ErrorState error={action.error||reports.error}/>{(report||opsDigest)&&<section className="card"><Notice>Report generated successfully.</Notice><pre className="data">{opsDigest||report?.content}</pre>{report?.download_url&&<a className="button" href={report.download_url}>Download {report.format}</a>}{!report?.download_url&&(opsDigest||report?.content)&&<button type="button" className="secondary" onClick={()=>downloadJson("ops-digest.md",{content:opsDigest||report?.content})}>Download JSON wrapper</button>}</section>}<section className="card"><h2>Shared reports</h2>{(reports.data?.reports||[]).length?<ul className="item-list">{(reports.data?.reports||[]).map((item:any)=><li key={item.report_id}><span>{item.title}<small>{item.format} by {item.created_by}</small></span><a className="button" href={`/api/v1/reports/${item.report_id}/download?format=${item.format}`}>Download</a></li>)}</ul>:<EmptyState title="No shared reports yet" description="Generate a report above to publish a downloadable artifact for your team." compact/>}</section></>;
}

import { FormEvent, ReactNode, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, Role } from "./api";
import { Chips, CollectionSelect, ConfirmDialog, DataTable, EmptyState, ErrorState, Heading, KeyValues, Notice, PayloadView, RawJson, ScoreBar, StatRow, formatWhen, humanizeLabel } from "./ui";
import { HorizontalBars, TimeSeriesArea } from "./components/charts";
import { OpsSurfaceKpis } from "./components/ops_kpis";

function message(error: unknown) { return error instanceof Error ? error.message : "Request failed"; }

/** Render a job/ingest detail object as counters instead of a JSON blob. */
export function DetailStats({ detail }: { detail: Record<string, any> | undefined }) {
  const entries = Object.entries(detail || {}).filter(([, value]) => value !== null && value !== undefined && typeof value !== "object");
  if (!entries.length) return <p className="muted">No detail reported yet.</p>;
  return <StatRow items={entries.map(([key, value]) => ({
    label: humanizeLabel(key),
    value: typeof value === "boolean" ? (value ? "Yes" : "No") : String(value),
    tone: /error/i.test(key) && Number(value) > 0 ? "bad" : /processed|chunks|files/i.test(key) && Number(value) > 0 ? "ok" : undefined,
  }))}/>;
}
function feedCollectionName(name: string) {
  const body = name.trim().replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^[-._]+|[-._]+$/g, "") || "unnamed";
  return `feed-${body}`.slice(0, 128);
}

export function JobsWorkflow() {
  const jobs=useQuery({queryKey:["jobs"],queryFn:()=>api<any>("/jobs"),refetchInterval:3000});const [error,setError]=useState("");
  const values=jobs.data?.jobs||[];return <><Heading title="Ingestion jobs" subtitle="Monitor persisted job state and stop active work." actions={<button className="secondary" onClick={()=>jobs.refetch()}>Refresh jobs</button>}/><ErrorState error={error||jobs.error}/>{values.length?<div className="result-grid">{values.map((job:any)=><article className="card job-card" key={job.job_id}><div className="section-head"><div><span className="section-kicker">{job.job_type}</span><h2>{job.job_id}</h2></div><span className={`status ${job.status}`}>{job.status}</span></div><DetailStats detail={job.detail}/><KeyValues items={[{label:"Started",value:formatWhen(job.created_at)},{label:"Updated",value:formatWhen(job.updated_at)}]}/>{["queued","running","stopping"].includes(job.status)&&<button className="danger" onClick={async()=>{try{await api(`/ingest/${job.job_id}/stop`,{method:"POST"});jobs.refetch()}catch(e){setError(message(e))}}}>Stop job</button>}</article>)}</div>:<section className="card empty-card"><EmptyState title="No ingestion jobs" description="Upload evidence to a collection and its processing activity will appear here." action={<a className="button" href="/ingest">Ingest evidence</a>}/></section>}</>;
}

export function IngestWorkflow({role}:{role:Role}) {
  const settings=useQuery({queryKey:["admin-settings-lite"],queryFn:async()=>{try{return await api<any>("/admin/settings")}catch{return null}},enabled:role==="admin",retry:false});
  const [files,setFiles]=useState<FileList|null>(null);const [collection,setCollection]=useState("all-knowledge");const [result,setResult]=useState<any>();const [error,setError]=useState("");
  useEffect(()=>{const name=settings.data?.ingestion?.collection_name;if(name)setCollection(name)},[settings.data?.ingestion?.collection_name]);
  async function submit(event:FormEvent){event.preventDefault();if(!files)return;const body=new FormData();Array.from(files).forEach(file=>body.append("files",file,file.webkitRelativePath||file.name));body.append("collection",collection);try{setError("");setResult(await api("/ingest/upload",{method:"POST",body}))}catch(e){setError(message(e))}}
  return <><Heading title="Ingest evidence" subtitle="Import individual files or a complete folder tree into an indexed collection."/><form className="card form-grid" onSubmit={submit}><CollectionSelect value={collection} onChange={setCollection} required/><div className="upload-options"><label>Choose files<input type="file" multiple accept=".txt,.log,.md,.rst,.csv,.tsv,.json,.jsonl,.ndjson,.xml,.html,.htm,.xhtml,.pdf,.xlsx,.docx,.pptx,.odt,.ods,.rtf,.eml,.yaml,.yml,.ini,.cfg,.conf,.stix,.stix2,.sarif,.png,.jpg,.jpeg,.webp,.gif,.bmp,.tif,.tiff" onChange={e=>setFiles(e.target.files)}/></label><label>Choose entire directory<input type="file" multiple {...({webkitdirectory:"",directory:""} as any)} onChange={e=>setFiles(e.target.files)}/></label></div><Notice>Supported evidence includes JSON/JSONL, HTML/XML, PDF, CSV/TSV, XLSX, Word, PowerPoint, OpenDocument, email, STIX/SARIF, logs, markup, configuration files, and common images.</Notice>{files&&<p className="selection-summary">Ready to upload {files.length} file{files.length===1?"":"s"}.</p>}{role==="viewer"&&<Notice>Viewer accounts cannot start ingestion.</Notice>}<button disabled={role==="viewer"||!files?.length}>Start ingestion</button></form><ErrorState error={error}/>{result&&<section className="card"><div className="section-head"><div><span className="section-kicker">Accepted</span><h2>Ingestion started</h2></div>{result.status&&<span className={`status ${result.status}`}>{result.status}</span>}</div><KeyValues items={[{label:"Job ID",value:result.job_id,wide:true},...(result.message?[{label:"Message",value:result.message,wide:true}]:[])]}/><div className="actions"><a className="button secondary" href="/jobs">Track in Jobs</a></div></section>}</>;
}

export function CollectionsWorkflow({role}:{role:Role}) {
  const client=useQueryClient();
  const collections=useQuery({queryKey:["collections"],queryFn:()=>api<any[]>("/collections")});
  const [selected,setSelected]=useState(""); const [cursor,setCursor]=useState("");
  const [newName,setNewName]=useState("");
  const points=useQuery({queryKey:["points",selected,cursor],queryFn:()=>api<any>(`/collections/${encodeURIComponent(selected)}/points?limit=25${cursor?`&cursor=${encodeURIComponent(cursor)}`:""}`),enabled:!!selected});
  const detail=useQuery({queryKey:["collection",selected],queryFn:()=>api<any>(`/collections/${encodeURIComponent(selected)}`),enabled:!!selected});
  const [point,setPoint]=useState<any>(); const [text,setText]=useState(""); const [error,setError]=useState("");
  async function pointAction(path:string,body:any,method="POST"){try{await api(path,{method,body:JSON.stringify(body)});setText("")}catch(e){setError(message(e))}}
  async function removePoint(){if(!point)return;try{await api(`/collections/${encodeURIComponent(selected)}/points/${encodeURIComponent(point.id)}`,{method:"DELETE"});setPoint(undefined);await client.invalidateQueries({queryKey:["points",selected]});await client.invalidateQueries({queryKey:["collections"]})}catch(e){setError(message(e))}}
  async function createCollection(event:FormEvent){event.preventDefault();try{setError("");await api("/collections",{method:"POST",body:JSON.stringify({name:newName})});setSelected(newName);setNewName("");await client.invalidateQueries({queryKey:["collections"]})}catch(e){setError(message(e))}}
  const values=collections.data||[];
  return <><Heading title="Ingested data" subtitle="Create collections, browse evidence, remove indexed items, and manage analyst context."/><ErrorState error={error||collections.error||points.error||detail.error}/>
    <div className="split collection-layout"><section className="card collection-sidebar"><div className="section-head"><div><span className="section-kicker">Vector store</span><h2>Collections</h2></div><span className="count-badge">{values.length}</span></div>
      {role==="admin"&&<form className="inline-create" onSubmit={createCollection}><label>New collection<input value={newName} onChange={e=>setNewName(e.target.value)} pattern="^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$" required placeholder="all-knowledge"/></label><button>Create</button></form>}
      {values.length?<ul className="item-list">{values.map(collection=><li className={selected===collection.name?"selected":""} key={collection.name}><button className="ghost" onClick={()=>{setSelected(collection.name);setCursor("");setPoint(undefined)}}><span>{collection.name}</span><small>{collection.points_count} points</small></button>{role==="admin"&&<ConfirmDialog label="Delete collection" expected={collection.name} onConfirm={async()=>{await api(`/collections/${encodeURIComponent(collection.name)}`,{method:"DELETE"});setSelected("");setPoint(undefined);await client.invalidateQueries({queryKey:["collections"]})}}/>}</li>)}</ul>:<EmptyState title="No collections" description="Create an empty collection here, or ingest evidence into a new name." compact />}</section>
      <section className="card collection-content"><div className="section-head"><div><span className="section-kicker">Indexed items</span><h2>{selected||"Choose a collection"}</h2></div></div>
      {selected&&detail.data&&(()=>{const textVec=detail.data.vectors?.text;const size=detail.data.vector_size??textVec?.size??"—";const distance=detail.data.distance??textVec?.distance??"—";return <div className="collection-meta"><small>Points: {detail.data.points_count ?? 0}</small><small>Vector size: {size}</small><small>Distance: {String(distance)}</small>{detail.data.vectors&&<small>Vectors: {Object.keys(detail.data.vectors).join(", ")}</small>}</div>})()}
      {selected?(points.data?.points||[]).length?<ul className="item-list point-list">{points.data.points.map((value:any)=><li key={value.id}><button className="ghost" onClick={()=>setPoint(value)}><span>{value.payload?.source_file?.split(/[\\/]/).pop()||value.id}</span><small>{String(value.payload?.body_text||value.payload?.ocr_text||"").slice(0,160)}</small></button></li>)}</ul>:<EmptyState title="Collection is empty" description="Indexed evidence points will appear here." />:<EmptyState title="Select a collection" description="Choose a collection to inspect its indexed evidence." />}{selected&&<div className="pagination">{cursor&&<button className="secondary" onClick={()=>setCursor("")}>First page</button>}{points.data?.next_cursor&&<button onClick={()=>setCursor(points.data.next_cursor)}>Next page</button>}</div>}</section></div>
    {point&&<section className="card point-detail"><div className="section-head"><div><span className="section-kicker">Selected evidence</span><h2>{point.payload?.source_file?.split(/[\\/]/).pop()||`Point ${point.id}`}</h2></div>{role==="admin"&&<ConfirmDialog label="Remove item" expected={String(point.id)} onConfirm={removePoint}/>}</div><PayloadView payload={point.payload||{}}/>{role!=="viewer"&&<div className="form-grid"><label>Analyst text<input value={text} onChange={e=>setText(e.target.value)}/></label><div className="actions"><button onClick={()=>pointAction("/annotations",{collection:selected,point_id:point.id,content:text})}>Annotate</button><button onClick={()=>pointAction("/notes",{collection:selected,point_id:point.id,content:text})}>Add note</button><button onClick={()=>pointAction("/tags",{collection:selected,point_id:point.id,tag:text})}>Add tag</button><button className="secondary" onClick={()=>pointAction("/bookmarks",{collection:selected,point_id:point.id})}>Toggle bookmark</button></div></div>}</section>}</>;
}

function CaseDwellStrip() {
  const dwell = useQuery({
    queryKey: ["case-time-in-status"],
    queryFn: () => api<any>("/analytics/distributions?metric=time_in_status&range=30d"),
  });
  const series = (dwell.data?.items || dwell.data?.buckets || []).map((row: any) => ({
    label: String(row.label || row.key || ""),
    value: Number(row.value ?? row.count ?? 0),
  }));
  if (!series.length) return null;
  return (
    <section className="card">
      <div className="section-head"><div><span className="section-kicker">Dwell</span><h2>Mean hours in status (30d)</h2></div><Link className="button ghost compact" to="/analytics">Analytics</Link></div>
      <HorizontalBars data={series} />
    </section>
  );
}

export function CasesWorkflow({role}:{role:Role}) {
  const client=useQueryClient();
  const cases=useQuery({queryKey:["cases"],queryFn:()=>api<any>("/cases")});
  const [selected,setSelected]=useState("");
  const detail=useQuery({queryKey:["case",selected],queryFn:()=>api<any>(`/cases/${selected}`),enabled:!!selected});
  const [title,setTitle]=useState("");
  const [description,setDescription]=useState("");
  const [entry,setEntry]=useState("");
  const [iocType,setIocType]=useState("ip");
  const [actionTab,setActionTab]=useState<"note"|"ioc"|"point"|"meta"|"share">("note");
  const [editTitle,setEditTitle]=useState("");
  const [editDescription,setEditDescription]=useState("");
  const [editPriority,setEditPriority]=useState("medium");
  const [editAssignee,setEditAssignee]=useState("");
  const [editTags,setEditTags]=useState("");
  const [notice,setNotice]=useState("");
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  const caseDetail=detail.data;
  useEffect(()=>{
    if(!caseDetail)return;
    setEditTitle(caseDetail.title||"");
    setEditDescription(caseDetail.description||"");
    setEditPriority(caseDetail.priority||"medium");
    setEditAssignee(caseDetail.assignee||"");
    setEditTags((caseDetail.tags||[]).join(", "));
  },[caseDetail]);
  async function refresh(){await client.invalidateQueries({queryKey:["cases"]});await client.invalidateQueries({queryKey:["case",selected]})}
  async function create(event:FormEvent){event.preventDefault();try{setError("");const value=await api<any>("/cases",{method:"POST",body:JSON.stringify({title,description,priority:"medium",tags:[]})});setSelected(value.case_id);setTitle("");setDescription("");await refresh()}catch(e){setError(message(e))}}
  async function runAction(label:string,operation:()=>Promise<void>,needsEntry=true){
    if(!selected){setError("Select a case first.");return}
    if(needsEntry&&!entry.trim()){setError(`${label} needs a value in the field above.`);return}
    setBusy(true);setError("");setNotice("");
    try{await operation();if(needsEntry)setEntry("");await refresh()}
    catch(e){setError(message(e))}
    finally{setBusy(false)}
  }
  async function patchCase(body:Record<string,unknown>){
    setBusy(true);setError("");setNotice("");
    try{await api(`/cases/${selected}`,{method:"PATCH",body:JSON.stringify(body)});setNotice("Case updated.");await refresh()}
    catch(e){setError(message(e))}
    finally{setBusy(false)}
  }
  async function enrichAttachedIocs(){
    const allowed=new Set(["ip","domain","url","hash","email","cve"]);
    const iocs=(detail.data?.iocs||[]).filter((item:any)=>allowed.has(String(item.ioc_type||"").toLowerCase()));
    if(!iocs.length)throw new Error("No enrichable IOC types attached (ip, domain, url, hash, email, cve).");
    for(const item of iocs){
      await api("/enrich",{method:"POST",body:JSON.stringify({ioc_type:String(item.ioc_type).toLowerCase(),ioc_value:item.ioc_value})});
    }
    setNotice(`Enrichment requested for ${iocs.length} IOC(s).`);
  }
  async function generateCaseReport(){
    const report=await api<any>("/reports/generate",{method:"POST",body:JSON.stringify({title:detail.data.title,case_id:selected,format:"markdown",iocs:{}})});
    const suffix=report.download_url?" — available under Reports.":".";
    setNotice(`Report generated: ${report.title||detail.data.title}${suffix}`);
  }
  async function publishCaseToMisp(){
    const iocs=(detail.data?.iocs||[]).map((item:any)=>({ioc_type:item.ioc_type,ioc_value:item.ioc_value}));
    const result=await api<any>("/misp/publish",{method:"POST",body:JSON.stringify({case_id:selected,iocs,info:detail.data.title})});
    setNotice(`Published ${result.ioc_count??iocs.length} IOC(s) to MISP.`);
  }
  async function attachPoint(){
    const [collection,point_id]=(entry.includes(":")?entry:":").split(":",2).map(v=>v.trim());
    if(!collection||!point_id)throw new Error("Attach point needs collection:point_id");
    await api(`/cases/${selected}/points`,{method:"POST",body:JSON.stringify({collection,point_id})});
  }
  return <>
    <Heading title="Investigation cases" subtitle="Manage evidence, notes, IOCs, points, timelines, metadata, reports, and MISP publishing. Detection-spine incidents link via external incident id." actions={<><Link className="button secondary compact" to="/incidents">Incidents</Link><Link className="button secondary compact" to="/analytics">Analytics</Link></>}/>
    <OpsSurfaceKpis metrics="mttr,closure_rate,sla_breach_rate,reopen_rate,alert_case_ratio" />
    <CaseDwellStrip />
    <ErrorState error={error||cases.error||detail.error}/>
    {notice&&<Notice>{notice}</Notice>}
    <div className="split">
      <section className="card">
        <h2>Cases</h2>
        {role!=="viewer"&&<form className="form-grid" onSubmit={create}><label>Title<input value={title} onChange={e=>setTitle(e.target.value)} required/></label><label>Description<textarea value={description} onChange={e=>setDescription(e.target.value)}/></label><button>Create case</button></form>}
        <ul className="item-list">{(cases.data?.cases||[]).map((value:any)=><li key={value.case_id} className={selected===value.case_id?"selected":""}><button type="button" className="ghost" onClick={()=>setSelected(value.case_id)}>{value.title}</button><span className={`status ${value.status}`}>{value.status}</span></li>)}</ul>
      </section>
      <section className="card">
        <h2>{detail.data?.title||"Select a case"}</h2>
        {detail.data&&<>
          <p>{detail.data.description||<span className="muted">No description</span>}</p>
          <CaseDetail detail={detail.data}/>
          {role!=="viewer"&&<div className="case-actions">
            <div className="tabs" role="tablist" aria-label="Case actions">
              {([["note","Add note"],["ioc","Attach IOC"],["point","Attach evidence"],["meta","Edit case"],["share","Share / report"]] as const).map(([key,label])=>(
                <button key={key} type="button" role="tab" aria-selected={actionTab===key} onClick={()=>setActionTab(key)}>{label}</button>
              ))}
            </div>
            {actionTab==="note"&&<div className="form-grid">
              <label>Note<textarea rows={3} value={entry} onChange={e=>setEntry(e.target.value)} placeholder="Investigation note…"/></label>
              <div className="actions"><button type="button" disabled={busy} onClick={()=>runAction("Add note",()=>api(`/cases/${selected}/notes`,{method:"POST",body:JSON.stringify({content:entry.trim()})}))}>Add note</button></div>
            </div>}
            {actionTab==="ioc"&&<div className="form-grid">
              <label>IOC type<select value={iocType} onChange={e=>setIocType(e.target.value)}><option>ip</option><option>domain</option><option>url</option><option>hash</option><option>email</option><option>cve</option><option>indicator</option></select></label>
              <label>Value<input value={entry} onChange={e=>setEntry(e.target.value)} placeholder="Indicator value"/></label>
              <div className="actions">
                <button type="button" disabled={busy} onClick={()=>runAction("Attach IOC",()=>api(`/cases/${selected}/iocs`,{method:"POST",body:JSON.stringify({ioc_type:iocType,ioc_value:entry.trim()})}))}>Attach IOC</button>
                <button type="button" className="secondary" disabled={busy||!(detail.data.iocs||[]).length} onClick={()=>runAction("Enrich IOCs",enrichAttachedIocs,false)}>Enrich attached IOCs</button>
              </div>
            </div>}
            {actionTab==="point"&&<div className="form-grid">
              <label>Evidence point<input value={entry} onChange={e=>setEntry(e.target.value)} placeholder="collection:point_id"/></label>
              <div className="actions">
                <button type="button" disabled={busy} onClick={()=>runAction("Attach point",attachPoint)}>Attach point</button>
                <Link className="button secondary" to="/collections">Browse collections</Link>
              </div>
            </div>}
            {actionTab==="meta"&&<div className="form-grid">
              <label>Title<input value={editTitle} onChange={e=>setEditTitle(e.target.value)}/></label>
              <label>Description<textarea rows={3} value={editDescription} onChange={e=>setEditDescription(e.target.value)}/></label>
              <label>Status<select value={detail.data.status} onChange={e=>patchCase({status:e.target.value})}><option>open</option><option>investigating</option><option>resolved</option><option>closed</option></select></label>
              <label>Priority<select value={editPriority} onChange={e=>setEditPriority(e.target.value)}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
              <label>Assignee<input value={editAssignee} onChange={e=>setEditAssignee(e.target.value)} placeholder="Analyst or queue"/></label>
              <label>Tags <small>comma-separated</small><input value={editTags} onChange={e=>setEditTags(e.target.value)} placeholder="phishing, apt29"/></label>
              <div className="actions">
                <button type="button" disabled={busy} onClick={()=>patchCase({
                  title:editTitle.trim()||detail.data.title,
                  description:editDescription,
                  priority:editPriority,
                  assignee:editAssignee.trim()||null,
                  tags:editTags.split(",").map(t=>t.trim()).filter(Boolean),
                })}>Save case details</button>
              </div>
            </div>}
            {actionTab==="share"&&<div className="form-grid">
              <p className="section-description">Generate a sanitized intelligence report from this case, or publish attached IOCs to the configured MISP instance.</p>
              <div className="actions">
                <button type="button" disabled={busy} onClick={()=>runAction("Generate report",generateCaseReport,false)}>Generate report</button>
                <button type="button" className="secondary" disabled={busy||!(detail.data.iocs||[]).length} onClick={()=>runAction("Publish to MISP",publishCaseToMisp,false)}>Publish IOCs to MISP</button>
                <Link className="button secondary" to="/reports">Open reports</Link>
                <Link className="button secondary" to="/iocs">IOC workbench</Link>
              </div>
            </div>}
            <ConfirmDialog label="Delete case" expected={detail.data.title} onConfirm={async()=>{await api(`/cases/${selected}`,{method:"DELETE"});setSelected("");refresh()}}/>
          </div>}
        </>}
      </section>
    </div>
  </>;
}

function CaseDetail({ detail }: { detail: any }) {
  const [tab,setTab]=useState("iocs");
  const iocs=detail.iocs||[];
  const points=detail.points||[];
  const notes=detail.notes||[];
  const timeline=detail.timeline||[];
  const tabs:[string,string,number][]=[["iocs","IOCs",iocs.length],["points","Evidence",points.length],["notes","Notes",notes.length],["timeline","Timeline",timeline.length]];
  let body:ReactNode=null;
  if(tab==="iocs")body=<DataTable
    columns={[
      {key:"ioc_type",label:"Type",render:(row:any)=><span className="chip accent">{row.ioc_type}</span>},
      {key:"ioc_value",label:"Value",clip:true},
      {key:"added_at",label:"Added",nowrap:true,render:(row:any)=>formatWhen(row.added_at||row.created_at)},
    ]}
    rows={iocs}
    rowKey={(row:any,index:number)=>`${row.ioc_type}-${row.ioc_value}-${index}`}
    empty={<EmptyState title="No IOCs attached" description="Open the Attach IOC action tab to add indicators." compact/>}
  />;
  if(tab==="points")body=<DataTable
    columns={[
      {key:"collection",label:"Collection"},
      {key:"point_id",label:"Point",clip:true},
      {key:"added_at",label:"Added",nowrap:true,render:(row:any)=>formatWhen(row.added_at||row.created_at)},
    ]}
    rows={points}
    rowKey={(row:any,index:number)=>`${row.collection}-${row.point_id}-${index}`}
    empty={<EmptyState title="No evidence linked" description="Open the Attach evidence action tab and enter collection:point_id." compact/>}
  />;
  if(tab==="notes")body=notes.length?<ul className="note-list">{notes.map((note:any,index:number)=><li key={note.note_id||index}>
    <div className="note-head"><b>{note.author||note.created_by||"analyst"}</b><small>{formatWhen(note.created_at)}</small></div>
    <p>{note.content}</p>
  </li>)}</ul>:<EmptyState title="No notes yet" description="Open the Add note action tab to record investigation notes." compact/>;
  if(tab==="timeline")body=timeline.length?<ul className="timeline">{timeline.map((entry:any,index:number)=><li key={entry.event_id||index}>
    <small>{formatWhen(entry.timestamp||entry.created_at)}</small>
    <b>{humanizeLabel(String(entry.event_type||entry.action||"event"))}</b>
    <span>{entry.description||entry.detail||entry.content||""}</span>
  </li>)}</ul>:<EmptyState title="No timeline entries" description="Case activity such as notes, IOCs, and status changes appears here." compact/>;
  const slaDue=detail.sla_due_at?new Date(detail.sla_due_at):null;
  const slaBreached=!!slaDue&&!detail.closed_at&&slaDue.getTime()<Date.now();
  return <div className="case-detail">
    <KeyValues items={[
      {label:"Status",value:<span className={`status ${detail.status}`}>{detail.status}</span>},
      {label:"Priority",value:detail.priority},
      {label:"Severity",value:detail.severity||"—"},
      {label:"Assignee",value:detail.assignee||"Unassigned"},
      {label:"Detection incident",value:detail.external_incident_id?(<Link to={`/incidents/${detail.external_incident_id}`}>{detail.external_incident_id}</Link>):"—",wide:!!detail.external_incident_id},
      {label:"Detected",value:formatWhen(detail.detected_at||detail.created_at)},
      {label:"Contained",value:formatWhen(detail.contained_at)},
      {label:"Closed",value:formatWhen(detail.closed_at)},
      {label:"SLA due",value:<span className={slaBreached?"status failed":""}>{formatWhen(detail.sla_due_at)}{slaBreached?" · breached":""}</span>},
      {label:"Created",value:formatWhen(detail.created_at)},
      {label:"Updated",value:formatWhen(detail.updated_at)},
      ...((detail.tags||[]).length?[{label:"Tags",value:<Chips items={detail.tags}/>,wide:true}]:[]),
    ]}/>
    <div className="tabs" role="tablist">{tabs.map(([key,label,count])=><button key={key} type="button" role="tab" aria-selected={tab===key} onClick={()=>setTab(key)}>{label} ({count})</button>)}</div>
    {body}
  </div>;
}

function parseAlertContext(raw: unknown): unknown {
  if (raw == null || raw === "") return null;
  if (typeof raw !== "string") return raw;
  try { return JSON.parse(raw); } catch { return raw; }
}

const ALERT_DISPOSITIONS = ["true_positive", "false_positive", "benign_positive", "duplicate", "informational", "escalated"] as const;

export function WatchlistsWorkflow({role}:{role:Role}) {
  const client=useQueryClient();
  const lists=useQuery({queryKey:["watchlists"],queryFn:()=>api<any>("/watchlists")});
  const alerts=useQuery({queryKey:["alerts"],queryFn:()=>api<any>("/alerts")});
  const [selected,setSelected]=useState("");
  const [selectedAlertId,setSelectedAlertId]=useState("");
  const [disposition,setDisposition]=useState<typeof ALERT_DISPOSITIONS[number]>("true_positive");
  const [dispositionNote,setDispositionNote]=useState("");
  const [suppress,setSuppress]=useState(false);
  const items=useQuery({queryKey:["watchlist-items",selected],queryFn:()=>api<any>(`/watchlists/${selected}/items`),enabled:!!selected});
  const [name,setName]=useState("");
  const [value,setValue]=useState("");
  const [type,setType]=useState("ip");
  const [error,setError]=useState("");
  const alertRows=alerts.data?.alerts||[];
  const selectedAlert=alertRows.find((alert:any)=>alert.alert_id===selectedAlertId)||null;
  const alertContext=useMemo(()=>parseAlertContext(selectedAlert?.context),[selectedAlert?.context]);
  async function refresh(){await client.invalidateQueries({queryKey:["watchlists"]});await client.invalidateQueries({queryKey:["watchlist-items",selected]});await client.invalidateQueries({queryKey:["alerts"]});await client.invalidateQueries({queryKey:["triage"]});await client.invalidateQueries({queryKey:["analytics"]})}
  const noisy=useQuery({queryKey:["watchlist-noisy-ioc"],queryFn:()=>api<any>("/analytics/distributions?metric=noisy_ioc&range=30d")});
  const intelAge=useQuery({queryKey:["watchlist-intel-age"],queryFn:()=>api<any>("/analytics/distributions?metric=intel_age_at_match&range=30d")});
  return <><Heading title="Watchlists and alerts" subtitle="Manage monitored indicators and review deduplicated alert context before acknowledging. Disposition false positives to suppress noisy items." actions={<Link className="button secondary compact" to="/triage">Unified triage</Link>}/><OpsSurfaceKpis metrics="mtta,fpr,alert_case_ratio,fresh_ioc_ratio" /><ErrorState error={error||lists.error||alerts.error}/>
  <div className="widget-grid">
    <section className="card widget-span-6"><div className="section-head"><div><span className="section-kicker">Noise</span><h2>Noisy IOC leaderboard</h2></div><Link className="button ghost compact" to="/analytics">Analytics</Link></div>
      <HorizontalBars data={(noisy.data?.items||[]).slice(0,12).map((row:any)=>({label:String(row.label||row.key||""),value:Number(row.value??row.count??0)}))} />
    </section>
    <section className="card widget-span-6"><div className="section-head"><div><span className="section-kicker">CTI</span><h2>Intel age at match</h2></div></div>
      <HorizontalBars data={(intelAge.data?.items||[]).map((row:any)=>({label:String(row.label||row.key||""),value:Number(row.value??row.count??0)}))} />
    </section>
  </div>
  <div className="split">
    <section className="card"><h2>Watchlists</h2>{role!=="viewer"&&<form onSubmit={async e=>{e.preventDefault();try{await api("/watchlists",{method:"POST",body:JSON.stringify({name,description:""})});setName("");refresh()}catch(x){setError(message(x))}}}><label>Name<input value={name} onChange={e=>setName(e.target.value)} required/></label><button>Create</button></form>}
      <ul className="item-list">{(lists.data?.watchlists||[]).map((list:any)=><li key={list.list_id} className={selected===list.list_id?"selected":""}><button className="ghost" onClick={()=>setSelected(list.list_id)}>{list.name} ({list.item_count})</button></li>)}</ul>
      {selected&&role!=="viewer"&&<form onSubmit={async e=>{e.preventDefault();await api(`/watchlists/${selected}/items`,{method:"POST",body:JSON.stringify({items:[{ioc_type:type,ioc_value:value}]})});setValue("");refresh()}}><label>Type<select value={type} onChange={e=>setType(e.target.value)}><option>ip</option><option>domain</option><option>url</option><option>hash</option></select></label><label>Value<input value={value} onChange={e=>setValue(e.target.value)} required/></label><button>Add item</button></form>}
      <ul className="item-list">{(items.data?.items||[]).map((item:any)=><li key={item.item_id}><span>{item.ioc_type}: {item.ioc_value}</span>{role!=="viewer"&&<button className="danger" onClick={async()=>{await api(`/watchlists/${selected}/items/${item.item_id}`,{method:"DELETE"});refresh()}}>Remove</button>}</li>)}</ul>
    </section>
    <section className="card">
      <div className="section-head"><div><span className="section-kicker">Matches</span><h2>Alerts</h2></div><span className="count-badge">{alertRows.length}</span></div>
      {alertRows.length?<ul className="item-list alert-list">{alertRows.map((alert:any)=><li key={alert.alert_id} className={selectedAlertId===alert.alert_id?"selected":""}>
        <button type="button" className="ghost alert-select" onClick={()=>setSelectedAlertId(alert.alert_id)}>
          <span>{alert.watchlist_name?`${alert.watchlist_name}: `:""}{alert.ioc_type}: {alert.ioc_value}</span>
          <small>{alert.collection||"no collection"}{alert.point_id?` / ${alert.point_id}`:""} · {formatWhen(alert.triggered_at)}{alert.acknowledged?" · acknowledged":""}{alert.disposition?` · ${humanizeLabel(String(alert.disposition))}`:""}</small>
        </button>
        {!alert.acknowledged&&role!=="viewer"&&<button type="button" className="compact" onClick={async(e)=>{e.stopPropagation();await api(`/alerts/${alert.alert_id}/acknowledge`,{method:"POST"});refresh()}}>Acknowledge</button>}
      </li>)}</ul>:<EmptyState title="No alerts yet" description="Watchlist matches from ingested or pulled data appear here. Select one to inspect context before acknowledging." compact/>}
      {selectedAlert&&<div className="alert-detail">
        <div className="section-head"><div><span className="section-kicker">Selected alert</span><h3>{selectedAlert.ioc_type}: {selectedAlert.ioc_value}</h3></div>{selectedAlert.disposition?<span className="status completed">{humanizeLabel(String(selectedAlert.disposition))}</span>:selectedAlert.acknowledged?<span className="status completed">acknowledged</span>:<span className="status queued">open</span>}</div>
        <KeyValues items={[
          {label:"Watchlist",value:selectedAlert.watchlist_name||selectedAlert.list_id||"—"},
          {label:"Indicator",value:`${selectedAlert.ioc_type}: ${selectedAlert.ioc_value}`,wide:true},
          {label:"Collection",value:selectedAlert.collection||"—"},
          {label:"Point",value:selectedAlert.point_id||"—",wide:true},
          {label:"Disposition",value:selectedAlert.disposition?humanizeLabel(String(selectedAlert.disposition)):"—"},
          {label:"Triggered",value:formatWhen(selectedAlert.triggered_at)},
          {label:"Alert ID",value:selectedAlert.alert_id,wide:true},
          ...(selectedAlert.promoted_case_id?[{label:"Case",value:selectedAlert.promoted_case_id,wide:true}]:[]),
        ]}/>
        {alertContext!=null&&(typeof alertContext==="object"?<PayloadView payload={alertContext as Record<string,any>}/>:<p className="alert-context-text">{String(alertContext)}</p>)}
        {role!=="viewer"&&<div className="form-grid">
          <label>Disposition
            <select value={disposition} onChange={e=>setDisposition(e.target.value as typeof ALERT_DISPOSITIONS[number])}>
              {ALERT_DISPOSITIONS.map(d=><option key={d} value={d}>{humanizeLabel(d)}</option>)}
            </select>
          </label>
          <label>Note<textarea rows={2} value={dispositionNote} onChange={e=>setDispositionNote(e.target.value)} placeholder="Optional disposition note"/></label>
          {disposition==="false_positive"&&<label className="check setting-toggle"><input type="checkbox" checked={suppress} onChange={e=>setSuppress(e.target.checked)}/> Suppress / lower watchlist confidence</label>}
        </div>}
        <RawJson data={selectedAlert} label="Raw alert"/>
        <div className="actions">
          {!selectedAlert.acknowledged&&role!=="viewer"&&<button type="button" onClick={async()=>{await api(`/alerts/${selectedAlert.alert_id}/acknowledge`,{method:"POST"});refresh()}}>Acknowledge alert</button>}
          {role!=="viewer"&&<button type="button" onClick={async()=>{try{await api(`/alerts/${selectedAlert.alert_id}/disposition`,{method:"POST",body:JSON.stringify({disposition,note:dispositionNote,suppress_item:suppress&&disposition==="false_positive",lower_confidence:suppress&&disposition==="false_positive"})});setDispositionNote("");setSuppress(false);refresh()}catch(x){setError(message(x))}}}>Save disposition</button>}
          {role!=="viewer"&&!selectedAlert.promoted_case_id&&<button type="button" className="secondary" onClick={async()=>{try{const res=await api<any>(`/alerts/${selectedAlert.alert_id}/promote`,{method:"POST",body:JSON.stringify({note:dispositionNote})});refresh();if(res.case_id)setError("")}catch(x){setError(message(x))}}}>Promote to case</button>}
          {selectedAlert.collection&&<Link className="button secondary" to="/collections">Open collections</Link>}
          <Link className="button secondary" to="/iocs">IOC workbench</Link>
          <button type="button" className="secondary" onClick={()=>setSelectedAlertId("")}>Close detail</button>
        </div>
        <p className="muted">MISP sync for watchlist items is configured under Feeds → MISP; disposition here stays local to Black Onyx.</p>
      </div>}
    </section>
  </div></>;
}

const PUBLIC_FEED_PRESETS = [
  { name: "Microsoft Security Blog", url: "https://www.microsoft.com/en-us/security/blog/feed/", feed_type: "rss", tier: "free" },
  { name: "MSRC Security Updates", url: "https://api.msrc.microsoft.com/update-guide/rss", feed_type: "rss", tier: "free" },
  { name: "Cisco Talos", url: "https://blog.talosintelligence.com/rss/", feed_type: "rss", tier: "free" },
  { name: "Unit 42", url: "https://unit42.paloaltonetworks.com/feed/", feed_type: "rss", tier: "free" },
  { name: "Google Threat Intelligence", url: "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/", feed_type: "rss", tier: "free" },
  { name: "Check Point Research", url: "https://research.checkpoint.com/feed/", feed_type: "rss", tier: "free" },
  { name: "Securelist", url: "https://securelist.com/feed/", feed_type: "rss", tier: "free" },
  { name: "WeLiveSecurity", url: "https://www.welivesecurity.com/en/rss/feed/", feed_type: "rss", tier: "free" },
  { name: "Fortinet Threat Research", url: "https://feeds.fortinet.com/fortinet/blog/threat-research", feed_type: "rss", tier: "free" },
  { name: "Red Canary", url: "https://redcanary.com/feed/", feed_type: "rss", tier: "free" },
  { name: "Rapid7 Blog", url: "https://www.rapid7.com/blog/rss/", feed_type: "rss", tier: "free" },
  { name: "SANS Internet Storm Center", url: "https://isc.sans.edu/rssfeed.xml", feed_type: "rss", tier: "free" },
  { name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews", feed_type: "rss", tier: "free" },
  { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/", feed_type: "rss", tier: "free" },
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/", feed_type: "rss", tier: "free" },
  { name: "The Record", url: "https://therecord.media/feed", feed_type: "rss", tier: "free" },
  { name: "Exploit-DB", url: "https://www.exploit-db.com/rss.xml", feed_type: "rss", tier: "free" },
  // CISA.gov RSS often returns HTTP 403 from datacenter IPs — prefer KEV enrichment + vendor blogs.
] as const;

export function FeedsWorkflow({role}:{role:Role}) {
  const client=useQueryClient();
  const feeds=useQuery({queryKey:["feeds"],queryFn:()=>api<any>("/feeds")});
  const webhooks=useQuery({queryKey:["webhooks"],queryFn:()=>api<any>("/webhooks"),enabled:role==="admin",retry:false});
  const misp=useQuery({queryKey:["misp-status"],queryFn:()=>api<any>("/misp/status")});
  const [tab,setTab]=useState<"active"|"add"|"presets"|"webhooks"|"misp">("active");
  const [feedFilter,setFeedFilter]=useState<"all"|"rss"|"atom"|"taxii">("all");
  const [name,setName]=useState("");
  const [url,setUrl]=useState("");
  const [type,setType]=useState("rss");
  const [collection,setCollection]=useState("all-knowledge");
  const [passwordEnv,setPasswordEnv]=useState("");
  const [webhookName,setWebhookName]=useState("");
  const [createdToken,setCreatedToken]=useState<any>();
  const [mispUrl,setMispUrl]=useState("");
  const [mispKey,setMispKey]=useState("");
  const [mispCollection,setMispCollection]=useState("all-knowledge");
  const [mispSyncResult,setMispSyncResult]=useState<any>();
  const [result,setResult]=useState<any>();
  const [outcomes,setOutcomes]=useState<Record<string,any>>({});
  const [polling,setPolling]=useState("");
  const [error,setError]=useState("");
  const admin=role==="admin";
  const allFeeds=feeds.data?.feeds||[];
  const visibleFeeds=feedFilter==="all"?allFeeds:allFeeds.filter((feed:any)=>(feed.feed_type||"rss")===feedFilter);
  useEffect(()=>{if(name)setCollection(feedCollectionName(name))},[name]);
  useEffect(()=>{if(misp.data?.url)setMispUrl(misp.data.url);if(misp.data?.collection)setMispCollection(misp.data.collection)},[misp.data]);
  async function refresh(){await client.invalidateQueries({queryKey:["feeds"]});await client.invalidateQueries({queryKey:["collections"]});await client.invalidateQueries({queryKey:["webhooks"]});await client.invalidateQueries({queryKey:["misp-status"]})}
  async function pollFeed(feedName:string){
    setPolling(feedName);setError("");
    try{
      const outcome=await api<any>(`/feeds/${encodeURIComponent(feedName)}/poll`,{method:"POST"});
      setResult(outcome);
      setOutcomes(prev=>({...prev,[feedName]:outcome}));
      if(outcome?.error)setError(`${feedName}: ${outcome.error}`);
      await refresh();
    }catch(e){setError(message(e))}
    finally{setPolling("")}
  }
  async function pollAll(){
    setPolling("*");setError("");
    try{
      const response=await api<any>("/feeds/poll-all",{method:"POST"});
      const results=response?.results||{};
      setResult(response);
      setOutcomes(prev=>({...prev,...results}));
      const failed=Object.entries(results).filter(([,value]:any)=>value?.error).map(([key,value]:any)=>`${key}: ${value.error}`);
      if(failed.length)setError(failed.join(" · "));
      else if(!Object.keys(results).length)setError("No feeds were due for polling yet — use Poll now on a feed to force it.");
      await refresh();
    }catch(e){setError(message(e))}
    finally{setPolling("")}
  }
  async function addFeed(feedName:string, feedUrl:string, feedType:string){
    try{
      setError("");
      await api("/feeds",{method:"POST",body:JSON.stringify({name:feedName,url:feedUrl,feed_type:feedType,collection:feedCollectionName(feedName),poll_interval_minutes:60,config:null})});
      setTab("active");
      await refresh();
    }catch(x){setError(message(x))}
  }
  const tabs:[typeof tab,string,boolean][]=[
    ["active","Active feeds",true],
    ["add","Add feed",admin],
    ["presets","Presets",admin],
    ["webhooks","Inbound webhooks",admin],
    ["misp","MISP",true],
  ];
  return <><Heading title="Intelligence feeds" subtitle="RSS, Atom, TAXII, inbound webhooks, and MISP — organized by source type." actions={role!=="viewer"?<button type="button" disabled={!!polling} onClick={pollAll}>{polling==="*"?"Polling…":"Poll due feeds"}</button>:undefined}/>
  <OpsSurfaceKpis metrics="intel_hit_rate,fresh_ioc_ratio,fpr,mtta" />
  <ErrorState error={error||feeds.error||webhooks.error||misp.error}/>
  <div className="tabs feeds-tabs" role="tablist" aria-label="Feed sections">
    {tabs.filter(([, , show])=>show).map(([key,label])=><button key={key} type="button" role="tab" aria-selected={tab===key} onClick={()=>setTab(key)}>{label}</button>)}
  </div>

  {tab==="active"&&<>
    <div className="tabs feed-type-tabs" role="tablist" aria-label="Feed type filter">
      {([["all","All"],["rss","RSS"],["atom","Atom"],["taxii","TAXII"]] as const).map(([key,label])=><button key={key} type="button" role="tab" aria-selected={feedFilter===key} onClick={()=>setFeedFilter(key)}>{label}{key==="all"?` (${allFeeds.length})`:""}</button>)}
    </div>
    <div className="result-grid">{visibleFeeds.map((feed:any)=>{
      const outcome=outcomes[feed.name];
      const status=outcome?(outcome.error?"failed":outcome.skipped?"queued":"completed"):feed.last_status==="failed"?"failed":feed.last_status==="ok"?"completed":"";
      const statusLabel=status==="failed"?"Failing":status==="completed"?"Healthy":status==="queued"?"Not due":"Never polled";
      return <article className="card" key={feed.name}>
        <div className="section-head"><div><span className="section-kicker">{feed.feed_type||"rss"}</span><h2>{feed.name}</h2></div><span className={`status ${status}`}>{statusLabel}</span></div>
        <KeyValues items={[
          {label:"URL",value:feed.url,wide:true},
          {label:"Collection",value:feed.collection||"—"},
          {label:"Interval",value:`${feed.poll_interval_minutes||60} min`},
          {label:"Last successful poll",value:formatWhen(feed.last_poll)},
          ...(feed.last_attempt?[{label:"Last attempt",value:formatWhen(feed.last_attempt)}]:[]),
        ]}/>
        {outcome?(outcome.error?<p className="feed-outcome failed">{outcome.error}</p>:outcome.skipped?<p className="feed-outcome">{outcome.skipped}</p>:<StatRow items={[
          {label:"In feed",value:outcome.items_available??0},
          {label:"Ingested",value:outcome.items_processed??0,tone:"ok"},
          {label:"IOCs",value:outcome.iocs_extracted??0},
          ...(outcome.items_deferred?[{label:"Queued for next poll",value:outcome.items_deferred,tone:"warn" as const}]:[]),
          ...(outcome.items_failed?[{label:"Failed",value:outcome.items_failed,tone:"bad" as const}]:[]),
        ]}/>):feed.last_error?<p className="feed-outcome failed">{feed.last_error}</p>:null}
        <div className="actions">{role!=="viewer"&&<button type="button" disabled={!!polling} onClick={()=>pollFeed(feed.name)}>{polling===feed.name?"Polling…":"Poll now"}</button>}{admin&&<ConfirmDialog label="Delete" expected={feed.name} onConfirm={async()=>{await api(`/feeds/${encodeURIComponent(feed.name)}`,{method:"DELETE"});refresh()}}/>}</div>
      </article>;
    })}</div>
    {!visibleFeeds.length&&<section className="card"><EmptyState title={allFeeds.length?"No feeds for this type":"No feeds configured"} description={admin?"Use Add feed or Presets to configure an HTTPS RSS, Atom, or TAXII source.":"Ask an administrator to add approved feeds, then poll them here."} compact/></section>}
    {result&&<section className="card"><h2>Last poll outcome</h2><DataTable
      columns={[
        {key:"feed",label:"Feed"},
        {key:"state",label:"Result",render:(row:any)=><span className={`status ${row.error?"failed":row.skipped?"queued":"completed"}`}>{row.error?"failed":row.skipped?"skipped":"ok"}</span>},
        {key:"items_available",label:"In feed",render:(row:any)=>row.items_available??"—"},
        {key:"items_processed",label:"Ingested",render:(row:any)=>row.items_processed??"—"},
        {key:"iocs_extracted",label:"IOCs",render:(row:any)=>row.iocs_extracted??"—"},
        {key:"items_deferred",label:"Queued",render:(row:any)=>row.items_deferred||"—"},
        {key:"detail",label:"Detail",render:(row:any)=>row.error||row.skipped||"—"},
      ]}
      rows={result.results?Object.entries(result.results).map(([feedName,value]:any)=>({feed:feedName,...value})):[{feed:result.feed,...result}]}
      rowKey={(row:any,index:number)=>`${row.feed}-${index}`}
      empty={<EmptyState title="No feeds were due" description="Every feed has been polled within its interval. Use Poll now on a feed to force a fetch." compact/>}
    /><RawJson data={result}/></section>}
  </>}

  {tab==="add"&&admin&&<form className="card form-grid" onSubmit={async e=>{e.preventDefault();try{await api("/feeds",{method:"POST",body:JSON.stringify({name,url,feed_type:type,collection,poll_interval_minutes:60,config:type==="taxii"?{password_env:passwordEnv}:null})});setName("");setUrl("");setTab("active");refresh()}catch(x){setError(message(x))}}}><div className="section-head"><div><span className="section-kicker">Custom source</span><h2>Add feed</h2></div></div><label>Name<input value={name} onChange={e=>setName(e.target.value)} required/></label><label>HTTPS URL<input type="url" value={url} onChange={e=>setUrl(e.target.value)} required/></label><label>Type<select value={type} onChange={e=>setType(e.target.value)}><option>rss</option><option>atom</option><option>taxii</option></select></label><CollectionSelect value={collection} onChange={setCollection} required/>{type==="taxii"&&<label>Password environment variable<input value={passwordEnv} onChange={e=>setPasswordEnv(e.target.value)} required/></label>}<button type="submit">Add feed</button></form>}

  {tab==="presets"&&admin&&<section className="card"><div className="section-head"><div><span className="section-kicker">Catalog</span><h2>Public free feed presets</h2></div></div><p className="section-description">One-click add for commonly used free threat-intel RSS sources. Paid TAXII/commercial APIs still need credentials under Settings → Feeds.</p><div className="result-grid">{PUBLIC_FEED_PRESETS.map(preset=><article className="card" key={preset.name}><h3>{preset.name}</h3><p>{preset.url}</p><small>{preset.tier} · {preset.feed_type}</small><div className="actions"><button type="button" onClick={()=>{setName(preset.name);setUrl(preset.url);setType(preset.feed_type);setTab("add")}}>Use in form</button><button type="button" className="secondary" onClick={()=>addFeed(preset.name,preset.url,preset.feed_type)}>Add now</button></div></article>)}</div></section>}

  {tab==="webhooks"&&admin&&<section className="card"><div className="section-head"><div><span className="section-kicker">Automation</span><h2>Inbound webhooks</h2></div></div><p className="section-description">POST JSON to <code>/api/v1/webhooks/events</code> with header <code>X-Webhook-Token</code> (or Bearer). Body may include <code>text</code> for extraction and/or structured <code>iocs</code>. Sightings feed Decay and can raise Watchlist alerts.</p><form className="form-grid" onSubmit={async e=>{e.preventDefault();try{setError("");const created=await api<any>("/webhooks",{method:"POST",body:JSON.stringify({name:webhookName})});setCreatedToken(created);setWebhookName("");refresh()}catch(x){setError(message(x))}}}><label>Webhook name<input value={webhookName} onChange={e=>setWebhookName(e.target.value)} placeholder="splunk-alerts" required/></label><button type="submit">Create webhook</button></form>{createdToken&&<Notice>Copy this token now — it is shown once: <code>{createdToken.token}</code></Notice>}<ul className="item-list">{(webhooks.data?.webhooks||[]).map((hook:any)=><li key={hook.webhook_id}><span>{hook.name}<small>prefix {hook.token_prefix}… · {hook.event_count} events · {hook.enabled?"enabled":"disabled"}</small></span><div className="actions"><button type="button" className="secondary" onClick={async()=>{await api(`/webhooks/${hook.webhook_id}/${hook.enabled?"disable":"enable"}`,{method:"POST"});refresh()}}>{hook.enabled?"Disable":"Enable"}</button><ConfirmDialog label="Revoke" expected={hook.name} onConfirm={async()=>{await api(`/webhooks/${hook.webhook_id}`,{method:"DELETE"});refresh()}}/></div></li>)}</ul>{!(webhooks.data?.webhooks||[]).length&&<EmptyState title="No webhooks yet" description="Create a token above, then point your SIEM, EDR, or log shipper at the events endpoint." compact/>}</section>}

  {tab==="misp"&&<section className="card"><div className="section-head"><div><span className="section-kicker">MISP</span><h2>MISP connection</h2></div><span className={`status ${misp.data?.configured?"completed":"failed"}`}>{misp.data?.status||"loading"}</span></div>
    <p className="section-description">Connect to a MISP instance over HTTPS to pull recent events and publish case IOCs. API keys are stored as the <code>MISP_API_KEY</code> runtime secret. DigitalSide and similar community MISP JSON feeds are not RSS — use this connection instead of the preset catalog.</p>
    <KeyValues items={[
      {label:"URL",value:misp.data?.url||"—",wide:true},
      {label:"API key",value:misp.data?.api_key_present?"configured":"missing"},
      {label:"Watchlist",value:misp.data?.collection||"—"},
      {label:"Last sync",value:formatWhen(misp.data?.last_sync)},
      {label:"Synced events",value:misp.data?.synced_event_count??0},
      {label:"Synced IOCs",value:misp.data?.synced_ioc_count??0},
      {label:"Published",value:misp.data?.published_count??0},
    ]}/>
    {admin&&<form className="form-grid" onSubmit={async e=>{e.preventDefault();try{setError("");await api("/misp/configure",{method:"PUT",body:JSON.stringify({url:mispUrl,api_key:mispKey||null,api_key_env:"MISP_API_KEY",collection:mispCollection,enabled:true})});setMispKey("");await refresh()}catch(x){setError(message(x))}}}><label>MISP HTTPS URL<input type="url" value={mispUrl} onChange={e=>setMispUrl(e.target.value)} placeholder="https://misp.example.com" required/></label><label>API key <small>leave blank to keep existing</small><input type="password" value={mispKey} onChange={e=>setMispKey(e.target.value)} autoComplete="off"/></label><label>Watchlist for synced IOCs<input value={mispCollection} onChange={e=>setMispCollection(e.target.value)}/></label><button type="submit">Save MISP connection</button></form>}
    {role!=="viewer"&&<div className="actions"><button type="button" className="secondary" onClick={async()=>{try{setError("");setMispSyncResult(await api<any>("/misp/sync",{method:"POST"}));await refresh()}catch(x){setError(message(x))}}}>Sync now</button></div>}
    {mispSyncResult&&<Notice>Pulled {mispSyncResult.count??0} event(s), {mispSyncResult.ioc_count??0} IOC(s) into watchlist {mispSyncResult.watchlist||mispCollection}.</Notice>}
  </section>}
  </>;
}

export function DecayWorkflow({role}:{role:Role}) {
  const [view,setView]=useState("tracked");
  const query=useQuery({queryKey:["decay",view],queryFn:()=>api<any>(`/decay/${view}`)});
  const iocs=query.data?.iocs||[];
  const fresh=iocs.filter((item:any)=>Number(item.decay_score)>=0.7).length;
  const stale=iocs.filter((item:any)=>Number(item.decay_score)<0.3).length;
  const freshTs=useQuery({queryKey:["decay-fresh-ts"],queryFn:()=>api<any>("/analytics/timeseries?metric=fresh_iocs&group_by=day&range=30d")});
  const staleTs=useQuery({queryKey:["decay-stale-ts"],queryFn:()=>api<any>("/analytics/timeseries?metric=stale_iocs&group_by=day&range=30d")});
  return <><Heading title="IOC freshness and decay" subtitle="Review sighting history and recalculate confidence decay." actions={role!=="viewer"?<button type="button" onClick={async()=>{await api("/decay/update-scores",{method:"POST"});query.refetch()}}>Update scores</button>:undefined}/>
  <OpsSurfaceKpis metrics="fresh_ioc_ratio,fpr,mtta" />
  <div className="widget-grid">
    <section className="card widget-span-6"><div className="section-head"><div><span className="section-kicker">Trend</span><h2>Fresh IOCs (30d)</h2></div></div>
      <TimeSeriesArea data={(freshTs.data?.points||[]).map((p:any)=>({label:String(p.label||p.bucket||""),value:Number(p.value??p.count??0)}))} color="#6C3CF2" />
    </section>
    <section className="card widget-span-6"><div className="section-head"><div><span className="section-kicker">Trend</span><h2>Stale IOCs (30d)</h2></div></div>
      <TimeSeriesArea data={(staleTs.data?.points||[]).map((p:any)=>({label:String(p.label||p.bucket||""),value:Number(p.value??p.count??0)}))} color="#f07178" />
    </section>
  </div>
  <div className="tabs" role="tablist"><button type="button" role="tab" aria-selected={view==="tracked"} onClick={()=>setView("tracked")}>Tracked</button><button type="button" role="tab" aria-selected={view==="fresh"} onClick={()=>setView("fresh")}>Fresh</button><button type="button" role="tab" aria-selected={view==="stale"} onClick={()=>setView("stale")}>Stale</button></div>
  <ErrorState error={query.error}/>
  <section className="card">
    {iocs.length?<>
      <StatRow items={[{label:"Indicators",value:iocs.length},{label:"Fresh",value:fresh,tone:"ok"},{label:"Stale",value:stale,tone:"bad"}]}/>
      <DataTable
        columns={[
          {key:"ioc_type",label:"Type",render:(row:any)=><span className="chip accent">{row.ioc_type}</span>},
          {key:"ioc_value",label:"Indicator",clip:true},
          {key:"decay_score",label:"Confidence",render:(row:any)=><ScoreBar value={row.decay_score}/>},
          {key:"sighting_count",label:"Sightings",render:(row:any)=>`${row.sighting_count??0} from ${row.source_count??0} source(s)`},
          {key:"first_seen",label:"First seen",nowrap:true,render:(row:any)=>formatWhen(row.first_seen)},
          {key:"last_seen",label:"Last seen",nowrap:true,render:(row:any)=>formatWhen(row.last_seen)},
        ]}
        rows={iocs}
        rowKey={(row:any,index:number)=>`${row.ioc_type}-${row.ioc_value}-${index}`}
      />
      <RawJson data={iocs}/>
    </>:<EmptyState title="No decay scores yet" description="Indicators appear here after enrichment scoring or ingest sightings. Use the IOC workbench to enrich an indicator, then return and click Update scores." compact/>}
  </section></>;
}

export function BookmarksWorkflow(){
  const bookmarks=useQuery({queryKey:["bookmarks"],queryFn:()=>api<any>("/bookmarks")});
  const client=useQueryClient();
  const [error,setError]=useState("");
  const items=bookmarks.data?.bookmarks||[];
  async function remove(collection:string,pointId:string){
    try{setError("");await api("/bookmarks",{method:"POST",body:JSON.stringify({collection,point_id:pointId})});await client.invalidateQueries({queryKey:["bookmarks"]})}
    catch(e){setError(message(e))}
  }
  return <><Heading title="Bookmarks" subtitle="Your private shortlist of investigation points."/><ErrorState error={error||bookmarks.error}/>
  <section className="card">
    {items.length?<>
      <StatRow items={[{label:"Bookmarks",value:items.length},{label:"Collections",value:new Set(items.map((item:any)=>item.collection)).size}]}/>
      <DataTable
        columns={[
          {key:"collection",label:"Collection"},
          {key:"point_id",label:"Point",clip:true},
          {key:"created_at",label:"Saved",nowrap:true,render:(row:any)=>formatWhen(row.created_at)},
          {key:"actions",label:"",render:(row:any)=><button type="button" className="danger compact" onClick={()=>remove(row.collection,row.point_id)}>Remove</button>},
        ]}
        rows={items}
        rowKey={(row:any,index:number)=>row.bookmark_id||`${row.collection}-${row.point_id}-${index}`}
      />
      <RawJson data={items}/>
    </>:<EmptyState title="No bookmarks yet" description="Open Collections, select an evidence point, then use Toggle bookmark. Bookmarked points show up here for quick return." compact/>}
  </section></>;
}

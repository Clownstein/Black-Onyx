import React, { FormEvent, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import { ChatComposerMenu, ChatToolApproval, formatSecurityEvidence, stripExecutionControlArgs } from "./chat_composer_menu";
import { api, streamChat } from "./api";
import { EmptyState, ErrorState, Heading, RagCollectionPicker } from "./ui";
import { useUser } from "./user_context";
import { isOperational } from "./rbac";
import { SecurityLabWorkflow } from "./workflows_security_lab";

function useRef<T>(initial?: T) { return React.useRef<T | undefined>(initial); }

export function ChatWorkflow() {
  const sessions = useQuery({queryKey:["sessions"], queryFn:()=>api<any[]>("/sessions")});
  const providers = useQuery({queryKey:["llm-providers"], queryFn:()=>api<{providers:string[];active?:string;details?:Record<string,{label:string;model:string}>}>("/llm/providers")});
  const capabilities = useQuery({queryKey:["capabilities"], queryFn:()=>api<any>("/capabilities")});
  const mcpCatalog = useQuery({
    queryKey: ["mcp-tools"],
    queryFn: () => api<{ enabled: boolean; lab_profile_id: string; allowed_targets?: string[] }>("/mcp/tools"),
    enabled: Boolean(capabilities.data?.features?.mcp_tools),
  });
  const [session,setSession] = useState("");
  const [provider,setProvider] = useState("");
  const [messages,setMessages] = useState<{role:string;content:string;reasoning?:string;meta?:string}[]>([]);
  const [input,setInput] = useState("");
  const [images,setImages] = useState<File[]>([]);
  const [collections,setCollections] = useState<string[]>([]);
  const [useWebSearch,setUseWebSearch] = useState(false);
  const [selectedMcpTools,setSelectedMcpTools] = useState<string[]>([]);
  const [mcpLabProfile,setMcpLabProfile] = useState("anvil");
  const [sources,setSources] = useState<any[]>([]);
  const [tools,setTools] = useState<any[]>([]);
  const [error,setError] = useState("");
  const [streaming,setStreaming] = useState(false);
  const [showSettings,setShowSettings] = useState(false);
  // Runtime model overrides
  const [temperature,setTemperature] = useState<number>(0.7);
  const [maxTokens,setMaxTokens] = useState<number>(4096);
  const [thinkingLevel,setThinkingLevel] = useState<string>("OFF");
  const [systemPromptOverride,setSystemPromptOverride] = useState<string>("");
  const controller = useRef<AbortController>();
  const defaultsReady = useRef(false);
  const chatEndRef = useRef<HTMLDivElement | null>(null);
  const setChatEndRef = (node: HTMLDivElement | null) => { chatEndRef.current = node; };

  useEffect(()=>{
    if(defaultsReady.current || !capabilities.data) return;
    const rag = capabilities.data?.rag?.collections;
    if(Array.isArray(rag) && rag.length) setCollections(rag);
    const active = capabilities.data?.llm_provider || providers.data?.active;
    if(typeof active === "string" && active) setProvider(active);
    defaultsReady.current = true;
  },[capabilities.data, providers.data?.active]);

  useEffect(()=>{
    chatEndRef.current?.scrollIntoView({behavior:"smooth"});
  },[messages, tools, streaming]);

  const webAvailable = Boolean(capabilities.data?.features?.web_search);
  const mcpAvailable = Boolean(capabilities.data?.features?.mcp_tools);
  const useMcpTools = selectedMcpTools.length > 0;
  useEffect(() => {
    if (mcpCatalog.data?.lab_profile_id) setMcpLabProfile(mcpCatalog.data.lab_profile_id);
  }, [mcpCatalog.data?.lab_profile_id]);

  async function load(id:string) {
    setSession(id); setImages([]); setSources([]); setTools([]);
    try {
      const value=await api<any>(`/sessions/${id}/messages`);
      setMessages(value.messages);
      const selected=(sessions.data||[]).find(item=>item.session_id===id);
      if(selected?.provider)setProvider(selected.provider);
    } catch(reason) { setError(reason instanceof Error?reason.message:"Load failed"); }
  }

  async function runTurn(text: string, display?: string) {
    setError(""); setStreaming(true); setSources([]); setTools([]);
    setMessages(old=>[...old,{role:"user",content:display||text},{role:"assistant",content:"",reasoning:""}]);
    try {
      controller.current=new AbortController();
      await streamChat({
        message:text,
        session_id:session||null,
        provider,
        collections,
        use_rag:collections.length>0,
        use_web_search:useWebSearch,
        use_mcp_tools:useMcpTools,
        mcp_tool_names:useMcpTools?selectedMcpTools:undefined,
        temperature,
        max_tokens:maxTokens,
        thinking_level:thinkingLevel==="OFF"?undefined:thinkingLevel,
        system_prompt:systemPromptOverride.trim()||undefined,
      },(event,data)=>{
        if(event==="session")setSession(JSON.parse(data).session_id);
        if(event==="token")setMessages(old=>old.map((item,index)=>index===old.length-1?{...item,content:item.content+data}:item));
        if(event==="reasoning")setMessages(old=>old.map((item,index)=>index===old.length-1?{...item,reasoning:(item.reasoning||"")+data}:item));
        if(event==="source"){ try{ setSources(old=>[...old, JSON.parse(data)]); }catch{ /* ignore */ } }
        if(event==="tool"){ try{ setTools(old=>[...old, JSON.parse(data)]); }catch{ /* ignore */ } }
        if(event==="error")throw new Error(data||"Chat stream failed");
      },controller.current.signal);
      sessions.refetch();
    } catch(reason) {
      if((reason as Error).name!=="AbortError")setError(reason instanceof Error?reason.message:"Chat failed");
    } finally { setStreaming(false); }
  }

  async function submit(e:FormEvent) {
    e.preventDefault(); const text=input.trim(); if(!text)return;
    setInput("");
    if(images.length) {
      setError(""); setStreaming(true); setSources([]); setTools([]);
      setMessages(old=>[...old,{role:"user",content:`${text}\n\n[${images.length} image(s) attached]`},{role:"assistant",content:"",reasoning:""}]);
      try {
        const body=new FormData();
        images.forEach(image=>body.append("images",image));
        body.append("message",text); body.append("provider",provider);
        if(session)body.append("session_id",session);
        const result=await api<any>("/chat/images",{method:"POST",body});
        setSession(result.session_id); setImages([]);
        setMessages(old=>old.map((item,index)=>index===old.length-1?{...item,content:result.response}:item));
        sessions.refetch();
      } catch(reason) {
        setError(reason instanceof Error?reason.message:"Chat failed");
      } finally { setStreaming(false); }
      return;
    }
    await runTurn(text);
  }

  const footerParts = [
    images.length ? `${images.length} image${images.length===1?"":"s"} attached` : "",
    collections.length ? `RAG: ${collections.join(", ")}` : "RAG off",
    useWebSearch ? "Web search on" : "",
    useMcpTools ? `MCP tools on${(mcpCatalog.data?.allowed_targets||[]).length?` · allowlist ${(mcpCatalog.data?.allowed_targets||[]).length}`:" · no allowlist"}` : "",
    `temp ${temperature.toFixed(1)}`,
    `max ${maxTokens}`,
    thinkingLevel!=="OFF"?`think ${thinkingLevel.toLowerCase()}`:"",
  ].filter(Boolean);

  const promptChips = [
    "Review this code for security issues; list CWE-style findings and mitigations",
    "Summarize this threat intel report; extract IOCs and ATT&CK techniques with confidence",
    "Summarize open alerts and recommend dispositions",
    "Which IOCs should we enrich next?",
    "Draft an ops digest for the last 7 days",
  ];

  function providerLabel(id:string) {
    return providers.data?.details?.[id]?.label || id;
  }

  function resetSettings() {
    setTemperature(0.7); setMaxTokens(4096); setThinkingLevel("OFF"); setSystemPromptOverride("");
  }

  return <>
    <Heading kicker="AI assist" title="Chat" subtitle="Analyst sessions with evidence, MCP tools, and Security Lab runs in one place." actions={<>
      <button className="ghost compact" onClick={()=>setShowSettings(s=>!s)} title="Model settings">{showSettings?"Hide settings":"Settings"}</button>
      {streaming?<button className="danger" onClick={()=>controller.current?.abort()}>Cancel stream</button>:undefined}
    </>}/>
    <div className="chat-layout aikit">
      <section className="card session-panel">
        <div className="section-head"><div><span className="section-kicker">Workspace</span><h2>Sessions</h2></div><button className="compact" onClick={()=>{setSession("");setMessages([]);setImages([]);setSources([]);setTools([])}}>+ New</button></div>
        {(sessions.data||[]).length?<ul className="item-list session-list">{(sessions.data||[]).map(value=><li className={session===value.session_id?"selected":""} key={value.session_id}><button className="ghost" onClick={()=>load(value.session_id)}>{value.title}</button><button className="icon-danger" aria-label={`Delete ${value.title}`} onClick={async()=>{await api(`/sessions/${value.session_id}`,{method:"DELETE"});if(session===value.session_id){setSession("");setMessages([])}sessions.refetch()}}>×</button></li>)}</ul>:<EmptyState title="No conversations" description="Start a new private analyst session." compact />}
      </section>
      <section className="chat-stack">
        {showSettings&&<div className="card chat-settings-drawer">
          <div className="section-head"><div><span className="section-kicker">Runtime</span><h2>Model parameters</h2></div><button className="ghost compact" onClick={resetSettings}>Reset</button></div>
          <div className="settings-fields">
            <label className="settings-slider"><span>Temperature <strong>{temperature.toFixed(2)}</strong></span><input type="range" min="0" max="2" step="0.05" value={temperature} onChange={e=>setTemperature(Number(e.target.value))}/></label>
            <label className="settings-input"><span>Max tokens</span><input type="number" min="1" max="32768" step="256" value={maxTokens} onChange={e=>setMaxTokens(Number(e.target.value))}/></label>
            <label className="settings-select"><span>Thinking level</span><select value={thinkingLevel} onChange={e=>setThinkingLevel(e.target.value)}><option value="OFF">Off</option><option value="LOW">Low</option><option value="MEDIUM">Medium</option><option value="HIGH">High</option></select></label>
          </div>
          <label className="settings-textarea"><span>System prompt override <small>(empty = use config default)</small></span><textarea rows={3} placeholder="Answer the analyst's question, cite evidence chunks, recommend actions only…" value={systemPromptOverride} onChange={e=>setSystemPromptOverride(e.target.value)}/></label>
          <p className="muted small">Overrides apply to plain and RAG chat turns. MCP tool turns use the tool-declaration system prompt.</p>
        </div>}
        <div className="card chat" aria-live="polite">
          {messages.length?<>
            {messages.map((item,index)=>{
              const isLast=index===messages.length-1;
              const isStreaming=streaming&&isLast&&item.role==="assistant";
              // Insert tool cards before the assistant response they belong to
              const toolCards=item.role==="assistant"&&isLast?tools:[];
              return <React.Fragment key={index}>
                {toolCards.length>0&&<div className="chat-tool-cards">{toolCards.map((tool,tIndex)=>
                  <div key={`tool-${tIndex}`} className={`chat-tool-card ${tool.status||"running"}`}>
                    <div className="chat-tool-card-head">
                      <span className="chat-tool-icon">⚙</span>
                      <strong>{tool.name||"tool"}</strong>
                      <span className={`chat-tool-status ${(tool.status||"running")}`}>{tool.status||"running"}</span>
                    </div>
                    {tool.args&&Object.keys(stripExecutionControlArgs(tool.args as Record<string, unknown>)).length>0&&<pre className="chat-tool-args">{JSON.stringify(stripExecutionControlArgs(tool.args as Record<string, unknown>),null,2)}</pre>}
                    {tool.summary&&<pre className="chat-tool-summary">{String(tool.summary).slice(0,300)}</pre>}
                    {String(tool.summary||"").includes("approval_id")?<ChatToolApproval toolName={String(tool.name||"")} args={(tool.args||{}) as Record<string, unknown>} labProfileId={mcpLabProfile} onComplete={(result)=>{ if(streaming) return; void runTurn(formatSecurityEvidence(String(tool.name||""), result, (tool.args||{}) as Record<string, unknown>)); }}/>:null}
                  </div>
                )}</div>}
                <article className={`bubble ${item.role}`}>
                  <span className="message-role">{item.role==="user"?"You":"Assistant"}</span>
                  {item.reasoning?<details className="reasoning-block"><summary>Reasoning</summary><pre>{item.reasoning}</pre></details>:null}
                  <div className="message-content"><ReactMarkdown skipHtml>{item.content||(isStreaming?"":"")}</ReactMarkdown></div>
                  {isStreaming&&<span className="chat-streaming-indicator"><span></span><span></span><span></span></span>}
                </article>
              </React.Fragment>;
            })}
            <div ref={setChatEndRef}/>
          </>:<EmptyState title="Ready for analysis" description="Ask about indexed evidence, indicators, or attach images for multimodal review." />}
        </div>
        <form className="card chat-composer" onSubmit={submit}>
          <div className="prompt-chips">{promptChips.map(chip=><button key={chip} type="button" className="ghost" onClick={()=>setInput(chip)}>{chip}</button>)}</div>
          <div className="composer-toolbar">
            <label className="composer-provider">Provider<select value={provider || (providers.data?.providers||["local"])[0]} disabled={!!session} onChange={e=>setProvider(e.target.value)}>{(providers.data?.providers||["local"]).map(value=><option key={value} value={value}>{providerLabel(value)}</option>)}</select></label>
            <label className="composer-chip file-control"><span>Attach</span><input type="file" accept="image/*" multiple onChange={e=>setImages(Array.from(e.target.files||[]).slice(0,5))}/></label>
            <RagCollectionPicker values={collections} onChange={setCollections}/>
            <label className={`composer-chip ${useWebSearch?"active":""} ${!webAvailable?"disabled":""}`} title={!webAvailable?"Enable SearXNG in Settings":undefined}>
              <input type="checkbox" checked={useWebSearch} disabled={!webAvailable||useMcpTools} onChange={e=>{setUseWebSearch(e.target.checked); if(e.target.checked)setSelectedMcpTools([]);}}/>
              Web search
            </label>
            <ChatComposerMenu
              mcpAvailable={mcpAvailable && !useWebSearch}
              selected={selectedMcpTools}
              onChangeSelected={(names)=>{ setSelectedMcpTools(names); if(names.length) setUseWebSearch(false); }}
              onAttach={(files)=>setImages(files)}
              onOpenSystem={()=>setShowSettings(true)}
              disabled={streaming}
            />
          </div>
          {images.length>0&&<p className="composer-attachment-summary">{images.length} image{images.length===1?"":"s"} ready · {images.map(file=>file.name).join(", ")}</p>}
          <label className="message-field"><span className="visually-hidden">Message</span><textarea rows={3} placeholder="Ask Black Onyx to analyze the current evidence…" value={input} onChange={e=>setInput(e.target.value)} required/></label>
          <div className="composer-footer"><small>{footerParts.join(" · ") || "Direct model reply"}</small><button disabled={streaming}>Send message</button></div>
        </form>
        <ErrorState error={error||providers.error}/>
        {isOperational(useUser().role)?<details className="card chat-lab-drawer"><summary>Direct tool run</summary><React.Suspense fallback={<p className="muted">Loading tools…</p>}><SecurityLabWorkflow embedded onComplete={(payload)=>{ if(streaming) return; void runTurn(formatSecurityEvidence(payload.tool, payload.result, payload.args)); }}/></React.Suspense></details>:null}
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

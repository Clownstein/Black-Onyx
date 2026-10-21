/**
 * Security Lab workflow run defensive security tools against targets.
 *
 * Exposes the enabled security tools (scanners, binary RE, crypto/DFIR, Web3)
 * through the BFF at /api/v1/security/*. Non-read tools require explicit
 * approval via the approval gate.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  listSecurityTools,
  executeSecurityTool,
  previewSecurityTool,
  approveSecurityTool,
  runSecurityAgent,
  getSecurityAgentRun,
  resumeSecurityAgentRun,
  securityHealth,
  type SecurityTool,
  type AgentRunResponse,
  type ToolPreview,
  type ToolExecutionResult,
} from "./detection/api/security_client";
import { useUser } from "./user_context";

type ToolCategory = "sandbox" | "security" | "binary" | "crypto" | "web3";

const CATEGORIES: { id: ToolCategory; label: string }[] = [
  { id: "sandbox", label: "Sandbox" },
  { id: "security", label: "Network Scanners" },
  { id: "binary", label: "Binary RE" },
  { id: "crypto", label: "Crypto / DFIR" },
  { id: "web3", label: "Web3" },
];

const READ_TIERS = new Set(["read"]);
const NETWORK_SCOPED_TOOLS = new Set([
  "nmap_scan", "sqlmap_scan", "nikto_scan", "whois_lookup", "gobuster_dir",
  "hydra_brute", "port_scan", "cast_call", "get_contract_storage",
]);

function tierBadgeClass(tier: string): string {
  switch (tier) {
    case "read": return "security-tier tone-ok";
    case "workspace-write": return "security-tier tone-warn";
    case "network": return "security-tier tone-warn";
    case "code-execution": return "security-tier tone-bad";
    case "privileged-capture": return "security-tier tone-bad";
    case "transaction": return "security-tier tone-bad";
    case "lab": return "security-tier tone-warn";
    case "destructive": return "security-tier tone-bad";
    default: return "security-tier";
  }
}

interface ArgSchema {
  type?: string;
  description?: string;
  default?: unknown;
  maxLength?: number;
  enum?: string[];
}

export function SecurityLabWorkflow({
  embedded = false,
  onComplete,
}: {
  embedded?: boolean;
  onComplete?: (payload: { tool: string; result: ToolExecutionResult; args: Record<string, string> }) => void;
} = {}): React.ReactElement {
  const user = useUser();
  const agentRunStorageKey = `blackonyx-security-agent-run:${user.user_id}`;
  const [tools, setTools] = useState<SecurityTool[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<SecurityTool | null>(null);
  const [args, setArgs] = useState<Record<string, string>>({});
  const [networkProfile, setNetworkProfile] = useState<"lab" | "public">("lab");
  const [labProfileId, setLabProfileId] = useState("");
  const [preview, setPreview] = useState<ToolPreview | null>(null);
  const [result, setResult] = useState<ToolExecutionResult | null>(null);
  const [running, setRunning] = useState(false);
  const [activeCategory, setActiveCategory] = useState<ToolCategory | "all">("all");
  const [agentMessage, setAgentMessage] = useState("");
  const [agentAnswer, setAgentAnswer] = useState("");
  const [agentRounds, setAgentRounds] = useState(0);
  const [agentToolCalls, setAgentToolCalls] = useState<Array<{ name: string; arguments?: Record<string, unknown>; call_id?: string }>>([]);
  const [agentToolResults, setAgentToolResults] = useState<NonNullable<AgentRunResponse["tool_results"]>>([]);
  const [agentRunId, setAgentRunId] = useState<string | null>(null);
  const [pendingAgentApproval, setPendingAgentApproval] = useState<ToolPreview | null>(null);
  const [agentRunStatus, setAgentRunStatus] = useState("");
  const [agentApprovalError, setAgentApprovalError] = useState("");
  const [clockNow, setClockNow] = useState(() => Date.now());
  const [allowPublicScan, setAllowPublicScan] = useState<boolean | null>(null);

  const applyAgentResult = useCallback((res: AgentRunResponse) => {
    setAgentAnswer(res.answer || "");
    setAgentRounds(res.rounds || 0);
    setAgentToolCalls(res.tool_calls || []);
    setAgentToolResults(res.tool_results || []);
    setAgentApprovalError("");
    if (res.status === "pending_approval" && res.run_id && res.pending_approval) {
      setAgentRunId(res.run_id);
      setPendingAgentApproval(res.pending_approval);
      setAgentRunStatus("pending_approval");
      try { sessionStorage.setItem(agentRunStorageKey, res.run_id); } catch { /* storage is optional */ }
    } else {
      setAgentRunId(null);
      setPendingAgentApproval(null);
      setAgentRunStatus(res.status || "completed");
      try { sessionStorage.removeItem(agentRunStorageKey); } catch { /* storage is optional */ }
    }
  }, [agentRunStorageKey]);

  useEffect(() => {
    const timer = window.setInterval(() => setClockNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    let active = true;
    let savedRunId = "";
    try { savedRunId = sessionStorage.getItem(agentRunStorageKey) || ""; } catch { /* storage is optional */ }
    if (!savedRunId) return () => { active = false; };
    getSecurityAgentRun(savedRunId).then((run) => {
      if (!active) return;
      setAgentRunStatus(run.status);
      if (run.status === "pending_approval" && run.pending_approval) {
        setAgentRunId(run.run_id);
        setPendingAgentApproval(run.pending_approval);
      } else {
        setAgentRunId(null);
        setPendingAgentApproval(null);
        try { sessionStorage.removeItem(agentRunStorageKey); } catch { /* storage is optional */ }
      }
    }).catch(() => {
      if (!active) return;
      setAgentRunStatus("unavailable");
    });
    return () => { active = false; };
  }, [agentRunStorageKey]);

  const loadTools = useCallback(async () => {
    setLoading(true);
    setError("");
    // The public-scan flag is informational; its failure must not hide the tools.
    void securityHealth()
      .then((health) => setAllowPublicScan(Boolean(health.allow_public_targets)))
      .catch(() => setAllowPublicScan(null));
    try {
      setTools(await listSecurityTools());
    } catch (e) {
      setError(`Failed to load tools: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadTools();
  }, [loadTools]);

  const filteredTools = useMemo(() => {
    if (activeCategory === "all") return tools;
    return tools.filter((t) => t.category === activeCategory);
  }, [tools, activeCategory]);

  const groupedTools = useMemo(() => {
    if (activeCategory !== "all") {
      return [{ label: CATEGORIES.find((c) => c.id === activeCategory)?.label || activeCategory, tools: filteredTools }];
    }
    return CATEGORIES.map((cat) => ({
      label: cat.label,
      tools: tools.filter((t) => t.category === cat.id),
    })).filter((g) => g.tools.length > 0);
  }, [tools, filteredTools, activeCategory]);

  const properties = useMemo(() => {
    if (!selected) return {} as Record<string, ArgSchema>;
    const params = selected.parameters as { properties?: Record<string, ArgSchema> } | undefined;
    return params?.properties || {};
  }, [selected]);

  const requiredArgs = useMemo(() => {
    if (!selected) return [] as string[];
    const params = selected.parameters as { required?: string[] } | undefined;
    return params?.required || [];
  }, [selected]);

  const needsApproval = selected ? !READ_TIERS.has(selected.tier) : false;
  const needsNetworkScope = selected !== null && (
    NETWORK_SCOPED_TOOLS.has(selected.name) || selected.name === "tcpdump_capture"
  );
  const unavailable = selected?.status !== "enabled";

  function selectTool(tool: SecurityTool): void {
    setSelected(tool);
    setArgs({});
    setNetworkProfile("lab");
    setLabProfileId("");
    setPreview(null);
    setResult(null);
    setError("");
    // Pre-fill defaults
    const props = (tool.parameters as { properties?: Record<string, ArgSchema> } | undefined)?.properties || {};
    const initial: Record<string, string> = {};
    for (const [key, schema] of Object.entries(props)) {
      if (schema.default !== undefined && schema.default !== null) {
        initial[key] = String(schema.default);
      }
    }
    setArgs(initial);
  }

  async function runTool(): Promise<void> {
    if (!selected) return;
    if (unavailable) {
      setError(`${selected.name} is ${selected.status || "unavailable"} on the security gateway.`);
      return;
    }
    if (needsNetworkScope && networkProfile === "lab" && !labProfileId.trim()) {
      setError("Enter the registered lab profile ID before previewing this operation.");
      return;
    }
    setRunning(true);
    setError("");
    setResult(null);
    try {
      const payload: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(args)) {
        if (value !== "" && value !== undefined) {
          const schema = properties[key];
          if (schema?.type === "integer" || schema?.type === "number") {
            payload[key] = Number(value);
          } else if (schema?.type === "boolean") {
            payload[key] = value === "true";
          } else {
            payload[key] = value;
          }
        }
      }
      const networkOptions = needsNetworkScope ? {
        network_profile: networkProfile,
        lab_profile_id: networkProfile === "lab" ? labProfileId : null,
      } : undefined;
      if (needsApproval && !preview) {
        setPreview(await previewSecurityTool(selected.name, payload, 120, networkOptions));
        return;
      }
      const approved = needsApproval && preview ? await approveSecurityTool(preview) : null;
      const res = await executeSecurityTool(selected.name, preview?.arguments || payload, {
        timeout: preview?.timeout ?? 120,
        session_id: preview?.session_id ?? "security-lab",
        approval_id: approved?.approval_id,
        network_profile: preview?.network_profile ?? networkOptions?.network_profile,
        destinations: preview?.destinations,
        ports: preview?.ports,
        lab_profile_id: preview?.lab_profile_id ?? networkOptions?.lab_profile_id,
        resolved_targets: preview?.resolved_targets,
      });
      setPreview(null);
      setResult(res);
    } catch (e) {
      setError(`Tool execution failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setRunning(false);
    }
  }

  function downloadCapture(): void {
    if (result?.format !== "pcap" || !result.content_base64) return;
    const bytes = Uint8Array.from(atob(result.content_base64), (value) => value.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes], { type: "application/vnd.tcpdump.pcap" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `black-onyx-capture-${result.job_id || "capture"}.pcap`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function runAgent(): Promise<void> {
    if (!agentMessage.trim()) return;
    setRunning(true);
    setError("");
    setAgentAnswer("");
    setAgentRounds(0);
    setAgentToolCalls([]);
    setAgentToolResults([]);
    setAgentApprovalError("");
    try {
      const res = await runSecurityAgent({
        message: agentMessage,
        max_rounds: 10,
        session_id: "security-lab",
      });
      applyAgentResult(res);
    } catch (e) {
      setError(`Agent run failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setRunning(false);
    }
  }

  async function decideAgentApproval(approve: boolean): Promise<void> {
    if (!agentRunId || !pendingAgentApproval) return;
    if (pendingAgentApproval.expires_at && clockNow / 1000 >= pendingAgentApproval.expires_at) {
      setAgentRunStatus("expired");
      setAgentApprovalError("This approval expired. Ask the agent again to create a new request.");
      return;
    }
    setRunning(true);
    setError("");
    setAgentApprovalError("");
    try {
      const action = approve
        ? { approval_id: (await approveSecurityTool(pendingAgentApproval)).approval_id }
        : { deny: true as const };
      applyAgentResult(await resumeSecurityAgentRun(agentRunId, action));
    } catch (e) {
      const message = `Could not ${approve ? "approve and resume" : "deny"} agent run: ${e instanceof Error ? e.message : String(e)}`;
      setError(message);
      setAgentApprovalError(message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className={`security-lab${embedded ? " embedded" : ""}`}>
      {!embedded && (
      <div className="section-head">
        <div>
          <span className="section-kicker">Security</span>
          <h1>Security Lab</h1>
          <p className="muted">
            Run defensive security tools — scanners, binary RE, crypto, Web3.
            Non-read tools require explicit approval.
          </p>
          {allowPublicScan !== null ? (
            <p className="muted">
              Non-lab public scanning:{" "}
              <strong>{allowPublicScan ? "enabled" : "disabled"}</strong> (deployment{" "}
              <code>ALLOW_PUBLIC_TARGETS</code>; lab profile gating still applies).
            </p>
          ) : null}
        </div>
        <div className="actions">
          <button className="button ghost compact" onClick={() => void loadTools()} disabled={loading}>
            {loading ? "Loading…" : "Refresh"}
          </button>
        </div>
      </div>
      )}
      {embedded && (
        <div className="actions">
          <button className="button ghost compact" onClick={() => void loadTools()} disabled={loading}>
            {loading ? "Loading…" : "Refresh tools"}
          </button>
        </div>
      )}

      {error && (
        <div className="banner error" role="alert">
          {error}
        </div>
      )}

      <div className="security-lab-filters">
        <button
          className={`button compact ${activeCategory === "all" ? "" : "ghost"}`}
          onClick={() => setActiveCategory("all")}
        >
          All ({tools.length})
        </button>
        {CATEGORIES.map((cat) => (
          <button
            key={cat.id}
            className={`button compact ${activeCategory === cat.id ? "" : "ghost"}`}
            onClick={() => setActiveCategory(cat.id)}
          >
            {cat.label} ({tools.filter((t) => t.category === cat.id).length})
          </button>
        ))}
      </div>

      <div className="security-tool-grid">
        {groupedTools.map((group) => (
          <div key={group.label} className="security-tool-group">
            <h3 className="security-tool-group-title">
              {group.label}
            </h3>
            {group.tools.map((tool) => (
              <button
                key={tool.name}
                className={`card security-tool-card ${selected?.name === tool.name ? "selected" : ""}`}
                onClick={() => selectTool(tool)}
              >
                <div className="security-tool-card-head">
                  <strong>{tool.name}</strong>
                  {tool.status !== "enabled" ? (
                    <span className="security-tier tone-off">{tool.status || "unavailable"}</span>
                  ) : (
                    <span className={tierBadgeClass(tool.tier)}>
                      {tool.tier}
                    </span>
                  )}
                </div>
                <p>
                  {tool.description.length > 80 ? tool.description.slice(0, 80) + "…" : tool.description}
                </p>
              </button>
            ))}
          </div>
        ))}
        {!loading && tools.length === 0 && (
          <p className="muted">No tools available. Ensure the security-gateway is running.</p>
        )}
      </div>

      {selected && (
        <section className="card security-lab-panel">
          <div className="security-lab-panel-head">
            <div>
              <h3>{selected.name}</h3>
              <p className="muted">{selected.description}</p>
            </div>
            {unavailable ? (
              <span className="security-tier tone-off">{selected.status || "unavailable"}</span>
            ) : (
              <span className={tierBadgeClass(selected.tier)}>{selected.tier}</span>
            )}
          </div>

          {unavailable && (
            <p className="alert">
              This capability is unavailable on the security gateway. Check its
              configuration and required adapter before trying again.
            </p>
          )}

          {needsNetworkScope && (
            <div className="security-argument-grid">
              <label>
                <span>Network profile</span>
                <select
                  value={networkProfile}
                  onChange={(event) => {
                    setNetworkProfile(event.target.value as "lab" | "public");
                    setPreview(null);
                  }}
                >
                  <option value="lab">Registered owned lab</option>
                  <option value="public">Approved public target</option>
                </select>
              </label>
              {networkProfile === "lab" && (
                <label>
                  <span>Registered lab profile ID</span>
                  <input
                    type="text"
                    value={labProfileId}
                    onChange={(event) => { setLabProfileId(event.target.value); setPreview(null); }}
                    placeholder="for example: anvil-lab"
                  />
                </label>
              )}
            </div>
          )}

          <div className="security-argument-grid">
            {Object.entries(properties).map(([key, schema]) => (
              <label key={key}>
                <span>
                  {key}
                  {requiredArgs.includes(key) && <strong className="required-marker"> *</strong>}
                  {schema.description && <span className="muted"> — {schema.description}</span>}
                </span>
                {schema.enum?.length ? (
                  <select
                    value={args[key] || String(schema.default ?? schema.enum[0])}
                    onChange={(e) => { setArgs({ ...args, [key]: e.target.value }); setPreview(null); }}
                  >
                    {schema.enum.map((option) => <option key={option} value={option}>{option}</option>)}
                  </select>
                ) : schema.type === "boolean" ? (
                  <select
                    value={args[key] || "false"}
                    onChange={(e) => { setArgs({ ...args, [key]: e.target.value }); setPreview(null); }}
                  >
                    <option value="false">false</option>
                    <option value="true">true</option>
                  </select>
                ) : (
                  <input
                    type={schema.type === "integer" || schema.type === "number" ? "number" : "text"}
                    maxLength={schema.maxLength}
                    value={args[key] || ""}
                    onChange={(e) => { setArgs({ ...args, [key]: e.target.value }); setPreview(null); }}
                    placeholder={schema.default !== undefined ? String(schema.default) : ""}
                  />
                )}
              </label>
            ))}
          </div>

          {preview && (
            <div className="security-approval">
              <strong>Review {preview.tier} operation</strong>
              <pre className="security-output">{JSON.stringify({
                tool: preview.tool, arguments: preview.arguments,
                session_id: preview.session_id, timeout: preview.timeout,
                network_profile: preview.network_profile,
                lab_profile_id: preview.lab_profile_id,
                destinations: preview.destinations,
                ports: preview.ports,
                resolved_targets: preview.resolved_targets,
              }, null, 2)}</pre>
              <p className="muted">Approval is single use and expires after five minutes.</p>
            </div>
          )}

          <button
            onClick={() => void runTool()}
            disabled={running || unavailable}
            className="button security-run-button"
          >
            {unavailable ? "Unavailable" : running ? "Running…" : preview ? "Approve and run" : needsApproval ? "Preview operation" : "Run Tool"}
          </button>
        </section>
      )}

      {result && (
        <section className="card security-lab-panel">
          <h3>Result</h3>
          <div className="security-result-meta">
            <span className={tierBadgeClass(result.status === "success" ? "read" : "destructive")}>
              {result.status}
            </span>
            {result.returncode !== undefined && <span>exit: {result.returncode}</span>}
            {result.duration_s !== undefined && <span>{result.duration_s.toFixed(2)}s</span>}
          </div>
          {result.format === "pcap" && result.content_base64 && (
            <div className="security-result-capture">
              <p className="muted">
                {result.captured_bytes ?? 0} bytes captured
                {result.sha256 ? ` · SHA-256 ${result.sha256}` : ""}
              </p>
              <button className="button compact" onClick={downloadCapture}>Download PCAP</button>
            </div>
          )}
          <pre className="security-output">
            {result.error || result.output || (result.format === "pcap" ? "Capture is ready to download." : "(no output)")}
          </pre>
          {embedded && onComplete && selected ? (
            <div className="actions">
              <button type="button" className="button compact" onClick={() => onComplete({ tool: selected.name, result, args })}>
                Send result to chat
              </button>
            </div>
          ) : null}
        </section>
      )}

      <section className="card security-lab-panel">
        <div className="section-head">
          <div>
            <span className="section-kicker">AI agent</span>
            <h3>Security Agent</h3>
            <p className="muted security-agent-description">
              Ask the security agent to chain enabled tool calls across multiple rounds. Live scanners pause for approval; privileged adapters stay out of autonomous runs.
            </p>
          </div>
          {agentRounds > 0 && (
            <span className="security-tier tone-ok">
              {agentRounds} round{agentRounds === 1 ? "" : "s"}
            </span>
          )}
        </div>
        <div className="security-agent-prompt">
          <input
            type="text"
            value={agentMessage}
            onChange={(e) => setAgentMessage(e.target.value)}
            placeholder="e.g. Extract strings from sample.bin and summarize"
            onKeyDown={(e) => {
              if (e.key === "Enter" && !running) void runAgent();
            }}
          />
          <button className="button primary" onClick={() => void runAgent()} disabled={running || !agentMessage.trim()}>
            {running ? "Running…" : "Ask"}
          </button>
        </div>

        {running && (
          <div className="security-agent-running">
            <span className="chat-streaming-indicator"><span></span><span></span><span></span></span>
            <small className="muted">Agent is reasoning and calling tools…</small>
          </div>
        )}

        {pendingAgentApproval && agentRunId && (
          <div className="security-approval" role="region" aria-label="Pending agent tool approval">
            <strong>Review pending {pendingAgentApproval.tier} operation</strong>
            <pre className="security-output">{JSON.stringify({
              tool: pendingAgentApproval.tool,
              arguments: pendingAgentApproval.arguments,
              session_id: pendingAgentApproval.session_id,
              timeout: pendingAgentApproval.timeout,
              network_profile: pendingAgentApproval.network_profile,
              destinations: pendingAgentApproval.destinations,
              ports: pendingAgentApproval.ports,
            }, null, 2)}</pre>
            <p className="muted">
              This request is bound to the preview and expires with the paused run.
              {pendingAgentApproval.expires_at ? ` Expires at ${new Date(pendingAgentApproval.expires_at * 1000).toLocaleTimeString()}.` : ""}
            </p>
            {(agentApprovalError || Boolean(pendingAgentApproval.expires_at && clockNow / 1000 >= pendingAgentApproval.expires_at)) && (
              <p className="banner error" role="alert">
                {agentApprovalError || "This approval expired. Ask the agent again to create a new request."}
              </p>
            )}
            <div className="actions">
              <button
                className="button primary"
                onClick={() => void decideAgentApproval(true)}
                disabled={running || Boolean(pendingAgentApproval.expires_at && clockNow / 1000 >= pendingAgentApproval.expires_at)}
                title={pendingAgentApproval.expires_at && clockNow / 1000 >= pendingAgentApproval.expires_at ? "Approval expired" : undefined}
              >
                {running ? "Resuming…" : "Approve and resume"}
              </button>
              <button
                className="button secondary"
                onClick={() => void decideAgentApproval(false)}
                disabled={running || Boolean(pendingAgentApproval.expires_at && clockNow / 1000 >= pendingAgentApproval.expires_at)}
              >
                Deny
              </button>
            </div>
          </div>
        )}
        {!pendingAgentApproval && agentRunStatus && agentRunStatus !== "completed" && (
          <p className="muted" role="status">Agent run status: {agentRunStatus.replaceAll("_", " ")}.</p>
        )}

        {agentToolCalls.length > 0 && (
          <div className="chat-tool-cards security-agent-tools">
            <h4>
              Tool calls ({agentToolCalls.length})
            </h4>
            {agentToolCalls.map((call, index) => {
              const row = agentToolResults[index];
              const nested = row?.result && typeof row.result === "object"
                ? row.result as Record<string, unknown>
                : {};
              const status = String(row?.status || nested.status || (row?.error || nested.error ? "error" : ""));
              const output = String(row?.output || nested.output || row?.summary || nested.summary || "");
              const error = String(row?.error || nested.error || "");
              const tone = status === "error" || error ? "error" : status ? "ok" : "";
              return (
                <div key={`agent-tool-${index}`} className={`chat-tool-card ${tone}`}>
                  <div className="chat-tool-card-head">
                    <span className="chat-tool-icon">⚙</span>
                    <strong>{call.name || "tool"}</strong>
                    {status ? (
                      <span className={`chat-tool-status ${status}`}>{status}</span>
                    ) : (
                      <span className="chat-tool-status">queued</span>
                    )}
                  </div>
                  {call.arguments && Object.keys(call.arguments).length > 0 && (
                    <pre className="chat-tool-args">{JSON.stringify(call.arguments, null, 2)}</pre>
                  )}
                  {output && <pre className="chat-tool-summary">{output.slice(0, 8000)}</pre>}
                  {error && <pre className="chat-tool-summary security-error-text">{error}</pre>}
                </div>
              );
            })}
          </div>
        )}

        {agentAnswer && (
          <div className="security-agent-answer">
            {agentAnswer}
          </div>
        )}
        {!agentAnswer && agentToolCalls.length > 0 && agentRunStatus && agentRunStatus !== "pending_approval" && (
          <p className="muted" role="status">The agent did not write a summary. Tool output is above.</p>
        )}
      </section>
    </div>
  );
}

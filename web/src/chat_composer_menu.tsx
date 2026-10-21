import React, { useEffect, useMemo, useState } from "react";
import { api } from "./api";
import {
  approveSecurityTool,
  executeSecurityTool,
  previewSecurityTool,
  type ToolExecutionResult,
  type ToolPreview,
} from "./detection/api/security_client";

export type McpToolRow = {
  name: string;
  description: string;
  group: string;
  enabled: boolean;
  allow_private: boolean;
  allow_public: boolean;
  network_profile: "lab" | "public" | "offline";
  timeout_seconds: number;
};

export type McpToolGroup = {
  id: string;
  label: string;
  tools: McpToolRow[];
};

type CatalogResponse = {
  enabled: boolean;
  lab_profile_id: string;
  allowed_targets?: string[];
  groups: McpToolGroup[];
};

const EXECUTION_CONTROL_KEYS = new Set([
  "approval_id",
  "network_profile",
  "lab_profile_id",
  "destinations",
  "resolved_targets",
  "session_id",
  "request_timeout",
]);

export function stripExecutionControlArgs(args: Record<string, unknown>): Record<string, unknown> {
  const cleaned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args)) {
    if (!EXECUTION_CONTROL_KEYS.has(key)) cleaned[key] = value;
  }
  return cleaned;
}

function isPrivateIPv4(host: string): boolean {
  const parts = host.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [a, b] = parts;
  if (a === 10 || a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

export function networkProfileForHost(raw: string): "lab" | "public" {
  let host = raw.trim();
  try {
    if (host.includes("://")) host = new URL(host).hostname;
  } catch {
    /* keep the raw host */
  }
  host = host.replace(/^\[|\]$/g, "").replace(/:\d+$/, "");
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) && isPrivateIPv4(host)) return "lab";
  return "public";
}

function hostFromToolArgs(args: Record<string, unknown>): string {
  return String(args.target ?? args.url ?? args.host ?? args.domain ?? "").trim();
}

function networkLabel(profile: McpToolRow["network_profile"]): string {
  switch (profile) {
    case "lab":
      return "lab";
    case "public":
      return "public";
    case "offline":
      return "offline";
    default: {
      const exhaustive: never = profile;
      return exhaustive;
    }
  }
}

export function ChatComposerMenu({
  mcpAvailable,
  selected,
  onChangeSelected,
  onAttach,
  onOpenSystem,
  disabled = false,
}: {
  mcpAvailable: boolean;
  selected: string[];
  onChangeSelected: (names: string[]) => void;
  onAttach: (files: File[]) => void;
  onOpenSystem: () => void;
  disabled?: boolean;
}): React.ReactElement {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  const [openGroup, setOpenGroup] = useState<string | null>(null);

  useEffect(() => {
    if (!mcpAvailable) return;
    let active = true;
    api<CatalogResponse>("/mcp/tools").then((value) => {
      if (active) setCatalog(value);
    }).catch(() => {
      if (active) setCatalog({ enabled: false, lab_profile_id: "anvil", groups: [] });
    });
    return () => { active = false; };
  }, [mcpAvailable]);

  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const enabledTools = (catalog?.groups || []).flatMap((group) => group.tools.filter((tool) => tool.enabled));
  const count = `${selected.length}/${enabledTools.length || 0}`;

  function toggle(name: string, on: boolean): void {
    if (disabled) return;
    if (on) onChangeSelected([...selectedSet, name].filter((item, index, list) => list.indexOf(item) === index));
    else onChangeSelected(selected.filter((item) => item !== name));
  }

  return (
    <details className="composer-plus">
      <summary className="composer-plus-toggle" title="Add files, system message, or tools">+</summary>
      <div className="composer-plus-menu" role="menu">
        <label className="composer-plus-item">
          Add files
          <input type="file" accept="image/*" multiple disabled={disabled} onChange={(event) => onAttach(Array.from(event.target.files || []).slice(0, 5))}/>
        </label>
        <button type="button" className="composer-plus-item" disabled={disabled} onClick={onOpenSystem}>System Message</button>
        <details className="composer-plus-submenu">
          <summary>Tools <span className="composer-plus-count">{count}</span></summary>
          {mcpAvailable && catalog ? (
            <p className="muted small">
              {(catalog.allowed_targets || []).length
                ? `Chat allowlist: ${(catalog.allowed_targets || []).join(", ")}`
                : "No chat allowlist. Off-list scanners need Preview → Approve."}
            </p>
          ) : null}
          {!mcpAvailable ? <p className="muted small">Enable MCP tools in Settings.</p> : (catalog?.groups || []).map((group) => (
            <details key={group.id} className="composer-plus-submenu" open={openGroup === group.id} onToggle={(event) => {
              if ((event.currentTarget as HTMLDetailsElement).open) setOpenGroup(group.id);
              else if (openGroup === group.id) setOpenGroup(null);
            }}>
              <summary>{group.label} {group.tools.filter((tool) => selectedSet.has(tool.name)).length}/{group.tools.filter((tool) => tool.enabled).length}</summary>
              <ul className="composer-tool-list">
                {group.tools.map((tool) => (
                  <li key={tool.name}>
                    <label className={!tool.enabled || disabled ? "disabled" : ""} title={tool.enabled ? tool.description : "Disabled in Settings → MCP tools"}>
                      <input
                        type="checkbox"
                        checked={selectedSet.has(tool.name)}
                        disabled={!tool.enabled || disabled}
                        onChange={(event) => toggle(tool.name, event.target.checked)}
                      />
                      <span>{tool.name}</span>
                      <small>{networkLabel(tool.network_profile)}</small>
                    </label>
                  </li>
                ))}
              </ul>
            </details>
          ))}
        </details>
      </div>
    </details>
  );
}

function previewPins(preview: ToolPreview): Array<[string, string]> {
  const resolved = preview.resolved_targets || {};
  const pins = Object.entries(resolved).map(([host, ips]) => `${host} → ${(ips || []).join(", ")}`);
  return [
    ["Profile", preview.network_profile + (preview.lab_profile_id ? ` (${preview.lab_profile_id})` : "")],
    ["Destinations", (preview.destinations || []).join(", ") || "—"],
    ["Ports", (preview.ports || []).map(String).join(", ") || "—"],
    ["Resolved", pins.join("; ") || "—"],
    ["Preview hash", preview.preview_hash],
  ];
}

export function formatSecurityEvidence(
  toolName: string,
  result: ToolExecutionResult,
  args?: Record<string, unknown>,
): string {
  const body = String(result.error || result.output || JSON.stringify(result)).slice(0, 8000);
  const cleaned = args ? stripExecutionControlArgs(args) : {};
  const argLine = Object.keys(cleaned).length ? `args: ${JSON.stringify(cleaned)}\n` : "";
  return (
    `Tool result for ${toolName} (untrusted evidence):\n` +
    argLine +
    `status: ${result.status}\n` +
    `${body}\n\n` +
    "Continue from this evidence. You may call selected scanners again with different ports or scan=version|connect|scripts. Do not invent approval_id."
  );
}

export function ChatToolApproval({
  toolName,
  args,
  labProfileId,
  onComplete,
}: {
  toolName: string;
  args: Record<string, unknown>;
  labProfileId: string;
  onComplete?: (result: ToolExecutionResult) => void;
}): React.ReactElement | null {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [preview, setPreview] = useState<ToolPreview | null>(null);
  const [result, setResult] = useState<ToolExecutionResult | null>(null);

  if (!toolName.startsWith("sec_")) return null;
  const shortName = toolName.slice(4);
  const toolArgs = stripExecutionControlArgs(args);

  async function runPreview(): Promise<void> {
    setBusy(true);
    setError("");
    try {
      const host = hostFromToolArgs(toolArgs);
      const networkProfile = host ? networkProfileForHost(host) : "lab";
      setPreview(await previewSecurityTool(shortName, toolArgs, 120, {
        network_profile: networkProfile,
        lab_profile_id: networkProfile === "lab" ? labProfileId : null,
      }));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function runApprove(): Promise<void> {
    if (!preview) return;
    setBusy(true);
    setError("");
    try {
      const approved = await approveSecurityTool(preview);
      const executed = await executeSecurityTool(shortName, preview.arguments, {
        timeout: preview.timeout,
        session_id: preview.session_id,
        approval_id: approved.approval_id,
        network_profile: preview.network_profile,
        destinations: preview.destinations,
        ports: preview.ports,
        lab_profile_id: preview.lab_profile_id,
        resolved_targets: preview.resolved_targets,
      });
      setResult(executed);
      setPreview(null);
      onComplete?.(executed);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="chat-tool-approval">
      {error ? <p className="alert error">{error}</p> : null}
      {result ? <pre className="chat-tool-summary">{JSON.stringify(result, null, 2).slice(0, 1200)}</pre> : null}
      {!result && !preview ? <button type="button" className="ghost compact" disabled={busy} onClick={() => void runPreview()}>{busy ? "Previewing…" : "Preview"}</button> : null}
      {preview ? (
        <div className="chat-tool-preview-block">
          <dl className="chat-tool-preview">
            {previewPins(preview).map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
          <div className="actions">
            <button type="button" className="compact" disabled={busy} onClick={() => void runApprove()}>{busy ? "Approving…" : "Approve"}</button>
            <button type="button" className="ghost compact" disabled={busy} onClick={() => setPreview(null)}>Cancel</button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

/** API client for /api/v1/security/* security tooling BFF routes.
 *
 * All calls go through the Black Onyx BFF (same-origin, session cookies).
 * The browser never talks to the security-gateway directly.
 */

export interface SecurityTool {
  name: string;
  description: string;
  category: string;
  tier: string;
  /** enabled, disabled by configuration, or unavailable until its adapter is ready. */
  status?: string;
  /** JSON Schema for the tool arguments. Optional because an older gateway
   *  omitted it from the capability matrix, which left the argument form
   *  empty for every tool. */
  parameters?: Record<string, unknown>;
}

export interface AgentRunRequest {
  message: string;
  max_rounds?: number;
  approved_tools?: string[];
  system_prompt?: string;
  session_id?: string;
}

export interface AgentRunResponse {
  answer: string;
  rounds: number;
  status?: string;
  run_id?: string;
  pending_approval?: ToolPreview & { call_id?: string };
  tool_calls?: Array<{ name: string; arguments?: Record<string, unknown>; call_id?: string }>;
  tool_results?: Array<{
    name: string;
    status?: string;
    output?: string;
    error?: string;
    summary?: string;
    result?: Record<string, unknown>;
  }>;
}

export interface ToolExecutionResult {
  status: string;
  output?: string;
  returncode?: number;
  duration_s?: number;
  error?: string;
  format?: string;
  content_base64?: string;
  captured_bytes?: number;
  sha256?: string;
  job_id?: string;
}

export interface ToolPreview {
  tool: string;
  tier: string;
  arguments: Record<string, unknown>;
  session_id: string;
  timeout: number;
  network_profile: string;
  destinations: string[];
  ports?: number[];
  lab_profile_id?: string | null;
  resolved_targets?: Record<string, string[]>;
  preview_hash: string;
  expires_at?: number;
}

export interface AgentRunStatus {
  run_id: string;
  status: string;
  pending_tool?: string;
  pending_approval?: ToolPreview;
  expires_at?: number;
}

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)blackonyx_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, {
    credentials: "same-origin",
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken(),
      ...(init?.headers || {}),
    },
  });
  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new Error(`Security API ${resp.status}: ${body.slice(0, 200)}`);
  }
  return resp.json() as Promise<T>;
}

export async function listSecurityTools(): Promise<SecurityTool[]> {
  const data = await fetchJson<{ tools: SecurityTool[] }>("/api/v1/security/capabilities");
  return data.tools || [];
}

export async function runSecurityAgent(req: AgentRunRequest): Promise<AgentRunResponse> {
  return fetchJson<AgentRunResponse>("/api/v1/security/agent/run", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function getSecurityAgentRun(runId: string): Promise<AgentRunStatus> {
  return fetchJson<AgentRunStatus>(`/api/v1/security/agent/runs/${encodeURIComponent(runId)}`);
}

export async function resumeSecurityAgentRun(
  runId: string,
  action: { approval_id: string } | { deny: true },
): Promise<AgentRunResponse> {
  return fetchJson<AgentRunResponse>(`/api/v1/security/agent/runs/${encodeURIComponent(runId)}/resume`, {
    method: "POST",
    body: JSON.stringify(action),
  });
}

export async function executeSecurityTool(
  toolName: string,
  arguments_: Record<string, unknown>,
  options?: {
    timeout?: number;
    session_id?: string;
    approval_id?: string;
    network_profile?: string;
    destinations?: string[];
    ports?: number[];
    lab_profile_id?: string | null;
    resolved_targets?: Record<string, string[]>;
  },
): Promise<ToolExecutionResult> {
  return fetchJson<ToolExecutionResult>(`/api/v1/security/tools/${encodeURIComponent(toolName)}`, {
    method: "POST",
    body: JSON.stringify({
      arguments: arguments_,
      timeout: options?.timeout ?? 60,
      session_id: options?.session_id,
      approval_id: options?.approval_id,
      network_profile: options?.network_profile,
      destinations: options?.destinations,
      ports: options?.ports,
      lab_profile_id: options?.lab_profile_id,
      resolved_targets: options?.resolved_targets,
    }),
  });
}

export async function previewSecurityTool(
  toolName: string,
  arguments_: Record<string, unknown>,
  timeout = 120,
  network?: { network_profile: string; lab_profile_id?: string | null },
): Promise<ToolPreview> {
  return fetchJson<ToolPreview>(`/api/v1/security/tools/${encodeURIComponent(toolName)}/preview`, {
    method: "POST",
    body: JSON.stringify({
      arguments: arguments_, timeout, session_id: "security-lab",
      ...network,
    }),
  });
}

export async function approveSecurityTool(preview: ToolPreview): Promise<{ approval_id: string }> {
  return fetchJson<{ approval_id: string }>(`/api/v1/security/tools/${encodeURIComponent(preview.tool)}/approve`, {
    method: "POST",
    body: JSON.stringify({
      arguments: preview.arguments,
      session_id: preview.session_id,
      timeout: preview.timeout,
      network_profile: preview.network_profile,
      destinations: preview.destinations ?? [],
      ports: preview.ports ?? [],
      lab_profile_id: preview.lab_profile_id ?? null,
      resolved_targets: preview.resolved_targets ?? {},
      preview_hash: preview.preview_hash,
    }),
  });
}

export async function securityHealth(): Promise<{
  status: string;
  gateway_configured: boolean;
  allow_public_targets?: boolean;
}> {
  return fetchJson("/api/v1/security/health");
}

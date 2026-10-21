export type Role = "admin" | "analyst" | "viewer";
export interface User {
  user_id: string;
  email: string;
  display_name: string;
  role: Role;
  mfa_enabled?: boolean;
}

let authEpoch = 0;
export function advanceAuthEpoch(): void { authEpoch += 1; }

class StaleSessionResponse extends Error {
  constructor() { super("The authenticated session changed while this request was in flight."); }
}

function cookie(name: string): string {
  const item = document.cookie.split("; ").find((value) => value.startsWith(`${name}=`));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : "";
}

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

/** FastAPI may return detail as a string, problem title, or validation-error array. */
export function formatApiDetail(detail: unknown, fallback: string): string {
  if (detail == null || detail === "") return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const parts = detail.map((item) => {
      if (typeof item === "string") return item;
      if (item && typeof item === "object") {
        const row = item as { msg?: unknown; message?: unknown; loc?: unknown[] };
        const msg = typeof row.msg === "string" ? row.msg
          : typeof row.message === "string" ? row.message
          : "";
        const loc = Array.isArray(row.loc)
          ? row.loc.filter((part) => part !== "body" && part !== "query").map(String).join(".")
          : "";
        if (msg && loc) return `${loc}: ${msg}`;
        if (msg) return msg;
      }
      try { return JSON.stringify(item); } catch { return ""; }
    }).filter(Boolean);
    return parts.join("; ") || fallback;
  }
  if (typeof detail === "object") {
    const row = detail as { message?: unknown; msg?: unknown; title?: unknown };
    if (typeof row.message === "string") return row.message;
    if (typeof row.msg === "string") return row.msg;
    if (typeof row.title === "string") return row.title;
    try { return JSON.stringify(detail); } catch { return fallback; }
  }
  return String(detail);
}

function errorMessageFromBody(body: Record<string, unknown>, fallback: string): string {
  const fromDetail = formatApiDetail(body.detail, "");
  if (fromDetail) return fromDetail;
  return formatApiDetail(body.title, fallback);
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const requestEpoch = authEpoch;
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD"].includes((init.method || "GET").toUpperCase())) {
    headers.set("X-CSRF-Token", cookie("blackonyx_csrf"));
  }
  const response = await fetch(`/api/v1${path}`, { ...init, headers, credentials: "same-origin" });
  if (requestEpoch !== authEpoch) throw new StaleSessionResponse();
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as Record<string, unknown>;
    if (requestEpoch !== authEpoch) throw new StaleSessionResponse();
    // Failed login/register is unauthenticated by design do not treat it as an expired session.
    const authBootstrap = path.startsWith("/auth/login") || path.startsWith("/auth/register")
      || path.startsWith("/auth/password-reset");
    if (response.status === 401 && !authBootstrap) {
      window.dispatchEvent(new Event("blackonyx:session-expired"));
    }
    throw new ApiError(
      response.status,
      errorMessageFromBody(body, `Request failed (${response.status})`),
    );
  }
  if (response.status === 204) return undefined as T;
  const value = await response.json() as T;
  if (requestEpoch !== authEpoch) throw new StaleSessionResponse();
  return value;
}

export type ChatStreamEvent = "session" | "token" | "reasoning" | "source" | "tool" | "error" | "done";

export async function downloadCollectorPackage(osName: string): Promise<void> {
  const requestEpoch = authEpoch;
  const response = await fetch(`/api/v1/collectors/${encodeURIComponent(osName)}/download`, {
    credentials: "same-origin",
  });
  if (requestEpoch !== authEpoch) throw new StaleSessionResponse();
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as Record<string, unknown>;
    if (response.status === 401) window.dispatchEvent(new Event("blackonyx:session-expired"));
    throw new ApiError(response.status, errorMessageFromBody(body, `Download failed (${response.status})`));
  }
  const blob = await response.blob();
  if (requestEpoch !== authEpoch) throw new StaleSessionResponse();
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = /filename="?([^"]+)"?/i.exec(disposition);
  const filename = match?.[1] || `black-onyx-collector-${osName}.zip`;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

/** SSE field value: strip at most one space after the colon so leading token spaces stay intact. */
function sseDataPayload(line: string): string {
  const value = line.slice("data:".length);
  return value.startsWith(" ") ? value.slice(1) : value;
}

export async function streamChat(
  payload: unknown,
  onEvent: (event: ChatStreamEvent, data: string) => void,
  signal?: AbortSignal,
): Promise<void> {
  const requestEpoch = authEpoch;
  const response = await fetch("/api/v1/chat/stream", {
    method: "POST",
    credentials: "same-origin",
    signal,
    headers: { "Content-Type": "application/json", "X-CSRF-Token": cookie("blackonyx_csrf") },
    body: JSON.stringify(payload),
  });
  if (requestEpoch !== authEpoch) throw new StaleSessionResponse();
  if (!response.ok || !response.body) {
    const body = await response.json().catch(() => ({})) as Record<string, unknown>;
    if (response.status === 401) window.dispatchEvent(new Event("blackonyx:session-expired"));
    throw new ApiError(response.status, errorMessageFromBody(body, "Chat stream failed"));
  }
  const reader = response.body.getReader(); const decoder = new TextDecoder(); let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (requestEpoch !== authEpoch) {
      await reader.cancel();
      throw new StaleSessionResponse();
    }
    buffer += decoder.decode(value, { stream: !done });
    const records = buffer.split(/\r?\n\r?\n/); buffer = records.pop() || "";
    for (const record of records) {
      let event = "message"; const data: string[] = [];
      for (const line of record.split(/\r?\n/)) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        if (line.startsWith("data:")) data.push(sseDataPayload(line));
      }
      onEvent(event as ChatStreamEvent, data.join("\n"));
    }
    if (done) break;
  }
}

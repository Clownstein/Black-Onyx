export type Role = "admin" | "analyst" | "viewer";
export interface User { user_id: string; email: string; display_name: string; role: Role }

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
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD"].includes((init.method || "GET").toUpperCase())) {
    headers.set("X-CSRF-Token", cookie("blackonyx_csrf"));
  }
  const response = await fetch(`/api/v1${path}`, { ...init, headers, credentials: "same-origin" });
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as Record<string, unknown>;
    // Failed login/register is unauthenticated by design — do not treat it as an expired session.
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
  return response.json() as Promise<T>;
}

export async function streamChat(
  payload: unknown,
  onEvent: (event: string, data: string) => void,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch("/api/v1/chat/stream", {
    method: "POST",
    credentials: "same-origin",
    signal,
    headers: { "Content-Type": "application/json", "X-CSRF-Token": cookie("blackonyx_csrf") },
    body: JSON.stringify(payload),
  });
  if (!response.ok || !response.body) {
    const body = await response.json().catch(() => ({})) as Record<string, unknown>;
    if (response.status === 401) window.dispatchEvent(new Event("blackonyx:session-expired"));
    throw new ApiError(response.status, errorMessageFromBody(body, "Chat stream failed"));
  }
  const reader = response.body.getReader(); const decoder = new TextDecoder(); let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value, { stream: !done });
    const records = buffer.split(/\r?\n\r?\n/); buffer = records.pop() || "";
    for (const record of records) {
      let event = "message"; const data: string[] = [];
      for (const line of record.split(/\r?\n/)) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
      }
      onEvent(event, data.join("\n"));
    }
    if (done) break;
  }
}

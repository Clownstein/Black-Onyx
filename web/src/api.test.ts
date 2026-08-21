import { afterEach, describe, expect, it, vi } from "vitest";
import { api, formatApiDetail, streamChat } from "./api";

afterEach(() => {
  vi.restoreAllMocks();
  document.cookie = "blackonyx_csrf=; Max-Age=0; Path=/";
});

describe("typed API client", () => {
  it("adds the CSRF token to unsafe same-origin requests", async () => {
    document.cookie = "blackonyx_csrf=test-token; Path=/";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await api("/sessions", { method: "POST", body: JSON.stringify({ title: "Test" }) });

    const [, init] = fetchMock.mock.calls[0];
    expect(new Headers(init?.headers).get("X-CSRF-Token")).toBe("test-token");
    expect(init?.credentials).toBe("same-origin");
  });

  it("normalizes problem details and announces expired sessions", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ title: "Authentication required" }), {
        status: 401,
        headers: { "Content-Type": "application/problem+json" },
      }),
    );
    const expired = vi.fn();
    window.addEventListener("blackonyx:session-expired", expired);

    await expect(api("/info")).rejects.toEqual(
      expect.objectContaining({ status: 401, message: "Authentication required" }),
    );
    expect(expired).toHaveBeenCalledOnce();
  });

  it("formats FastAPI validation-error detail arrays", () => {
    expect(formatApiDetail([
      { loc: ["body", "email"], msg: "value is not a valid email address", type: "value_error" },
      { loc: ["body", "password"], msg: "Field required", type: "missing" },
    ], "fallback")).toBe("email: value is not a valid email address; password: Field required");
  });

  it("surfaces validation errors from failed login without session-expired", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({
        detail: [{ loc: ["body", "email"], msg: "value is not a valid email address", type: "value_error" }],
      }), { status: 422, headers: { "Content-Type": "application/json" } }),
    );
    const expired = vi.fn();
    window.addEventListener("blackonyx:session-expired", expired);

    await expect(api("/auth/login", { method: "POST", body: JSON.stringify({}) })).rejects.toEqual(
      expect.objectContaining({ status: 422, message: "email: value is not a valid email address" }),
    );
    expect(expired).not.toHaveBeenCalled();
  });

  it("parses streamed event and token records", async () => {
    const body = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode("event: session\ndata: {\"session_id\":\"abc\"}\n\nevent: token\ndata: hello\n\n")); controller.close(); } });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(body, { status: 200 }));
    const events: [string, string][] = [];
    await streamChat({ message: "hello" }, (event, data) => events.push([event, data]));
    expect(events).toEqual([["session", '{"session_id":"abc"}'], ["token", "hello"]]);
  });
});

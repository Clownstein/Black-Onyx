import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./client";

afterEach(() => {
  vi.restoreAllMocks();
  document.cookie = "blackonyx_csrf=; Max-Age=0; Path=/";
});

describe("detection API client", () => {
  it("announces expired sessions on 401 like the TIP client", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ title: "Authentication required" }), {
        status: 401,
        headers: { "Content-Type": "application/problem+json" },
      }),
    );
    const expired = vi.fn();
    window.addEventListener("blackonyx:session-expired", expired);

    await expect(api.listPendingResponses()).rejects.toThrow(/API 401/);
    expect(expired).toHaveBeenCalledOnce();

    window.removeEventListener("blackonyx:session-expired", expired);
  });

  it("adds the CSRF token to unsafe detection requests", async () => {
    document.cookie = "blackonyx_csrf=det-token; Path=/";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(undefined, { status: 204 }),
    );

    await api.approveResponse("req-1", "analyst@example.com");

    const [, init] = fetchMock.mock.calls[0];
    expect((init?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("det-token");
    expect(init?.credentials).toBe("same-origin");
  });

  it("loads reconciliation through the same-origin BFF without browser credentials", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: [{ request_id: "resp-1", status: "execution_uncertain" }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const rows = await api.listResponseReconciliation();
    expect(rows[0].status).toBe("execution_uncertain");
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/api/v1/detection/response/api/v1/response/reconciliation");
    expect(init?.credentials).toBe("same-origin");
    expect((init?.headers as Record<string, string>)["X-Approver-Key"]).toBeUndefined();
  });

  it("sends the chosen asset with asset-scoped response requests and no asset otherwise", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async () => (
      new Response(JSON.stringify({ request_id: "resp-1", status: "pending" }), { status: 200 })
    ));
    await api.createResponseRequest({
      incident_id: "inc-1", playbook_id: "isolate-host", asset_id: "wazuh:007", dry_run: true,
    });
    await api.createResponseRequest({ incident_id: "inc-1", playbook_id: "block-c2", dry_run: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [isolate, block] = fetchMock.mock.calls.map(([url, init]) => ({
      url: String(url), payload: JSON.parse(String(init?.body)).payload,
    }));
    expect(isolate.url).toContain("/api/v1/detection/response/api/v1/response/request");
    expect(isolate.payload).toEqual({ response_mode: "suggest_only", asset_id: "wazuh:007" });
    expect(block.payload).toEqual({ response_mode: "suggest_only" });
  });

  it("marks asset-scoped playbooks from the orchestrator catalog", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      items: [{ id: "isolate-host", name: "Isolate host", asset_scoped: true }, { id: "block-c2", name: "Block C2" }],
    }), { status: 200 }));
    const books = await api.listPlaybooks();
    expect(books.map((b) => [b.playbook_id, b.asset_scoped])).toEqual([["isolate-host", true], ["block-c2", false]]);
  });

  it("scans stale responses with a CSRF-protected BFF mutation", async () => {
    document.cookie = "blackonyx_csrf=reconcile-token; Path=/";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: [] }), { status: 200 }),
    );
    await api.scanResponseReconciliation();
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/api/v1/detection/response/api/v1/response/reconciliation/scan");
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("reconcile-token");
    expect((init?.headers as Record<string, string>)["X-Approver-Key"]).toBeUndefined();
  });
});

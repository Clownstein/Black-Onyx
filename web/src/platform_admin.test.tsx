import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";
import { DeploymentPanel, SectionSource, SettingsInventoryPanel } from "./workflows_platform_admin";

const draft = {
  revision_id: "rev-1",
  target: "compose",
  parent_revision_id: null,
  status: "draft",
  changed_keys: ["env.BLACK_ONYX_DETECTION_TENANT"],
  rendered_preview: "# managed.env\nBLACK_ONYX_DETECTION_TENANT=acme\nSECURITY_GATEWAY_KEY=<set>",
  preview_digest: "d".repeat(64),
  exception_expires_at: null,
  created_by: "admin-1",
  approved_by: null,
  applied_at: null,
  health: null,
  error: null,
  created_at: "2026-09-27T00:00:00Z",
};

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return {
    ...actual,
    api: vi.fn(async (path: string) => {
      if (path === "/admin/settings/inventory")
        return {
          total: 2,
          production: false,
          expired_exceptions: [],
          items: [
            { key: "chunking.chunk_size", section: "chunking", kind: "application", type: "int", desired: 900, effective: 900, default: 512, source: "runtime", consumers: ["black-onyx ingestion pipeline"], editable: true, restart_required: false, secret: false, validation: {}, description: "" },
            { key: "SECURITY_GATEWAY_KEY", section: "security tools", kind: "deployment", type: "string", desired: null, effective: { configured: true }, default: null, source: "environment", consumers: ["black-onyx", "security-gateway"], editable: true, restart_required: true, secret: true, validation: {}, description: "HMAC key" },
          ],
        };
      if (path.startsWith("/admin/deployments?")) return { items: [draft], handoff_configured: true };
      return draft;
    }),
  };
});

afterEach(cleanup);

function renderQuery(element: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{element}</QueryClientProvider>);
}

describe("settings inventory", () => {
  it("shows source metadata and never a secret value", async () => {
    renderQuery(<SettingsInventoryPanel />);
    expect(await screen.findByText("chunking.chunk_size")).toBeVisible();
    expect(screen.getByText("runtime")).toBeVisible();
    expect(screen.getByText("configured")).toBeVisible();
  });

  it("summarizes a section as live with runtime overrides", () => {
    render(<SectionSource section="chunking" meta={{ "chunking.chunk_size": { desired: 900, effective: 900, default: 512, source: "runtime", restart_required: false, validation: {} } }} />);
    expect(screen.getByText(/Live apply · 1 override/)).toBeVisible();
  });
});

describe("deployment controller", () => {
  it("approves the exact previewed digest", async () => {
    renderQuery(<DeploymentPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Approve this preview" }));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith("/admin/deployments/rev-1/approve", {
        method: "POST",
        body: JSON.stringify({ preview_digest: "d".repeat(64) }),
      }),
    );
    expect(screen.getByText(/SECURITY_GATEWAY_KEY=<set>/)).toBeVisible();
  });

  it("sends NAME=value lines as env changes", async () => {
    renderQuery(<DeploymentPanel />);
    fireEvent.change(await screen.findByPlaceholderText("BLACK_ONYX_DETECTION_TENANT=acme"), {
      target: { value: "BLACK_ONYX_DETECTION_TENANT=acme\nLLM_MODEL_NAME=<unset>" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create draft" }));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith("/admin/deployments", {
        method: "POST",
        body: JSON.stringify({ target: "compose", env: { BLACK_ONYX_DETECTION_TENANT: "acme", LLM_MODEL_NAME: null }, values: {}, lab_exception_hours: null }),
      }),
    );
  });
});

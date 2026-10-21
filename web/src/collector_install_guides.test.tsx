import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ToastProvider } from "./components/toast";
import { UserProvider } from "./user_context";

const apiMock = vi.hoisted(() => ({ api: vi.fn(), downloadCollectorPackage: vi.fn() }));
vi.mock("./api", () => apiMock);

import { CollectorInstallGuides } from "./collector_install_guides";

function guide(revealed: boolean) {
  const key = revealed ? "ingest-key-1" : "********";
  return {
    gateway_url: "http://100.64.0.5:18091",
    registry_url: "http://100.64.0.5:18082",
    tenant_id: "tenant-a",
    wazuh_manager: "100.64.0.5",
    wazuh_manager_reachable: true,
    secrets_revealed: revealed,
    missing_secrets: [],
    guides: [{
      id: "osquery_shipper",
      title: "Endpoint — osquery + shipper",
      summary: "Install",
      commands: { linux: `sudo BLACK_ONYX_COLLECTOR_INGEST_KEY=${key} ./install.sh` },
    }],
    packages: [],
  };
}

function renderAs(role: "admin" | "analyst") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <UserProvider user={{ user_id: "u1", email: "u@example.test", display_name: "U", role }}>
          <CollectorInstallGuides showDownloads={false} />
        </UserProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("collector install guides", () => {
  it("lets an administrator reveal real enrollment secrets", async () => {
    apiMock.api.mockImplementation(async (path: string) => guide(path.includes("reveal=true")));
    renderAs("admin");
    expect(await screen.findByText(/BLACK_ONYX_COLLECTOR_INGEST_KEY=\*{8}/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Reveal enrollment secrets" }));
    expect(await screen.findByText(/BLACK_ONYX_COLLECTOR_INGEST_KEY=ingest-key-1/)).toBeInTheDocument();
    expect(apiMock.api).toHaveBeenCalledWith("/collectors/guide?reveal=true");
  });

  it("never offers the reveal to non-administrators", async () => {
    apiMock.api.mockResolvedValue(guide(false));
    renderAs("analyst");
    expect(await screen.findByText(/an administrator can reveal them/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Reveal enrollment secrets/ })).not.toBeInTheDocument();
  });
});

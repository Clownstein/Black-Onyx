import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { ConfirmDialog, DataTable, EmptyState, Heading, KeyValues } from "./ui";
import { FeedsWorkflow, IngestWorkflow } from "./workflows_operations";

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return { ...actual, api: vi.fn(async (path: string) => {
    if (path === "/feeds") return { feeds: [], enabled: true };
    if (path === "/misp/status") return { configured: false, status: "not_configured" };
    if (path === "/webhooks") return { webhooks: [] };
    return { status: "ok" };
  }) };
});

function renderQuery(element: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<MemoryRouter><QueryClientProvider client={client}>{element}</QueryClientProvider></MemoryRouter>);
}

describe("role-aware workflows", () => {
  it("disables ingestion for viewers", () => {
    renderQuery(<IngestWorkflow role="viewer" />);
    expect(screen.getByRole("button", { name: "Start ingestion" })).toBeDisabled();
    expect(screen.getByText(/Viewer accounts cannot start ingestion/)).toBeVisible();
  });

  it("allows analysts to poll approved feeds without showing feed administration", async () => {
    renderQuery(<FeedsWorkflow role="analyst" />);
    expect(await screen.findByRole("button", { name: "Poll due feeds" })).toBeVisible();
    expect(screen.getByRole("tab", { name: "Active feeds" })).toBeVisible();
    expect(screen.getByRole("tab", { name: "MISP" })).toBeVisible();
    expect(screen.queryByRole("tab", { name: "Add feed" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Inbound webhooks" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add feed" })).not.toBeInTheDocument();
  });
});

describe("typed destructive confirmation", () => {
  it("requires the exact resource name", async () => {
    const confirm = vi.fn();
    render(<ConfirmDialog label="Delete" expected="critical-case" onConfirm={confirm} />);
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    const finalButton = screen.getByRole("button", { name: "Confirm" });
    expect(finalButton).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Confirmation"), { target: { value: "critical-case" } });
    fireEvent.click(finalButton);
    await waitFor(() => expect(confirm).toHaveBeenCalledOnce());
  });
});

describe("workspace presentation", () => {
  it("renders intentional empty states instead of raw empty JSON", () => {
    render(<DataTable<{ name: string }> columns={[{ key: "name", label: "Name" }]} rows={[]} rowKey={row => row.name} empty={<EmptyState title="Nothing to show yet" description="Results appear here." compact />} />);
    expect(screen.getByText("Nothing to show yet")).toBeVisible();
    expect(screen.queryByText("[]")).not.toBeInTheDocument();
  });

  it("renders object detail as labelled fields rather than JSON", () => {
    render(<KeyValues items={[{ label: "Ingested", value: "12 files" }]} />);
    expect(screen.getByText("Ingested")).toBeVisible();
    expect(screen.getByText("12 files")).toBeVisible();
  });

  it("keeps page actions separate from heading copy", () => {
    render(<Heading title="Ingestion jobs" subtitle="Monitor active work." actions={<button>Refresh jobs</button>} />);
    expect(screen.getByRole("heading", { name: "Ingestion jobs" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Refresh jobs" })).toBeVisible();
  });
});

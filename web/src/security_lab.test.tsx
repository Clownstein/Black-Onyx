import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UserProvider } from "./user_context";

const securityApi = vi.hoisted(() => ({
  listSecurityTools: vi.fn(),
  executeSecurityTool: vi.fn(),
  previewSecurityTool: vi.fn(),
  approveSecurityTool: vi.fn(),
  runSecurityAgent: vi.fn(),
  getSecurityAgentRun: vi.fn(),
  resumeSecurityAgentRun: vi.fn(),
  securityHealth: vi.fn(),
}));

vi.mock("./detection/api/security_client", () => securityApi);

import { SecurityLabWorkflow } from "./workflows_security_lab";

/**
 * Shaped like the real `/api/v1/security/capabilities` payload, which the BFF
 * proxies from the gateway's `/health/tools`: name, description, category,
 * tier, status and the argument JSON Schema.
 *
 * `status` and `parameters` are the two fields that had drifted. The gateway
 * reported five capabilities as disabled and the UI dropped the flag, so a
 * gated tool looked runnable and 403'd on execution; and `parameters` was only
 * ever on `/v1/tools`, so the argument form rendered empty for all 45 tools.
 */
const NMAP = {
  name: "nmap_scan",
  description: "Network port and service scan",
  category: "security",
  tier: "lab",
  status: "enabled",
  parameters: {
    type: "object",
    properties: {
      target: { type: "string", description: "Target host/IP" },
      ports: { type: "string", description: "Port range", default: "1-1024" },
    },
    required: ["target"],
  },
};

const HYDRA = {
  name: "hydra_brute",
  description: "Credential brute force",
  category: "security",
  tier: "destructive",
  status: "disabled",
  parameters: {
    type: "object",
    properties: { target: { type: "string", description: "Target host" } },
    required: ["target"],
  },
};

const STRINGS = {
  name: "extract_strings",
  description: "Extract printable strings from a binary",
  category: "binary",
  tier: "read",
  status: "enabled",
  parameters: { type: "object", properties: { path: { type: "string" } } },
};

const CAPTURE = {
  name: "tcpdump_capture",
  description: "Capture packets in a registered lab",
  category: "security",
  tier: "privileged-capture",
  status: "enabled",
  parameters: {
    type: "object",
    properties: {
      duration: { type: "integer", default: 10 },
      filter: { type: "string", default: "" },
    },
  },
};

afterEach(() => cleanup());

beforeEach(() => {
  cleanup();
  vi.clearAllMocks();
  securityApi.listSecurityTools.mockResolvedValue([NMAP, HYDRA, STRINGS]);
  securityApi.securityHealth.mockResolvedValue({ allow_public_targets: false });
  securityApi.executeSecurityTool.mockResolvedValue({
    status: "success",
    output: "done",
    returncode: 0,
  });
  securityApi.previewSecurityTool.mockResolvedValue({
    tool: "hydra_brute", tier: "destructive", arguments: {},
    session_id: "security-lab", timeout: 120, network_profile: "offline",
    destinations: [], preview_hash: "test-preview",
  });
  securityApi.approveSecurityTool.mockResolvedValue({ approval_id: "approval-test" });
  securityApi.getSecurityAgentRun.mockResolvedValue({ run_id: "run-1", status: "completed" });
  securityApi.resumeSecurityAgentRun.mockResolvedValue({ answer: "done", rounds: 1, status: "completed" });
});

async function openTool(name: string) {
  render(<UserProvider user={{ user_id: "u1", email: "analyst@example.test", display_name: "Analyst", role: "analyst" }}><SecurityLabWorkflow /></UserProvider>);
  const card = await screen.findByText(name);
  fireEvent.click(card);
  return card;
}

describe("Security Lab capability gating", () => {
  it("builds the argument form from the schema the capability matrix returns", async () => {
    await openTool("nmap_scan");

    // Both declared arguments render, the required one is marked, and the
    // schema default pre-fills. None of this happened while `parameters` was
    // absent from the endpoint the picker loads from.
    expect(await screen.findByText("target")).toBeInTheDocument();
    expect(screen.getByText("ports")).toBeInTheDocument();
    expect(screen.getByText("Target host/IP", { exact: false })).toBeInTheDocument();
    // `ports` carries a schema default, so the input is pre-filled with it.
    expect(screen.getByDisplayValue("1-1024")).toBeInTheDocument();
    // `target` is in the schema's `required` list and is marked as such.
    expect(screen.getByText("*")).toBeInTheDocument();
  });

  it("marks a gateway-disabled capability instead of offering it as runnable", async () => {
    await openTool("hydra_brute");

    await waitFor(() => expect(screen.getAllByText("disabled").length).toBeGreaterThan(0));
    expect(
      screen.getByText(/unavailable on the security gateway/i),
    ).toBeInTheDocument();
  });

  it("blocks running a disabled capability and never calls the API", async () => {
    await openTool("hydra_brute");

    const run = await screen.findByRole("button", { name: /unavailable/i });
    expect(run).toBeDisabled();

    // Disabled attribute aside, the handler must refuse too, so a programmatic
    // or keyboard activation cannot reach the gateway just to collect a 403.
    fireEvent.click(run);
    await waitFor(() => expect(securityApi.executeSecurityTool).not.toHaveBeenCalled());
  });

  it("does not show the approval gate for a capability that cannot run", async () => {
    await openTool("hydra_brute");

    // hydra_brute is destructive tier, so the approval checkbox would normally
    // appear. Asking an analyst to approve an operation that cannot execute is
    // the confusing state this replaces.
    await waitFor(() => expect(screen.getByText(/unavailable on the security gateway/i)).toBeInTheDocument());
    expect(screen.queryByText(/review destructive operation/i)).not.toBeInTheDocument();
  });

  it("still gates an enabled destructive tool behind explicit approval", async () => {
    securityApi.listSecurityTools.mockResolvedValue([{ ...HYDRA, status: "enabled" }]);
    await openTool("hydra_brute");

    fireEvent.change(screen.getByPlaceholderText("for example: anvil-lab"), { target: { value: "anvil-lab" } });

    const preview = await screen.findByRole("button", { name: /preview operation/i });
    fireEvent.click(preview);
    expect(await screen.findByText(/review destructive operation/i)).toBeInTheDocument();
    const run = screen.getByRole("button", { name: /approve and run/i });
    fireEvent.click(run);
    await waitFor(() => expect(securityApi.approveSecurityTool).toHaveBeenCalledOnce());
    await waitFor(() => expect(securityApi.executeSecurityTool).toHaveBeenCalledWith(
      "hydra_brute", expect.any(Object), expect.objectContaining({ approval_id: "approval-test" }),
    ));
  });

  it("requires a registered lab profile before previewing networked work", async () => {
    securityApi.listSecurityTools.mockResolvedValue([{ ...HYDRA, status: "enabled" }]);
    await openTool("hydra_brute");

    fireEvent.click(await screen.findByRole("button", { name: /preview operation/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/registered lab profile id/i);
    expect(securityApi.previewSecurityTool).not.toHaveBeenCalled();
  });

  it("shows a bounded capture result as a downloadable PCAP", async () => {
    securityApi.listSecurityTools.mockResolvedValue([{ ...CAPTURE }]);
    securityApi.previewSecurityTool.mockResolvedValue({
      tool: "tcpdump_capture", tier: "privileged-capture", arguments: { duration: 10, filter: "" },
      session_id: "security-lab", timeout: 10, network_profile: "lab", destinations: [],
      ports: [], lab_profile_id: "anvil-lab", resolved_targets: {}, preview_hash: "capture-preview",
    });
    securityApi.executeSecurityTool.mockResolvedValue({
      status: "success", output: "", format: "pcap", content_base64: "Y2FwdHVyZQ==",
      captured_bytes: 7, sha256: "a".repeat(64), job_id: "capture-job",
    });
    await openTool("tcpdump_capture");
    fireEvent.change(screen.getByPlaceholderText("for example: anvil-lab"), { target: { value: "anvil-lab" } });
    fireEvent.click(await screen.findByRole("button", { name: /preview operation/i }));
    fireEvent.click(await screen.findByRole("button", { name: /approve and run/i }));
    expect(await screen.findByText(/7 bytes captured/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download PCAP" })).toBeInTheDocument();
  });

  it("runs a read-tier tool without an approval step", async () => {
    securityApi.listSecurityTools.mockResolvedValue([STRINGS]);
    await openTool("extract_strings");

    expect(screen.queryByText(/I approve this/i)).not.toBeInTheDocument();
    const run = await screen.findByRole("button", { name: /run tool/i });
    expect(run).not.toBeDisabled();

    fireEvent.click(run);
    await waitFor(() => expect(securityApi.executeSecurityTool).toHaveBeenCalledWith(
      "extract_strings",
      expect.any(Object),
      expect.objectContaining({ session_id: "security-lab" }),
    ));
  });

  it("fails closed when an older capability matrix omits readiness", async () => {
    // An older gateway omits `parameters`. The picker must still render the
    // tool, just with no argument inputs.
    securityApi.listSecurityTools.mockResolvedValue([
      { name: "file_info", description: "File metadata", category: "binary", tier: "read" },
    ]);
    await openTool("file_info");

    expect(await screen.findByRole("button", { name: /^unavailable$/i })).toBeDisabled();
  });

  it("shows the exact pending agent request and resumes only after an explicit approval", async () => {
    const pending = {
      tool: "Write", tier: "workspace-write", arguments: { path: "notes.txt", content: "review" },
      session_id: "security-lab", timeout: 30, network_profile: "offline", destinations: [],
      preview_hash: "preview-bound", expires_at: Math.floor(Date.now() / 1000) + 60,
    };
    securityApi.runSecurityAgent.mockResolvedValue({
      answer: "", rounds: 1, status: "pending_approval", run_id: "run-1", pending_approval: pending,
    });
    const input = screen.queryByPlaceholderText(/Extract strings from sample.bin/);
    if (!input) render(<UserProvider user={{ user_id: "u1", email: "analyst@example.test", display_name: "Analyst", role: "analyst" }}><SecurityLabWorkflow /></UserProvider>);
    fireEvent.change(await screen.findByPlaceholderText(/Extract strings from sample.bin/), { target: { value: "write notes" } });
    fireEvent.click(screen.getByRole("button", { name: "Ask" }));
    expect(await screen.findByText(/review pending workspace-write operation/i)).toBeInTheDocument();
    expect(screen.getByText(/notes.txt/)).toBeInTheDocument();
    expect(securityApi.approveSecurityTool).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /approve and resume/i }));
    await waitFor(() => expect(securityApi.approveSecurityTool).toHaveBeenCalledWith(pending));
    await waitFor(() => expect(securityApi.resumeSecurityAgentRun).toHaveBeenCalledWith(
      "run-1", { approval_id: "approval-test" },
    ));
    expect(screen.getByText("done")).toBeInTheDocument();
  });

  it("explains an expired agent approval instead of ignoring the click", async () => {
    const pending = {
      tool: "Write", tier: "workspace-write", arguments: { path: "notes.txt", content: "review" },
      session_id: "security-lab", timeout: 30, network_profile: "offline", destinations: [],
      preview_hash: "preview-bound", expires_at: Math.floor(Date.now() / 1000) - 30,
    };
    securityApi.runSecurityAgent.mockResolvedValue({
      answer: "", rounds: 1, status: "pending_approval", run_id: "run-expired", pending_approval: pending,
    });
    const input = screen.queryByPlaceholderText(/Extract strings from sample.bin/);
    if (!input) render(<UserProvider user={{ user_id: "u1", email: "analyst@example.test", display_name: "Analyst", role: "analyst" }}><SecurityLabWorkflow /></UserProvider>);
    fireEvent.change(await screen.findByPlaceholderText(/Extract strings from sample.bin/), { target: { value: "write notes" } });
    fireEvent.click(screen.getByRole("button", { name: "Ask" }));
    expect(await screen.findByText(/this approval expired/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /approve and resume/i })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: /approve and resume/i }));
    expect(securityApi.approveSecurityTool).not.toHaveBeenCalled();
    expect(securityApi.resumeSecurityAgentRun).not.toHaveBeenCalled();
  });

  it("recovers a paused run after navigation and permits explicit denial", async () => {
    const pending = {
      tool: "Write", tier: "workspace-write", arguments: { path: "notes.txt", content: "review" },
      session_id: "security-lab", timeout: 30, network_profile: "offline", destinations: [],
      preview_hash: "preview-bound", expires_at: Math.floor(Date.now() / 1000) + 60,
    };
    sessionStorage.setItem("blackonyx-security-agent-run:u1", "run-1");
    securityApi.getSecurityAgentRun.mockResolvedValue({
      run_id: "run-1", status: "pending_approval", pending_approval: pending,
    });
    securityApi.resumeSecurityAgentRun.mockResolvedValue({ answer: "denied", rounds: 2, status: "completed" });
    render(<UserProvider user={{ user_id: "u1", email: "analyst@example.test", display_name: "Analyst", role: "analyst" }}><SecurityLabWorkflow /></UserProvider>);
    expect(await screen.findByText(/review pending workspace-write operation/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    await waitFor(() => expect(securityApi.resumeSecurityAgentRun).toHaveBeenCalledWith("run-1", { deny: true }));
    expect(securityApi.approveSecurityTool).not.toHaveBeenCalled();
  });
});


describe("Security Lab public-scan status", () => {
  it("still lists tools when the public-scan status cannot be loaded", async () => {
    securityApi.securityHealth.mockRejectedValue(new Error("gateway health down"));
    render(<UserProvider user={{ user_id: "u1", email: "analyst@example.test", display_name: "Analyst", role: "analyst" }}><SecurityLabWorkflow /></UserProvider>);
    expect(await screen.findByText("nmap_scan")).toBeInTheDocument();
    expect(screen.queryByText(/Non-lab public scanning/)).not.toBeInTheDocument();
  });

  it("shows the deployment flag read-only when available", async () => {
    securityApi.securityHealth.mockResolvedValue({ allow_public_targets: true });
    render(<UserProvider user={{ user_id: "u1", email: "analyst@example.test", display_name: "Analyst", role: "analyst" }}><SecurityLabWorkflow /></UserProvider>);
    expect(await screen.findByText("enabled")).toBeInTheDocument();
  });
});

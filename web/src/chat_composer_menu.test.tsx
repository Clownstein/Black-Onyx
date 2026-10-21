import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ChatComposerMenu, networkProfileForHost, stripExecutionControlArgs } from "./chat_composer_menu";

vi.mock("./api", () => ({
  api: vi.fn(async () => ({
    enabled: true,
    lab_profile_id: "anvil",
    groups: [{
      id: "security",
      label: "Network scanners",
        tools: [{
        name: "sec_nmap_scan",
        description: "nmap",
        group: "security",
        enabled: true,
        allow_private: true,
        allow_public: false,
        network_profile: "lab",
        timeout_seconds: 60,
      }, {
        name: "sec_sqlmap_scan",
        description: "sqlmap",
        group: "security",
        enabled: false,
        allow_private: true,
        allow_public: false,
        network_profile: "lab",
        timeout_seconds: 60,
      }],
    }],
  })),
}));

describe("chat composer tool menu", () => {
  it("lets the analyst select an enabled MCP tool", async () => {
    const onChange = vi.fn();
    render(
      <ChatComposerMenu
        mcpAvailable
        selected={[]}
        onChangeSelected={onChange}
        onAttach={vi.fn()}
        onOpenSystem={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByTitle("Add files, system message, or tools"));
    expect(await screen.findByText("Tools")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Tools"));
    const networkScanners = await screen.findByText(
      (_content, element) => element?.tagName === "SUMMARY" && element.textContent?.includes("Network scanners") === true,
    );
    expect(networkScanners).toBeInTheDocument();
    fireEvent.click(networkScanners);
    const boxes = await screen.findAllByRole("checkbox");
    expect(boxes[1]).toBeDisabled();
    fireEvent.click(boxes[0]);
    expect(onChange).toHaveBeenCalledWith(["sec_nmap_scan"]);
  });

  it("derives lab vs public from the scanned host and strips control fields", () => {
    expect(networkProfileForHost("10.88.0.2")).toBe("lab");
    expect(networkProfileForHost("https://example.com/path")).toBe("public");
    expect(stripExecutionControlArgs({
      target: "10.88.0.2",
      approval_id: "forged",
      network_profile: "public",
    })).toEqual({ target: "10.88.0.2" });
  });
});

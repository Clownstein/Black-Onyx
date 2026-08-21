import "@testing-library/jest-dom/vitest";
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { UserProvider } from "../user_context";
import { User } from "../api";
import { BUILTIN_TILES } from "./tile_registry";
import { GalleryHub } from "./GalleryHub";
import { DEFAULT_FILTER, matchesFilter } from "./FilterPanel";
import { GalleryTile } from "./types";
import { AddSiteForm } from "./sites";
import { CredentialPanel } from "./CredentialPanel";
import { GalleryTileCard } from "./GalleryTileCard";
import { A11yTileLinks } from "./A11yTileLinks";

const EMPTY_RESPONSES: Record<string, unknown> = {
  "/info": { collections: [] },
  "/jobs": { jobs: [] },
  "/feeds": { feeds: [], enabled: true },
  "/cases": { cases: [], total: 0 },
  "/alerts": { alerts: [] },
  "/bookmarks": { bookmarks: [] },
  "/decay/summary": { tracked_count: 0, stale_count: 0, fresh_count: 0, last_updated: null },
  "/capabilities": { features: {}, disabled_reasons: {} },
  "/sites": [],
  "/connectors": [],
};

function defaultApiImpl(path: string, _init?: RequestInit) {
  const base = path.split("?")[0];
  if (base in EMPTY_RESPONSES) return Promise.resolve(EMPTY_RESPONSES[base]);
  return Promise.resolve({});
}

const apiMock = vi.fn(defaultApiImpl);

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return { ...actual, api: (...args: Parameters<typeof apiMock>) => apiMock(...args) };
});

// This project's vitest config does not set `test.globals`, so
// @testing-library/react's automatic per-test cleanup (which relies on a
// global `afterEach`) never registers — without an explicit cleanup() here,
// every GalleryHub render in this file accumulates in the same document,
// and later tests' `getByText` calls fail with "multiple elements found".
afterEach(() => {
  cleanup();
});

beforeEach(() => {
  apiMock.mockReset();
  apiMock.mockImplementation(defaultApiImpl);
});

// jsdom implements neither matchMedia nor a canvas WebGL context. Real
// browsers support both — useCanvasSupport's own try/catch already handles
// their absence correctly (falls back to the list view), but jsdom's
// unimplemented getContext() logs noisy console errors on every call, so
// stub both directly rather than relying on the try/catch to swallow them.
beforeAll(() => {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  });
  HTMLCanvasElement.prototype.getContext = (() => null) as typeof HTMLCanvasElement.prototype.getContext;
});

function renderWithProviders(element: React.ReactNode, user: User) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/"]}>
        <UserProvider user={user}>{element}</UserProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function userWithRole(role: User["role"]): User {
  return { user_id: "u1", email: "analyst@example.com", display_name: "Analyst", role };
}

describe("tile_registry", () => {
  it("has a unique id and href per built-in tile", () => {
    const ids = new Set(BUILTIN_TILES.map(tile => tile.id));
    const hrefs = new Set(BUILTIN_TILES.map(tile => tile.href));
    expect(ids.size).toBe(BUILTIN_TILES.length);
    expect(hrefs.size).toBe(BUILTIN_TILES.length);
  });

  it("gives every tile a title, subtitle, section, and preview", () => {
    for (const tile of BUILTIN_TILES) {
      expect(tile.title.length).toBeGreaterThan(0);
      expect(tile.subtitle.length).toBeGreaterThan(0);
      expect(tile.section).toBeTruthy();
      expect(tile.preview).toBeTruthy();
    }
  });
});

describe("FilterPanel matchesFilter", () => {
  const tile: GalleryTile = {
    id: "route:/cases", kind: "builtin", href: "/cases", section: "operations",
    title: "Cases", subtitle: "Investigation cases", preview: "metric", tags: ["ops"],
  };

  it("matches everything with the default filter", () => {
    expect(matchesFilter(tile, DEFAULT_FILTER)).toBe(true);
  });

  it("filters by section", () => {
    expect(matchesFilter(tile, { ...DEFAULT_FILTER, section: "operations" })).toBe(true);
    expect(matchesFilter(tile, { ...DEFAULT_FILTER, section: "sites" })).toBe(false);
  });

  it("filters by origin", () => {
    expect(matchesFilter(tile, { ...DEFAULT_FILTER, origin: "builtin" })).toBe(true);
    expect(matchesFilter(tile, { ...DEFAULT_FILTER, origin: "external" })).toBe(false);
  });

  it("filters by free-text match on title, subtitle, href, and tags", () => {
    expect(matchesFilter(tile, { ...DEFAULT_FILTER, query: "investigation" })).toBe(true);
    expect(matchesFilter(tile, { ...DEFAULT_FILTER, query: "ops" })).toBe(true);
    expect(matchesFilter(tile, { ...DEFAULT_FILTER, query: "nonexistent" })).toBe(false);
  });

  it("filters by status", () => {
    const alertTile: GalleryTile = { ...tile, badge: "ALERTS" };
    expect(matchesFilter(alertTile, { ...DEFAULT_FILTER, status: "alerts" })).toBe(true);
    expect(matchesFilter(tile, { ...DEFAULT_FILTER, status: "alerts" })).toBe(false);
  });
});

describe("GalleryHub role-based rendering", () => {
  it("hides operational and admin-only tiles from a viewer", async () => {
    renderWithProviders(<GalleryHub />, userWithRole("viewer"));
    await waitFor(() => expect(screen.getByText("Dashboard")).toBeInTheDocument());
    expect(screen.queryByText("Jobs")).not.toBeInTheDocument();
    expect(screen.queryByText("Ingest")).not.toBeInTheDocument();
    expect(screen.queryByText("Chat")).not.toBeInTheDocument();
    expect(screen.queryByText("IOC workbench")).not.toBeInTheDocument();
    expect(screen.queryByText("Rules")).not.toBeInTheDocument();
    expect(screen.queryByText("Administration")).not.toBeInTheDocument();
    expect(screen.queryByText("Settings")).not.toBeInTheDocument();
    // Viewers get "New case" as the default CTA, not "Ask chat".
    expect(screen.getByRole("link", { name: "New case" })).toBeInTheDocument();
  });

  it("shows admin-only Control tiles and the Ask chat CTA for an admin", async () => {
    renderWithProviders(<GalleryHub />, userWithRole("admin"));
    await waitFor(() => expect(screen.getByText("Administration")).toBeInTheDocument());
    expect(screen.getByText("Settings")).toBeInTheDocument();
    expect(screen.getByText("Jobs")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Ask chat" })).toBeInTheDocument();
  });

  it("renders every visible tile as a real anchor with a correct href", async () => {
    renderWithProviders(<GalleryHub />, userWithRole("admin"));
    await waitFor(() => expect(screen.getByText("Dashboard")).toBeInTheDocument());
    const dashboardLink = screen.getByText("Dashboard").closest("a");
    expect(dashboardLink).toHaveAttribute("href", "/dashboard");
    const iocLink = screen.getByText("IOC workbench").closest("a");
    expect(iocLink).toHaveAttribute("href", "/iocs");
  });

  it("opens the Add site form from the Sites section CTA", async () => {
    renderWithProviders(<GalleryHub />, userWithRole("analyst"));
    await waitFor(() => expect(screen.getByText("Dashboard")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Sites" }));
    // The empty-Sites state also offers its own "+ Add site" button, so scope
    // this click to the persistent CTA in the chrome, not the empty state.
    const cta = document.querySelector(".gallery-cta") as HTMLElement;
    const ctaButton = await within(cta).findByRole("button", { name: "+ Add site" });
    fireEvent.click(ctaButton);
    expect(await screen.findByRole("heading", { name: "Add site" })).toBeInTheDocument();
  });
});

describe("AddSiteForm", () => {
  it("submits a site create request and, when a login is provided, a credential request", async () => {
    apiMock.mockImplementation(async (path: string, init?: RequestInit) => {
      if (path === "/sites" && init?.method === "POST") return { site_id: "site-1" };
      if (path === "/sites/site-1/credential" && init?.method === "POST") return { status: "ok" };
      const base = path.split("?")[0];
      return EMPTY_RESPONSES[base] ?? {};
    });
    const onCreated = vi.fn();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <AddSiteForm onCreated={onCreated} onCancel={() => {}} />
      </QueryClientProvider>,
    );

    fireEvent.change(screen.getByLabelText(/Display name/), { target: { value: "Internal SIEM" } });
    fireEvent.change(screen.getByLabelText(/^URL/), { target: { value: "https://siem.example.com" } });
    fireEvent.click(screen.getByLabelText(/Save a login for this site/));
    fireEvent.change(screen.getByLabelText(/Username \/ email/), { target: { value: "analyst" } });
    fireEvent.change(screen.getByLabelText(/Password \/ API token/), { target: { value: "hunter2" } });
    fireEvent.click(screen.getByRole("button", { name: "Add site" }));

    await waitFor(() => expect(onCreated).toHaveBeenCalledWith("site-1"));
    const siteCall = apiMock.mock.calls.find(call => call[0] === "/sites");
    expect(siteCall).toBeTruthy();
    const body = JSON.parse((siteCall![1] as RequestInit).body as string);
    expect(body).toMatchObject({ name: "Internal SIEM", url: "https://siem.example.com", section: "sites" });
    const credentialCall = apiMock.mock.calls.find(call => call[0] === "/sites/site-1/credential");
    expect(credentialCall).toBeTruthy();
  });
});

describe("CredentialPanel", () => {
  const site = {
    site_id: "site-1", name: "Internal SIEM", url: "https://siem.example.com",
    login_url: null, section: "sites" as const, tags: [], open_mode: "new_tab" as const,
    favicon_url: null, has_credential: true,
    frameable: null, frameable_checked_at: null, frameable_error: null,
    created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z",
  };

  it("reveals a saved login and offers copy buttons", async () => {
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
    apiMock.mockImplementation(async (path: string) => {
      if (path === "/sites/site-1/credential") {
        return { username: "analyst@example.com", secret: "hunter2-secret", notes: null, updated_at: "2026-01-01T00:00:00Z", last_accessed_at: null };
      }
      return {};
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <CredentialPanel site={site} onClose={() => {}} />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Reveal" }));
    expect(await screen.findByText("analyst@example.com")).toBeInTheDocument();
    const copyButtons = screen.getAllByRole("button", { name: "Copy" });
    fireEvent.click(copyButtons[0]);
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith("analyst@example.com"));
  });

  it("surfaces a rate-limit error distinctly from other failures", async () => {
    const { ApiError } = await import("../api");
    apiMock.mockImplementation(async () => { throw new ApiError(429, "Too many attempts"); });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <CredentialPanel site={site} onClose={() => {}} />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Reveal" }));
    expect(await screen.findByText(/Too many reveal attempts/)).toBeInTheDocument();
  });
});

describe("GalleryHub manage panel stays live", () => {
  it("reflects has_credential after saving a login, without closing and reopening the panel", async () => {
    let hasCredential = false;
    const liveSite = () => ({
      site_id: "site-1", name: "Live Site", url: "https://live.example.com",
      login_url: null, section: "sites" as const, tags: [], open_mode: "new_tab" as const,
      favicon_url: null, has_credential: hasCredential,
      frameable: null, frameable_checked_at: null, frameable_error: null,
      created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z",
    });
    apiMock.mockImplementation(async (path: string, init?: RequestInit) => {
      if (path === "/sites" && (!init || !init.method)) return [liveSite()];
      if (path === "/sites/site-1/credential" && init?.method === "POST") {
        hasCredential = true;
        return { status: "ok" };
      }
      const base = path.split("?")[0];
      return EMPTY_RESPONSES[base] ?? {};
    });

    renderWithProviders(<GalleryHub />, userWithRole("analyst"));
    await waitFor(() => expect(screen.getByText("Live Site")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Manage login" }));

    // Opens on the actions view with no saved login yet — this is also the
    // regression case for the "inescapable form" bug: there must be a
    // "Save login" action, not an auto-opened form with no way out.
    expect(await screen.findByText("No saved login yet")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save login" }));
    fireEvent.change(screen.getByLabelText(/Username \/ email/), { target: { value: "analyst" } });
    fireEvent.change(screen.getByLabelText(/Password \/ API token/), { target: { value: "hunter2" } });
    fireEvent.click(screen.getByRole("button", { name: "Save login" }));

    // The same, still-open panel must pick up has_credential:true from the
    // invalidated ["sites"] query — no manual close/reopen required.
    await waitFor(() => expect(screen.getByText("Saved login")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Edit / rotate" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reveal" })).toBeInTheDocument();
  });
});

describe("embedded open_mode routes to the in-app panel", () => {
  const embeddedTile: GalleryTile = {
    id: "site:s1", kind: "external", href: "https://console.example.com",
    section: "sites", title: "Embedded Console", subtitle: "console.example.com",
    preview: "favicon", openMode: "embedded", siteId: "s1",
  };

  it("opens the panel instead of a new tab from the list/grid view", () => {
    const onOpenEmbedded = vi.fn();
    render(
      <MemoryRouter>
        <GalleryTileCard tile={embeddedTile} onOpenEmbedded={onOpenEmbedded} />
      </MemoryRouter>,
    );
    const anchor = screen.getByRole("link", { name: /Embedded Console/ });
    // Still a real anchor with a real href for no-JS / middle-click / a11y...
    expect(anchor).toHaveAttribute("href", "https://console.example.com");
    // ...but must not be a plain new-tab escape, which is what it silently
    // fell through to before: only "launcher" was special-cased, so embedded
    // mode worked in canvas view alone.
    expect(anchor).not.toHaveAttribute("target", "_blank");
    fireEvent.click(anchor);
    expect(onOpenEmbedded).toHaveBeenCalledWith(embeddedTile);
  });

  it("keeps the manage-login control available for embedded sites", () => {
    // Unlike launcher mode (where the panel *is* the credential manager), the
    // embedded panel shows the site, so a saved login still needs a way in.
    render(
      <MemoryRouter>
        <GalleryTileCard tile={embeddedTile} onOpenEmbedded={vi.fn()} onManage={vi.fn()} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("button", { name: "Manage login" })).toBeInTheDocument();
  });

  it("gives keyboard users the same panel via the a11y link layer", () => {
    const onOpenEmbedded = vi.fn();
    render(
      <MemoryRouter>
        <A11yTileLinks tiles={[embeddedTile]} onOpenEmbedded={onOpenEmbedded} />
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole("link", { name: "Embedded Console" }));
    expect(onOpenEmbedded).toHaveBeenCalledWith(embeddedTile);
  });

  it("falls back to a plain new-tab anchor when no panel handler is wired", () => {
    render(
      <MemoryRouter>
        <GalleryTileCard tile={embeddedTile} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: /Embedded Console/ })).toHaveAttribute("target", "_blank");
  });
});

describe("gallery pan + concave sphere math", () => {
  it("applies grab polarity on drag (invert vertical)", async () => {
    const { applyDragPanDelta } = await import("./gallery_geometry");
    expect(applyDragPanDelta({ x: 0, y: 0 }, 10, 20)).toEqual({ x: 10, y: -20 });
  });

  it("applies standard wheel polarity (add deltas)", async () => {
    const { applyWheelPanDelta } = await import("./gallery_geometry");
    expect(applyWheelPanDelta({ x: 1, y: 2 }, 3, 4)).toEqual({ x: 4, y: 6 });
  });

  it("places the origin cell on the sphere wall at z≈0 facing the camera", async () => {
    const { poseOnConcaveSphere, GALLERY_RADIUS } = await import("./gallery_geometry");
    const { position, rotation } = poseOnConcaveSphere(0, 0);
    expect(position.x).toBeCloseTo(0, 5);
    expect(position.y).toBeCloseTo(0, 5);
    expect(position.z).toBeCloseTo(0, 5);
    expect(rotation.x).toBeCloseTo(0, 5);
    expect(rotation.y).toBeCloseTo(0, 5);
    expect(rotation.z).toBeCloseTo(0, 5);
    const off = poseOnConcaveSphere(GALLERY_RADIUS * (Math.PI / 6), 0);
    expect(off.position.z).toBeGreaterThan(0);
    expect(off.rotation.y).toBeCloseTo(-(Math.PI / 6), 5);
  });

  it("keeps Trends and Triage glyphs distinct", () => {
    const trends = BUILTIN_TILES.find((t) => t.id === "route:/trends");
    const triage = BUILTIN_TILES.find((t) => t.id === "route:/triage");
    expect(trends?.glyph).toBeTruthy();
    expect(triage?.glyph).toBeTruthy();
    expect(trends?.glyph).not.toBe(triage?.glyph);
  });
});

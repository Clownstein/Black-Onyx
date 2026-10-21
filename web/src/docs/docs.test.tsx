import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import mainSource from "../main.tsx?raw";
import type { User } from "../api";
import { UserProvider } from "../user_context";
import { PAGE_DOCS, docsForRole } from "./catalog";
import { Documentation } from "./Documentation";
import { Walkthrough, finishWalkthrough, walkthroughFinished } from "./Walkthrough";

const ROUTES = /<Route\s+path="([^"]+)"/g;
const SKIP = new Set(["/", "/hub", "*", "/detection-admin", "/services"]);

function user(role: User["role"]): User {
  return { user_id: "u", email: "a@b.c", display_name: "A", role };
}

function renderDocs(role: User["role"], path = "/docs") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <UserProvider user={user(role)}>
        <Documentation />
        <Walkthrough />
      </UserProvider>
    </MemoryRouter>,
  );
}

afterEach(() => {
  cleanup();
  localStorage.clear();
});

beforeEach(() => {
  localStorage.clear();
});

describe("page documentation", () => {
  it("covers every static page route", () => {
    const routes = [...mainSource.matchAll(ROUTES)]
      .map((match) => match[1])
      .filter((path) => path.startsWith("/") && !path.includes(":") && !SKIP.has(path));
    const documented = new Set(PAGE_DOCS.map((article) => article.path));
    expect(routes.filter((path) => !documented.has(path))).toEqual([]);
  });

  it("walks pages in sidebar order, with documentation before ingest", () => {
    const paths = docsForRole("admin").map((article) => article.path);
    expect(new Set(paths).size).toBe(paths.length);
    expect(paths[paths.indexOf("/docs") + 1]).toBe("/ingest");
  });

  it("gives every article the four sections", () => {
    for (const article of PAGE_DOCS) {
      expect(article.features.length, article.path).toBeGreaterThan(0);
      expect(article.configure.length, article.path).toBeGreaterThan(0);
      expect(article.works.length, article.path).toBeGreaterThan(0);
      expect(article.use.length, article.path).toBeGreaterThan(0);
    }
  });

  it("hides admin and analyst pages from a viewer", () => {
    const paths = docsForRole("viewer").map((article) => article.path);
    expect(paths).toContain("/docs");
    expect(paths).not.toContain("/admin");
    expect(paths).not.toContain("/settings");
    expect(paths).not.toContain("/triage");
    expect(paths).not.toContain("/hunt");
  });

  it("shows an article and hides the tour after it has been finished", () => {
    finishWalkthrough();
    renderDocs("admin");
    expect(screen.getByRole("heading", { name: "Documentation" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "Gallery" })).toBeVisible();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Feeds" }));
    expect(screen.getByRole("heading", { name: "Feeds" })).toBeVisible();
    expect(screen.getByText(/http:\/\/misp/)).toBeVisible();
  });
});

describe("first-run walkthrough", () => {
  it("starts on the current page and opens the next page", () => {
    renderDocs("analyst", "/dashboard");
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("Dashboard");
    expect(dialog).toHaveTextContent("2 of");
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(dialog).toHaveTextContent("Analytics");
  });

  it("records skip so the tour does not return", () => {
    renderDocs("viewer", "/search");
    fireEvent.click(screen.getByRole("button", { name: "Skip" }));
    expect(walkthroughFinished()).toBe(true);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("replays from the documentation page", () => {
    finishWalkthrough();
    renderDocs("admin", "/docs");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Replay walkthrough" }));
    expect(screen.getByRole("dialog")).toHaveTextContent("Gallery");
  });
});

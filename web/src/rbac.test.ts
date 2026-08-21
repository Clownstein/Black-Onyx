import { describe, expect, it } from "vitest";
import { ADMIN_ONLY_PATHS, VIEWER_HIDDEN_PATHS, isAdmin, isOperational, visibleFor } from "./rbac";

describe("rbac", () => {
  it("hides operational-only paths from viewers", () => {
    for (const path of VIEWER_HIDDEN_PATHS) {
      expect(visibleFor("viewer", path)).toBe(false);
      expect(visibleFor("analyst", path)).toBe(true);
      expect(visibleFor("admin", path)).toBe(true);
    }
  });

  it("hides admin-only paths from every non-admin role", () => {
    for (const path of ADMIN_ONLY_PATHS) {
      expect(visibleFor("viewer", path)).toBe(false);
      expect(visibleFor("analyst", path)).toBe(false);
      expect(visibleFor("admin", path)).toBe(true);
    }
  });

  it("leaves ungated paths visible to every role", () => {
    for (const role of ["viewer", "analyst", "admin"] as const) {
      expect(visibleFor(role, "/cases")).toBe(true);
      expect(visibleFor(role, "/bookmarks")).toBe(true);
    }
  });

  it("isOperational/isAdmin match the underlying sets", () => {
    expect(isOperational("viewer")).toBe(false);
    expect(isOperational("analyst")).toBe(true);
    expect(isOperational("admin")).toBe(true);
    expect(isAdmin("admin")).toBe(true);
    expect(isAdmin("analyst")).toBe(false);
  });
});

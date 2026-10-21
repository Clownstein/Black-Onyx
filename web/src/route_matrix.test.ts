import { describe, expect, it } from "vitest";
import mainSource from "./main.tsx?raw";
import { ADMIN_ONLY_PATHS, VIEWER_HIDDEN_PATHS, visibleFor } from "./rbac";
import type { Role } from "./api";

/**
 * Black Onyx gates a route in two independent places: the `<Route element>` in
 * main.tsx decides what renders, and rbac.ts's `visibleFor` decides whether the
 * sidebar and the gallery tile wall offer the link at all. Nothing connected
 * them, and they had drifted eight operational routes were gated in the route
 * elements but absent from VIEWER_HIDDEN_PATHS, so a viewer saw the nav entries
 * and tiles and got redirected to / on click.
 *
 * These tests derive the matrix from the route elements themselves, so the two
 * lists are checked against the code rather than against each other's copy.
 */

type Gate = "open" | "operational" | "admin";

const ROUTE = /<Route\s+path="([^"]+)"\s+element=\{([\s\S]*?)\}\s*\/>/g;

/** Routes that render nothing role-specific: redirects, the gallery, the catch-all. */
const NON_PAGE_PATHS = new Set(["/", "/hub", "*", "/detection-admin", "/services"]);

function routeMatrix(): Map<string, Gate> {
  const matrix = new Map<string, Gate>();
  for (const [, path, element] of mainSource.matchAll(ROUTE)) {
    const gate: Gate = element.startsWith("operational?")
      ? "operational"
      : element.startsWith("isAdmin(user.role)?")
        ? "admin"
        : "open";
    matrix.set(path, gate);
  }
  return matrix;
}

/** `/incidents/:id` is gated with `/incidents`; nav and tiles only link the parent. */
function isParamRoute(path: string): boolean {
  return path.includes("/:");
}

const ROLES: Role[] = ["viewer", "analyst", "admin"];

describe("route matrix", () => {
  const matrix = routeMatrix();

  it("parsed the route table out of main.tsx", () => {
    expect(matrix.size).toBeGreaterThan(40);
    expect(matrix.get("/dashboard")).toBe("open");
    expect(matrix.get("/admin")).toBe("admin");
    expect(matrix.get("/security-lab")).toBe("operational");
  });

  it("hides every operational-gated route from viewers in nav and tiles", () => {
    const missing = [...matrix]
      .filter(([path, gate]) => gate === "operational" && !isParamRoute(path))
      .filter(([path]) => !VIEWER_HIDDEN_PATHS.has(path))
      .map(([path]) => path);
    expect(
      missing,
      "these routes redirect a viewer to / but are still offered in the sidebar and gallery",
    ).toEqual([]);
  });

  it("hides every admin-gated route from non-admins in nav and tiles", () => {
    const missing = [...matrix]
      .filter(([path, gate]) => gate === "admin" && !isParamRoute(path))
      .filter(([path]) => !ADMIN_ONLY_PATHS.has(path))
      .map(([path]) => path);
    expect(missing).toEqual([]);
  });

  it("does not hide a route that renders for every role", () => {
    // The inverse drift: a link removed from the nav while the page stays open
    // to everyone, which hides working functionality rather than protecting it.
    const overGated = [...matrix]
      .filter(([path, gate]) => gate === "open" && !NON_PAGE_PATHS.has(path))
      .filter(([path]) => VIEWER_HIDDEN_PATHS.has(path) || ADMIN_ONLY_PATHS.has(path))
      .map(([path]) => path);
    expect(overGated).toEqual([]);
  });

  it("classifies every declared path for every role", () => {
    for (const [path, gate] of matrix) {
      if (NON_PAGE_PATHS.has(path) || isParamRoute(path)) continue;
      for (const role of ROLES) {
        const visible = visibleFor(role, path);
        const shouldSee =
          gate === "open" ||
          (gate === "operational" && role !== "viewer") ||
          (gate === "admin" && role === "admin");
        expect(visible, `${role} @ ${path} (gate: ${gate})`).toBe(shouldSee);
      }
    }
  });

  it("keeps rbac.ts free of paths that no longer exist", () => {
    const declared = new Set(matrix.keys());
    const stale = [...VIEWER_HIDDEN_PATHS, ...ADMIN_ONLY_PATHS].filter((path) => !declared.has(path));
    expect(stale, "rbac.ts gates a path with no route").toEqual([]);
  });

  it("gates the detection console and Security Lab behind the analyst role", () => {
    // Their BFF mounts are analyst+ including GET, so a viewer cannot read them
    // even if the route rendered. Spot-checked explicitly because these are the
    // surfaces that reach scanners, malware detonation and response actions.
    for (const path of ["/security-lab", "/malware", "/response-queue", "/detection", "/hunt"]) {
      expect(matrix.get(path), path).toBe("operational");
      expect(visibleFor("viewer", path), path).toBe(false);
      expect(visibleFor("analyst", path), path).toBe(true);
    }
  });
});

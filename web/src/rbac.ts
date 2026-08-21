import { Role } from "./api";

/** Routes hidden from the viewer role in the primary sidebar nav and gated
 * server-side by the same set of paths in Layout()'s <Route> elements. */
export const VIEWER_HIDDEN_PATHS = new Set([
  "/jobs", "/ingest", "/chat", "/iocs", "/rules", "/query", "/assets", "/triage",
  // Detection BFF mounts ti/hub/response/notify/training/ingest/models as analyst+ (including GET).
  "/response-queue", "/malware", "/models", "/detection-services", "/security-profiles",
  "/data-health",
]);

/** Admin-only routes, gated both in nav rendering and route elements.
 * Connector *config* stays admin-only on the Detections page; analysts can
 * open /detections for the recent-detections read path. */
export const ADMIN_ONLY_PATHS = new Set(["/admin", "/settings"]);

export function isOperational(role: Role): boolean {
  return role !== "viewer";
}

export function isAdmin(role: Role): boolean {
  return role === "admin";
}

/** Whether a built-in route/tile should be visible to a given role. Single
 * source of truth shared by the sidebar nav, the gallery tile registry, and
 * the parallel a11y tile-link list — do not reimplement this elsewhere. */
export function visibleFor(role: Role, path: string): boolean {
  if (ADMIN_ONLY_PATHS.has(path)) return isAdmin(role);
  if (VIEWER_HIDDEN_PATHS.has(path)) return isOperational(role);
  return true;
}

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, Role } from "../api";
import { GalleryTile } from "./types";

/**
 * Live metrics/badges for built-in tiles, layered on top of the static
 * registry. Follows the codebase's existing inline-useQuery-per-widget
 * convention (see Dashboard/JobsWorkflow/etc. in main.tsx and
 * workflows_operations.tsx) rather than introducing a new hooks layer.
 *
 * Endpoint choices intentionally accept a capped-list `.length` as the v1
 * metric for jobs/feeds/cases/alerts/bookmarks — small datasets, and a new
 * count-only endpoint isn't worth it for each. Decay is the one exception:
 * /decay/stale and /decay/fresh are unbounded (no `limit` param at all), so
 * this uses the dedicated /decay/summary endpoint instead of calling those
 * raw. ATT&CK gallery metrics use /analytics/attack/coverage (org sighting
 * aggregates already computed server-side) — never invent placeholder counts.
 */
export function useTileMetrics(tiles: GalleryTile[], role: Role): GalleryTile[] {
  const info = useQuery({ queryKey: ["info"], queryFn: () => api<any>("/info") });
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: () => api<any>("/jobs"), refetchInterval: 3000 });
  const feeds = useQuery({ queryKey: ["feeds"], queryFn: () => api<any>("/feeds"), refetchInterval: 15_000 });
  // /api/v1/connectors is require_admin-gated server-side (org-wide
  // credentials/config, not personal data) — enabled:role==="admin" avoids a
  // guaranteed 403 on every gallery load for every non-admin session, the
  // same pattern FeedsWorkflow already uses for its webhooks query.
  const connectors = useQuery({
    queryKey: ["connectors"], queryFn: () => api<any[]>("/connectors"),
    enabled: role === "admin", refetchInterval: 15_000,
  });
  const cases = useQuery({ queryKey: ["cases"], queryFn: () => api<any>("/cases?limit=50") });
  const alerts = useQuery({
    queryKey: ["alerts-unacked"],
    queryFn: () => api<any>("/alerts?unacknowledged_only=true&limit=50"),
    refetchInterval: 15_000,
  });
  const bookmarks = useQuery({ queryKey: ["bookmarks"], queryFn: () => api<any>("/bookmarks") });
  const decay = useQuery({ queryKey: ["decay-summary"], queryFn: () => api<any>("/decay/summary") });
  const capabilities = useQuery({ queryKey: ["capabilities"], queryFn: () => api<any>("/capabilities") });
  const analytics = useQuery({
    queryKey: ["analytics-overview-tiles"],
    queryFn: () => api<any>("/analytics/overview?range=7d"),
    refetchInterval: 30_000,
  });
  const attackCoverage = useQuery({
    queryKey: ["attack-coverage-tiles"],
    queryFn: () => api<any>("/analytics/attack/coverage?range=30d"),
    refetchInterval: 60_000,
  });

  return useMemo(() => {
    const collections = (info.data?.collections || []) as any[];
    const allJobs = (jobs.data?.jobs || []) as any[];
    const activeJobs = allJobs.filter(job => ["queued", "running", "stopping"].includes(job.status));
    const feedList = (feeds.data?.feeds || []) as any[];
    const unhealthyFeeds = feedList.filter(feed => feed.last_status === "failed").length;
    const caseList = (cases.data?.cases || []) as any[];
    const openCases = caseList.filter(c => c.status === "open" || c.status === "investigating").length;
    const alertCount = ((alerts.data?.alerts || []) as any[]).length;
    const bookmarkCount = ((bookmarks.data?.bookmarks || []) as any[]).length;
    const decaySummary = decay.data as { tracked_count: number; fresh_count: number; stale_count: number } | undefined;
    const features = (capabilities.data?.features || {}) as Record<string, boolean>;
    const connectorList = (Array.isArray(connectors.data) ? connectors.data : []) as any[];
    const failingConnectors = connectorList.filter(c => c.enabled && c.last_poll_status === "failed").length;
    const sparks = analytics.data?.sparklines || {};
    const freshPct = analytics.data?.fresh_ioc_pct ?? (
      decaySummary && decaySummary.tracked_count
        ? Math.round((decaySummary.fresh_count / decaySummary.tracked_count) * 100)
        : undefined
    );
    const attackTechniques = ((attackCoverage.data?.techniques || attackCoverage.data?.leaderboard || []) as any[])
      .filter((t) => Number(t.sightings ?? 0) > 0);
    const topAttack = attackTechniques[0];
    const attackSightings = Number(attackCoverage.data?.n ?? attackTechniques.reduce((sum, t) => sum + Number(t.sightings ?? 0), 0));

    const patches: Record<string, Partial<GalleryTile>> = {
      "route:/": {
        metrics: { Collections: collections.length, "Active jobs": activeJobs.length },
        badge: activeJobs.length ? "LIVE" : undefined,
      },
      "route:/jobs": {
        metrics: { Active: activeJobs.length, Total: allJobs.length },
        badge: activeJobs.length ? "LIVE" : allJobs.length ? undefined : "EMPTY",
      },
      "route:/collections": {
        metrics: {
          Collections: collections.length,
          Points: collections.reduce((sum, item) => sum + (item.points_count || 0), 0),
        },
      },
      "route:/feeds": {
        metrics: { Feeds: feedList.length, Unhealthy: unhealthyFeeds },
        badge: unhealthyFeeds ? "ALERTS" : feedList.length ? "LIVE" : "EMPTY",
      },
      "route:/detections": {
        metrics: { Connectors: connectorList.length, Failing: failingConnectors },
        badge: failingConnectors ? "ALERTS" : connectorList.length ? "LIVE" : "EMPTY",
        sparkline: sparks.detections_24h || sparks.detections,
      },
      "route:/cases": {
        metrics: { Open: openCases, Total: caseList.length },
        badge: caseList.length ? undefined : "EMPTY",
      },
      "route:/watchlists": {
        metrics: { Unacknowledged: alertCount },
        badge: alertCount ? "ALERTS" : undefined,
        sparkline: sparks.alerts_7d || sparks.alerts,
      },
      "route:/triage": {
        metrics: { Unacknowledged: alertCount, Detections: analytics.data?.detections_24h ?? "—" },
        badge: alertCount ? "ALERTS" : undefined,
        sparkline: sparks.alerts_7d || sparks.alerts,
      },
      "route:/analytics": {
        metrics: {
          Alerts: analytics.data?.open_alerts ?? alertCount,
          "Fresh IOC %": freshPct ?? "—",
          Detections: analytics.data?.detections_24h ?? "—",
        },
        sparkline: sparks.alerts_7d || sparks.alerts,
        badge: "LIVE",
      },
      "route:/assets": {
        metrics: { Assets: analytics.data?.asset_count ?? "—" },
      },
      "route:/bookmarks": {
        metrics: { Saved: bookmarkCount },
        badge: bookmarkCount ? undefined : "EMPTY",
      },
      "route:/decay": decaySummary ? {
        metrics: { Tracked: decaySummary.tracked_count, Fresh: decaySummary.fresh_count, Stale: decaySummary.stale_count },
        badge: decaySummary.stale_count > 0 ? "ALERTS" : decaySummary.tracked_count ? undefined : "EMPTY",
        sparkline: sparks.fresh_ioc || undefined,
      } : {},
      "route:/attack": attackCoverage.data ? {
        metrics: {
          Techniques: attackCoverage.data.unique_techniques ?? attackTechniques.length,
          Sightings: attackSightings,
          ...(topAttack
            ? { Top: `${topAttack.technique_id}${topAttack.sightings != null ? `×${topAttack.sightings}` : ""}` }
            : {}),
        },
        badge: attackSightings ? "LIVE" : "EMPTY",
      } : {},
      "route:/system": {
        metrics: {
          Enabled: Object.values(features).filter(Boolean).length,
          Features: Object.keys(features).length,
        },
      },
    };

    return tiles.map(tile => {
      const patch = patches[tile.id];
      if (!patch) return tile;
      return { ...tile, ...patch, metrics: { ...tile.metrics, ...patch.metrics } };
    });
  }, [info.data, jobs.data, feeds.data, connectors.data, cases.data, alerts.data, bookmarks.data, decay.data, capabilities.data, analytics.data, attackCoverage.data, tiles]);
}

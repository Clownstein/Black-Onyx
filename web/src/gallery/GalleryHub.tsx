import React, { Suspense, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { useUser } from "../user_context";
import { isAdmin, isOperational, visibleFor } from "../rbac";
import { BUILTIN_TILES } from "./tile_registry";
import { GALLERY_SECTIONS, GallerySection, GalleryTile, UserSite } from "./types";
import { useTileMetrics } from "./tile_metrics";
import { AddSiteForm, siteToTile, useDeleteSite, useSites } from "./sites";
import { CredentialPanel } from "./CredentialPanel";
import { EmbeddedSitePanel } from "./EmbeddedSitePanel";
import { DEFAULT_FILTER, FilterPanel, GalleryFilterState, filterIsActive, matchesFilter } from "./FilterPanel";
import { GalleryTileCard } from "./GalleryTileCard";
import { A11yTileLinks } from "./A11yTileLinks";
import { useCanvasSupport } from "./useCanvasSupport";
import { BrandLogo } from "../BrandLogo";

// three.js/@react-three pull in a ~1MB bundle — code-split it into its own
// chunk so every other route (and users who never open the gallery, or who
// stay in list view) never pays for it.
const GalleryScene = React.lazy(() => import("./Scene").then(module => ({ default: module.GalleryScene })));

const VIEW_MODE_KEY = "blackonyx_gallery_mode";
type ViewMode = "canvas" | "list";

/**
 * Canvas is the default: the immersive drum *is* the hub, and a first-time
 * visitor landing on a flat card grid never sees the feature at all. List
 * mode remains a first-class, explicitly-chosen mode (and the automatic
 * fallback whenever useCanvasSupport says WebGL/motion rules forbid canvas).
 */
function loadViewMode(): ViewMode {
  try {
    return localStorage.getItem(VIEW_MODE_KEY) === "list" ? "list" : "canvas";
  } catch {
    return "canvas";
  }
}

/**
 * Immersive gallery hub: a full-viewport void owning the whole screen, with
 * floating chrome anchored to the edges (bare logo top-left, account
 * top-right, view toggle bottom-left, section pills bottom-centre, filter
 * bottom-right) over either the R3F canvas or the list/grid.
 *
 * This route is rendered OUTSIDE the classic sidebar shell (see main.tsx) —
 * the sidebar would box it into a column and defeat the immersive layout.
 * The classic shell is always one click away via the logo, and the list view
 * remains the permanent, mandatory escape hatch for power workflows.
 */
export function GalleryHub({ onLogout }: { onLogout?: () => void }) {
  const user = useUser();
  const navigate = useNavigate();
  const canvasSupport = useCanvasSupport();
  const [viewMode, setViewMode] = useState<ViewMode>(loadViewMode);
  const [filter, setFilter] = useState<GalleryFilterState>(DEFAULT_FILTER);
  const [filterOpen, setFilterOpen] = useState(false);
  const [addSiteOpen, setAddSiteOpen] = useState(false);
  // Track only the id, not a snapshot of the UserSite object — CredentialPanel
  // invalidates the ["sites"] query on every mutation, and deriving the live
  // object from that query below (rather than freezing one at open-time)
  // keeps the panel's has_credential/updated_at in sync after a save, rotate,
  // or credential removal without needing to close and reopen it.
  const [manageSiteId, setManageSiteId] = useState<string | null>(null);
  const [focusIndex, setFocusIndex] = useState<number | null>(null);
  // Multiple embedded popups can be open at once — each is independently
  // closable/draggable, so this is a list of site ids, not a single slot.
  const [embeddedPanelIds, setEmbeddedPanelIds] = useState<string[]>([]);
  const queryClient = useQueryClient();

  useEffect(() => {
    try { localStorage.setItem(VIEW_MODE_KEY, viewMode); } catch { /* storage unavailable */ }
  }, [viewMode]);

  const roleFilteredBuiltins = useMemo(
    () => BUILTIN_TILES.filter(tile => visibleFor(user.role, tile.href)),
    [user.role],
  );
  const metricTiles = useTileMetrics(roleFilteredBuiltins, user.role);
  const sitesQuery = useSites();
  const deleteSite = useDeleteSite();
  const siteTiles = useMemo(() => (sitesQuery.data || []).map(siteToTile), [sitesQuery.data]);
  const allTiles = useMemo(() => [...metricTiles, ...siteTiles], [metricTiles, siteTiles]);
  const filteredTiles = useMemo(() => allTiles.filter(tile => matchesFilter(tile, filter)), [allTiles, filter]);

  const canUseCanvas = canvasSupport.ready && canvasSupport.supported;
  const showCanvas = viewMode === "canvas" && canUseCanvas;
  const sitesEmpty = filter.section === "sites" && siteTiles.length === 0;
  const manageSite = useMemo(
    () => (sitesQuery.data || []).find(item => item.site_id === manageSiteId) || null,
    [sitesQuery.data, manageSiteId],
  );
  const embeddedSites = useMemo(
    () => embeddedPanelIds
      .map(id => (sitesQuery.data || []).find(site => site.site_id === id))
      .filter((site): site is UserSite => Boolean(site)),
    [sitesQuery.data, embeddedPanelIds],
  );

  function openManage(siteId?: string) {
    if (siteId) setManageSiteId(siteId);
  }

  function openEmbeddedPanel(siteId?: string) {
    if (!siteId) return;
    setEmbeddedPanelIds(current => (current.includes(siteId) ? current : [...current, siteId]));
  }

  function closeEmbeddedPanel(siteId: string) {
    setEmbeddedPanelIds(current => current.filter(id => id !== siteId));
  }

  function handleSiteProbed(updated: UserSite) {
    // Patch the cache in place rather than invalidating — an invalidate here
    // would refetch and briefly flash every open panel back to "unchecked"
    // while the list reloads.
    queryClient.setQueryData<UserSite[]>(["sites"], current =>
      (current || []).map(site => (site.site_id === updated.site_id ? updated : site)));
  }

  function handleNavigate(tile: GalleryTile) {
    if (tile.kind === "external") {
      if (tile.openMode === "embedded") { openEmbeddedPanel(tile.siteId); return; }
      if (tile.openMode === "launcher") { openManage(tile.siteId); return; }
      window.open(tile.href, "_blank", "noopener,noreferrer");
      return;
    }
    navigate(tile.href);
  }

  async function handleDeleteSite(siteId: string) {
    await deleteSite(siteId);
    setManageSiteId(null);
    closeEmbeddedPanel(siteId);
  }

  function selectSection(section: GallerySection) {
    setFilter(prev => ({ ...prev, section: prev.section === section ? "all" : section }));
  }

  useEffect(() => {
    if (filter.section === "all") { setFocusIndex(null); return; }
    const index = filteredTiles.findIndex(tile => tile.section === filter.section);
    setFocusIndex(index >= 0 ? index : null);
    // Re-focus only when the section changes, not on every tile-list update
    // (live metrics refresh every few seconds and must not yank the camera).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter.section]);

  const ctaIsSites = filter.section === "sites";
  const operational = isOperational(user.role);
  const visibleSections = GALLERY_SECTIONS.filter(section => section.key !== "control" || isAdmin(user.role));

  return (
    <div className={`gallery-hub${showCanvas ? " canvas-mode" : " list-mode"}`}>
      {/* Deep void backdrop + vignette. Purely decorative, sits under
          everything and never intercepts pointer events meant for the canvas. */}
      <div className="gallery-void" aria-hidden="true" />

      {/* Surface. Held back until detection has run so a canvas-preferring
          user never sees a flash of the grid before the canvas mounts. */}
      {!canvasSupport.ready ? (
        <div className="gallery-surface gallery-surface-pending" aria-hidden="true" />
      ) : showCanvas ? (
        <>
          {/* The gallery repeats its tile set to fill an endless wall, so an
              empty set has nothing to repeat — it would render as a blank
              void with no way back. Fall through to the DOM empty state. */}
          {filteredTiles.length ? (
            <Suspense fallback={<div className="gallery-surface gallery-canvas-loading">Loading immersive view…</div>}>
              <GalleryScene
                tiles={filteredTiles}
                reducedMotion={canvasSupport.reducedMotion}
                documentVisible={canvasSupport.documentVisible}
                onNavigate={handleNavigate}
                focusIndex={focusIndex}
              />
            </Suspense>
          ) : (
            <div className="gallery-surface gallery-canvas-empty">
              {sitesEmpty ? (
                <div className="gallery-empty gallery-empty-sites">
                  <p>Pin SIEM, EDR, and vendor consoles here.</p>
                  <button type="button" onClick={() => setAddSiteOpen(true)}>+ Add site</button>
                </div>
              ) : (
                <div className="gallery-empty">
                  <p>No tiles match the current filter.</p>
                  <button type="button" className="secondary" onClick={() => setFilter(DEFAULT_FILTER)}>Clear filter</button>
                </div>
              )}
            </div>
          )}
          <A11yTileLinks
            tiles={filteredTiles}
            onOpenLauncher={(tile) => openManage(tile.siteId)}
            onOpenEmbedded={(tile) => openEmbeddedPanel(tile.siteId)}
          />
        </>
      ) : (
        <div className="gallery-surface gallery-list-scroll">
          <div className="gallery-grid">
            {filteredTiles.length ? filteredTiles.map(tile => (
              <GalleryTileCard
                key={tile.id}
                tile={tile}
                onOpenLauncher={(t) => openManage(t.siteId)}
                onOpenEmbedded={(t) => openEmbeddedPanel(t.siteId)}
                onManage={(t) => openManage(t.siteId)}
              />
            )) : sitesEmpty ? (
              <div className="gallery-empty gallery-empty-sites">
                <p>Pin SIEM, EDR, and vendor consoles here.</p>
                <button type="button" onClick={() => setAddSiteOpen(true)}>+ Add site</button>
              </div>
            ) : (
              <div className="gallery-empty">
                <p>No tiles match the current filter.</p>
                <button type="button" className="secondary" onClick={() => setFilter(DEFAULT_FILTER)}>Clear filter</button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Phantom-style chrome: bare transparent mark top-left; view / sections /
          filter anchored along the bottom edge so the curved wall owns the frame. */}
      <Link to="/dashboard" className="gallery-logo" aria-label="Exit immersive gallery to the classic dashboard">
        <BrandLogo variant="lockup" />
      </Link>

      <div className="gallery-account-cluster">
        <div className="gallery-cta">
          {ctaIsSites ? (
            <button type="button" onClick={() => setAddSiteOpen(true)}>+ Add site</button>
          ) : operational ? (
            <Link className="button" to="/chat">Ask chat</Link>
          ) : (
            <Link className="button" to="/cases">New case</Link>
          )}
        </div>
        <div className="gallery-account">
          <span className="avatar" aria-hidden="true">{user.display_name.slice(0, 1).toUpperCase()}</span>
          <div className="gallery-account-copy">
            <b>{user.display_name}</b><small>{user.role}</small>
          </div>
          {onLogout && <button type="button" className="ghost gallery-logout" onClick={onLogout}>Log out</button>}
        </div>
      </div>

      {canUseCanvas && (
        <div className="gallery-view-toggle" role="group" aria-label="Gallery view">
          <button type="button" aria-pressed={viewMode === "canvas"} className={viewMode === "canvas" ? "active" : ""} onClick={() => setViewMode("canvas")}>Gallery</button>
          <button type="button" aria-pressed={viewMode === "list"} className={viewMode === "list" ? "active" : ""} onClick={() => setViewMode("list")}>List</button>
        </div>
      )}

      <div className="gallery-section-pill" role="group" aria-label="Gallery sections">
        {visibleSections.map(section => (
          <button
            key={section.key}
            type="button"
            aria-pressed={filter.section === section.key}
            className={filter.section === section.key ? "active" : ""}
            onClick={() => selectSection(section.key)}
          >
            {section.label}
          </button>
        ))}
      </div>

      <div className="gallery-filter-cluster">
        <button
          type="button"
          className={`gallery-pill gallery-filter-toggle${filterIsActive(filter) ? " active" : ""}`}
          aria-expanded={filterOpen}
          onClick={() => setFilterOpen(open => !open)}
        >
          Filter{filterIsActive(filter) ? " •" : ""}
        </button>
        <FilterPanel open={filterOpen} filter={filter} onChange={setFilter} onClose={() => setFilterOpen(false)} />
      </div>

      {addSiteOpen && (
        <div className="gallery-modal-overlay" onClick={() => setAddSiteOpen(false)}>
          <div className="gallery-modal-body" onClick={event => event.stopPropagation()}>
            <AddSiteForm onCreated={() => setAddSiteOpen(false)} onCancel={() => setAddSiteOpen(false)} />
          </div>
        </div>
      )}

      {manageSite && (
        <div className="gallery-modal-overlay" onClick={() => setManageSiteId(null)}>
          <div className="gallery-modal-body" onClick={event => event.stopPropagation()}>
            <CredentialPanel site={manageSite} onClose={() => setManageSiteId(null)} onDeleteSite={handleDeleteSite} />
          </div>
        </div>
      )}

      {/* No shared overlay/backdrop — each panel floats independently so the
          rest of the hub (and any other open panel) stays fully usable. */}
      {embeddedSites.map((site, index) => (
        <EmbeddedSitePanel
          key={site.site_id}
          site={site}
          index={index}
          onClose={closeEmbeddedPanel}
          onProbed={handleSiteProbed}
        />
      ))}
    </div>
  );
}

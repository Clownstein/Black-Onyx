import React, { useRef, useState } from "react";
import { api } from "../api";
import { UserSite } from "./types";

/**
 * A floating, non-blocking window for a pinned site's "embedded" open mode.
 *
 * Deliberately NOT the `.gallery-modal-overlay`/`.gallery-modal-body` pattern
 * used elsewhere in the gallery (Add Site, CredentialPanel) — those are full
 * backdrops that block interaction with the rest of the page until dismissed,
 * which is the opposite of what an embedded popup is for: the analyst asked
 * to still be able to use the rest of the app while it's open. So this has no
 * backdrop element at all, just a draggable card positioned in its own corner
 * of the viewport, and `GalleryHub` can have several of these open at once.
 */

export interface EmbeddedPanelState {
  site: UserSite;
  /** Cascade offset so multiple panels don't stack exactly on top of each other. */
  index: number;
}

const PANEL_WIDTH = 480;
const PANEL_HEIGHT = 520;
const CASCADE_STEP = 32;

export function EmbeddedSitePanel({
  site, index, onClose, onProbed,
}: {
  site: UserSite;
  index: number;
  onClose: (siteId: string) => void;
  /** Called after an on-demand re-probe with the refreshed site record. */
  onProbed: (site: UserSite) => void;
}) {
  const base = { right: 24 + index * CASCADE_STEP, bottom: 24 + index * CASCADE_STEP };
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [reprobing, setReprobing] = useState(false);
  const [probeError, setProbeError] = useState("");
  const drag = useRef<{ startX: number; startY: number; baseX: number; baseY: number } | null>(null);

  function onDragStart(event: React.PointerEvent<HTMLDivElement>) {
    // Buttons in the title bar (close, open-in-new-tab) must not start a drag.
    if ((event.target as HTMLElement).closest("button, a")) return;
    (event.target as HTMLElement).setPointerCapture(event.pointerId);
    drag.current = { startX: event.clientX, startY: event.clientY, baseX: offset.x, baseY: offset.y };
  }
  function onDragMove(event: React.PointerEvent<HTMLDivElement>) {
    if (!drag.current) return;
    setOffset({
      x: drag.current.baseX + (event.clientX - drag.current.startX),
      y: drag.current.baseY + (event.clientY - drag.current.startY),
    });
  }
  function onDragEnd() {
    drag.current = null;
  }

  async function reprobe() {
    setReprobing(true);
    setProbeError("");
    try {
      const refreshed = await api<UserSite>(`/sites/${site.site_id}/probe`, { method: "POST" });
      onProbed(refreshed);
    } catch (error) {
      // Without this the rejection escaped the click handler as an unhandled
      // promise rejection and the button just returned to its idle label,
      // leaving no way to tell a failed check from a completed one.
      setProbeError(error instanceof Error ? error.message : "Could not re-check this site");
    } finally {
      setReprobing(false);
    }
  }

  return (
    <div
      className="embedded-site-panel"
      style={{
        width: PANEL_WIDTH,
        height: PANEL_HEIGHT,
        right: base.right,
        bottom: base.bottom,
        // translate() is in viewport coordinates and is independent of the
        // right/bottom anchoring above, so neither axis is negated: +y from a
        // downward drag must move the panel down. Negating y made vertical
        // dragging run backwards and let the panel be pushed off the top of
        // the screen, taking its only close button with it.
        transform: offset.x || offset.y ? `translate(${offset.x}px, ${offset.y}px)` : undefined,
      }}
      role="dialog"
      aria-label={`${site.name} (embedded)`}
    >
      <div
        className="embedded-site-panel-titlebar"
        onPointerDown={onDragStart}
        onPointerMove={onDragMove}
        onPointerUp={onDragEnd}
      >
        {site.favicon_url && <img className="embedded-site-panel-favicon" src={site.favicon_url} alt="" />}
        <span className="embedded-site-panel-title" title={site.name}>{site.name}</span>
        <a href={site.url} target="_blank" rel="noopener noreferrer" className="embedded-site-panel-action" aria-label="Open in a new tab">⤢</a>
        <button type="button" className="embedded-site-panel-action" onClick={() => onClose(site.site_id)} aria-label="Close">✕</button>
      </div>
      <div className="embedded-site-panel-body">
        {site.frameable === true ? (
          <iframe
            src={site.url}
            title={site.name}
            sandbox="allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox"
          />
        ) : (
          <div className="embedded-site-panel-fallback">
            <p>
              {site.frameable === false
                ? (site.frameable_error || "This site can't be embedded — its security headers block framing.")
                : "This site hasn't been checked for embeddability yet."}
            </p>
            <div className="actions">
              <a className="button" href={site.url} target="_blank" rel="noopener noreferrer">Open in a new tab</a>
              <button type="button" className="secondary" disabled={reprobing} onClick={reprobe}>
                {reprobing ? "Checking…" : "Check again"}
              </button>
            </div>
            {probeError && <div role="alert" className="alert error">{probeError}</div>}
          </div>
        )}
      </div>
    </div>
  );
}

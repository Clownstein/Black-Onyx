import React, { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { UserSite } from "./types";

/**
 * A floating, non-blocking window for a pinned site's "embedded" open mode.
 *
 * Deliberately NOT the `.gallery-modal-overlay`/`.gallery-modal-body` pattern
 * used elsewhere in the gallery (Add Site, CredentialPanel) those are full
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

function panelSize() {
  return {
    width: Math.min(PANEL_WIDTH, Math.max(0, window.innerWidth - 16)),
    height: Math.min(PANEL_HEIGHT, Math.max(0, window.innerHeight - 16)),
  };
}

function initialPosition(index: number) {
  const size = panelSize();
  return {
    left: Math.max(8, window.innerWidth - size.width - 24 - index * CASCADE_STEP),
    top: Math.max(8, window.innerHeight - size.height - 24 - index * CASCADE_STEP),
  };
}

function clampPosition(left: number, top: number) {
  const size = panelSize();
  return {
    left: Math.min(Math.max(8, left), Math.max(8, window.innerWidth - size.width - 8)),
    top: Math.min(Math.max(8, top), Math.max(8, window.innerHeight - size.height - 8)),
  };
}

export function EmbeddedSitePanel({
  site, index, onClose, onProbed,
}: {
  site: UserSite;
  index: number;
  onClose: (siteId: string) => void;
  /** Called after an on-demand re-probe with the refreshed site record. */
  onProbed: (site: UserSite) => void;
}) {
  const [position, setPosition] = useState(() => initialPosition(index));
  const [reprobing, setReprobing] = useState(false);
  const [probeError, setProbeError] = useState("");
  const drag = useRef<{ startX: number; startY: number; left: number; top: number } | null>(null);

  useEffect(() => {
    const resize = () => setPosition(current => clampPosition(current.left, current.top));
    window.addEventListener("resize", resize);
    resize();
    return () => window.removeEventListener("resize", resize);
  }, []);

  function onDragStart(event: React.PointerEvent<HTMLDivElement>) {
    // Buttons in the title bar (close, open-in-new-tab) must not start a drag.
    if ((event.target as HTMLElement).closest("button, a")) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    drag.current = { startX: event.clientX, startY: event.clientY, left: position.left, top: position.top };
  }
  function onDragMove(event: React.PointerEvent<HTMLDivElement>) {
    if (!drag.current) return;
    setPosition(clampPosition(
      drag.current.left + (event.clientX - drag.current.startX),
      drag.current.top + (event.clientY - drag.current.startY),
    ));
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
      style={{ ...panelSize(), left: position.left, top: position.top }}
      role="dialog"
      aria-label={`${site.name} (embedded)`}
    >
      <div
        className="embedded-site-panel-titlebar"
        onPointerDown={onDragStart}
        onPointerMove={onDragMove}
        onPointerUp={onDragEnd}
        onPointerCancel={onDragEnd}
      >
        {site.favicon_url && <img className="embedded-site-panel-favicon" src={site.favicon_url} alt="" />}
        <span className="embedded-site-panel-title" title={site.name}>{site.name}</span>
        <a href={site.login_url || site.url} target="_blank" rel="noopener noreferrer" className="embedded-site-panel-action" aria-label="Open in a new tab">⤢</a>
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
              <a className="button" href={site.login_url || site.url} target="_blank" rel="noopener noreferrer">Open in a new tab</a>
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

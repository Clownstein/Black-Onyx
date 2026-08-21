import React from "react";
import { Link } from "react-router-dom";
import { GalleryTile } from "./types";

function isExternalHref(href: string): boolean {
  return /^https?:\/\//i.test(href);
}

/**
 * Parallel accessibility DOM layer for canvas mode: a real, focusable
 * `<a>`/`<Link>` per tile, visually hidden (clipped, not `display:none`, so
 * screen readers and Tab order still reach it) rather than absent. The
 * canvas has no per-tile DOM node for assistive tech to land on, so this is
 * what keeps every tile reachable without a mouse even when the immersive
 * view is active — the list/grid view (which renders real, visible anchors
 * via GalleryTileCard) remains the primary accessible surface.
 */
export function A11yTileLinks({ tiles, onOpenLauncher, onOpenEmbedded }: {
  tiles: GalleryTile[];
  onOpenLauncher?: (tile: GalleryTile) => void;
  /** Keyboard/assistive-tech equivalent of the canvas click path for
   * open_mode "embedded" — without it this layer fell through to a plain
   * new-tab anchor, so keyboard users could never reach the in-app panel. */
  onOpenEmbedded?: (tile: GalleryTile) => void;
}) {
  return (
    <nav className="sr-only gallery-a11y-links" aria-label="Gallery tiles (accessible list)">
      <ul>
        {tiles.map(tile => {
          const external = isExternalHref(tile.href);
          const launcherMode = tile.kind === "external" && tile.openMode === "launcher";
          const embeddedMode = tile.kind === "external" && tile.openMode === "embedded" && !!onOpenEmbedded;
          return (
            <li key={tile.id}>
              {launcherMode ? (
                <a data-tile-id={tile.id} href={tile.href} onClick={(event) => { event.preventDefault(); onOpenLauncher?.(tile); }}>
                  {tile.title}
                </a>
              ) : embeddedMode ? (
                <a data-tile-id={tile.id} href={tile.href} onClick={(event) => { event.preventDefault(); onOpenEmbedded!(tile); }}>
                  {tile.title}
                </a>
              ) : external ? (
                <a data-tile-id={tile.id} href={tile.href} target="_blank" rel="noopener noreferrer">{tile.title}</a>
              ) : (
                <Link data-tile-id={tile.id} to={tile.href}>{tile.title}</Link>
              )}
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

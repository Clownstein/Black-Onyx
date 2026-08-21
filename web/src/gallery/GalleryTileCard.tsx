import React from "react";
import { Link } from "react-router-dom";
import { GalleryTile } from "./types";

function isExternalHref(href: string): boolean {
  return /^https?:\/\//i.test(href);
}

const PREVIEW_GLYPH: Record<GalleryTile["preview"], string> = {
  metric: "◆",
  heatmap: "▦",
  list: "☰",
  favicon: "◎",
  color: "●",
};

/** One tile as a real anchor — used by the classic list/grid view directly,
 * and by A11yTileLinks as the visually-hidden parallel DOM layer over the
 * canvas view. Every tile must render a real `<a href>` regardless of which
 * view is active. The optional "Manage login" control is rendered as a
 * sibling of the anchor, not nested inside it — nesting a <button> inside an
 * <a> is invalid HTML and breaks assistive-tech interaction. */
export function GalleryTileCard({ tile, onOpenLauncher, onOpenEmbedded, onSelect, onManage }: {
  tile: GalleryTile;
  onOpenLauncher?: (tile: GalleryTile) => void;
  /** External tiles with open_mode "embedded": open the floating in-app panel
   * instead of navigating away. Without this the list/grid view silently fell
   * through to the plain new-tab anchor, so embedded mode only ever worked in
   * canvas view, which routes clicks through GalleryHub.handleNavigate. */
  onOpenEmbedded?: (tile: GalleryTile) => void;
  onSelect?: (tile: GalleryTile) => void;
  /** External tiles only: open the saved-login manage panel without
   * navigating away (independent of open_mode / launcher handling). */
  onManage?: (tile: GalleryTile) => void;
}) {
  const external = isExternalHref(tile.href);
  const launcherMode = tile.kind === "external" && tile.openMode === "launcher";
  const embeddedMode = tile.kind === "external" && tile.openMode === "embedded" && !!onOpenEmbedded;

  const mainContent = (
    <>
      <div className="gallery-tile-strip" data-badge={tile.badge || ""} />
      <div className="gallery-tile-head">
        {tile.faviconUrl
          ? <img className="gallery-tile-favicon" src={tile.faviconUrl} alt="" onError={(e) => { (e.currentTarget as HTMLImageElement).style.visibility = "hidden"; }} />
          : <span className="gallery-tile-glyph" aria-hidden="true">{tile.glyph || PREVIEW_GLYPH[tile.preview]}</span>}
        {tile.badge && <span className={`gallery-tile-badge badge-${tile.badge.toLowerCase()}`}>{tile.badge}</span>}
      </div>
      <div className="gallery-tile-body">
        <h3>{tile.title}</h3>
        <p>{tile.subtitle}</p>
      </div>
      {tile.metrics && Object.keys(tile.metrics).length > 0 && (
        <dl className="gallery-tile-metrics">
          {Object.entries(tile.metrics).map(([label, value]) => (
            <div key={label}><dt>{label}</dt><dd>{value}</dd></div>
          ))}
        </dl>
      )}
      {tile.tags && tile.tags.length > 0 && (
        <div className="gallery-tile-tags">{tile.tags.slice(0, 4).map(tag => <span key={tag}>{tag}</span>)}</div>
      )}
    </>
  );

  const className = `gallery-tile gallery-tile-${tile.kind}`;
  let anchor: React.ReactNode;
  if (launcherMode) {
    anchor = (
      <a
        className={className}
        data-tile-id={tile.id}
        href={tile.href}
        onClick={(event) => { event.preventDefault(); onOpenLauncher?.(tile); onSelect?.(tile); }}
      >
        {mainContent}
      </a>
    );
  } else if (embeddedMode) {
    anchor = (
      <a
        className={className}
        data-tile-id={tile.id}
        href={tile.href}
        onClick={(event) => { event.preventDefault(); onOpenEmbedded!(tile); onSelect?.(tile); }}
      >
        {mainContent}
      </a>
    );
  } else if (external) {
    anchor = (
      <a className={className} data-tile-id={tile.id} href={tile.href} target="_blank" rel="noopener noreferrer" onClick={() => onSelect?.(tile)}>
        {mainContent}
      </a>
    );
  } else {
    anchor = (
      <Link className={className} data-tile-id={tile.id} to={tile.href} onClick={() => onSelect?.(tile)}>
        {mainContent}
      </Link>
    );
  }

  // Embedded tiles keep the manage control: unlike launcher mode (where the
  // panel *is* the credential manager), the embedded panel shows the site, so
  // a saved login still needs somewhere to be revealed or rotated from.
  const showManage = tile.kind === "external" && onManage && !launcherMode;
  if (!showManage) return <>{anchor}</>;
  return (
    <div className="gallery-tile-shell">
      {anchor}
      <button type="button" className="gallery-tile-manage secondary compact" onClick={() => onManage!(tile)}>
        Manage login
      </button>
    </div>
  );
}

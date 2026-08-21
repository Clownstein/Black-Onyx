import React from "react";
import { GallerySection, GalleryTile } from "./types";

export interface GalleryFilterState {
  section: GallerySection | "all";
  origin: "all" | "builtin" | "external";
  status: "all" | "alerts" | "empty" | "saved";
  query: string;
}

export const DEFAULT_FILTER: GalleryFilterState = { section: "all", origin: "all", status: "all", query: "" };

export function filterIsActive(filter: GalleryFilterState): boolean {
  return filter.section !== "all" || filter.origin !== "all" || filter.status !== "all" || filter.query.trim() !== "";
}

/** Filtering dims/hides tiles client-side over the already-loaded tile
 * list — it never reloads the world or triggers a network round-trip. */
export function matchesFilter(tile: GalleryTile, filter: GalleryFilterState): boolean {
  if (filter.section !== "all" && tile.section !== filter.section) return false;
  if (filter.origin === "builtin" && tile.kind !== "builtin") return false;
  if (filter.origin === "external" && tile.kind !== "external") return false;
  if (filter.status === "alerts" && tile.badge !== "ALERTS") return false;
  if (filter.status === "saved" && !tile.hasCredential) return false;
  if (filter.status === "empty" && tile.badge !== "EMPTY") return false;
  if (filter.query.trim()) {
    const needle = filter.query.trim().toLowerCase();
    const haystack = [tile.title, tile.subtitle, tile.href, ...(tile.tags || [])].join(" ").toLowerCase();
    if (!haystack.includes(needle)) return false;
  }
  return true;
}

/** Non-modal floating filter panel (FILTER pill target). Section/Origin/
 * Status/text-match, per the doc's filter model. */
export function FilterPanel({ open, filter, onChange, onClose }: {
  open: boolean;
  filter: GalleryFilterState;
  onChange: (next: GalleryFilterState) => void;
  onClose: () => void;
}) {
  if (!open) return null;
  return (
    <div className="gallery-filter-panel card">
      <div className="section-head">
        <div><span className="section-kicker">Gallery</span><h2>Filter</h2></div>
        <button type="button" className="secondary compact" onClick={onClose} aria-label="Close filter panel">Close</button>
      </div>
      <label>Search<input
        value={filter.query}
        onChange={event => onChange({ ...filter, query: event.target.value })}
        placeholder="Title, subtitle, URL, or tag"
      /></label>
      <div className="field-row">
        <label>Section<select
          value={filter.section}
          onChange={event => onChange({ ...filter, section: event.target.value as GalleryFilterState["section"] })}
        >
          <option value="all">All sections</option>
          <option value="investigate">Investigate</option>
          <option value="intelligence">Intelligence</option>
          <option value="operations">Operations</option>
          <option value="sites">Sites</option>
          <option value="control">Control</option>
        </select></label>
        <label>Origin<select
          value={filter.origin}
          onChange={event => onChange({ ...filter, origin: event.target.value as GalleryFilterState["origin"] })}
        >
          <option value="all">Built-in and sites</option>
          <option value="builtin">Built-in pages only</option>
          <option value="external">Saved sites only</option>
        </select></label>
      </div>
      <label>Status<select
        value={filter.status}
        onChange={event => onChange({ ...filter, status: event.target.value as GalleryFilterState["status"] })}
      >
        <option value="all">Any status</option>
        <option value="alerts">Has alerts</option>
        <option value="saved">Has a saved login</option>
        <option value="empty">Empty</option>
      </select></label>
      <div className="actions">
        <button type="button" className="secondary" onClick={() => onChange(DEFAULT_FILTER)}>Reset</button>
      </div>
    </div>
  );
}

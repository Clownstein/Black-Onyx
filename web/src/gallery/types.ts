export type GallerySection = "investigate" | "intelligence" | "operations" | "control" | "sites";

export type GalleryBadge = "LIVE" | "ALERTS" | "EMPTY" | "SAVED" | "LOCKED";

export type GalleryPreview = "metric" | "heatmap" | "list" | "favicon" | "color";

export type SiteOpenMode = "new_tab" | "embedded" | "launcher";

export interface GalleryTile {
  /** Stable slug: "route:/iocs" for built-in tiles, "site:{site_id}" for external. */
  id: string;
  kind: "builtin" | "external";
  href: string;
  section: GallerySection;
  title: string;
  subtitle: string;
  /** Two-letter glyph reused from navigationGroups for built-in tiles. */
  glyph?: string;
  badge?: GalleryBadge;
  preview: GalleryPreview;
  metrics?: Record<string, string | number>;
  /** Optional sparkline series for tile preview metrics (analytics only). */
  sparkline?: number[];
  // Role visibility is not tracked per-tile here — see rbac.ts's visibleFor,
  // the single source of truth used by both the sidebar nav and the gallery.
  openMode?: SiteOpenMode;
  faviconUrl?: string;
  siteId?: string;
  hasCredential?: boolean;
  tags?: string[];
  createdAt?: string;
  updatedAt?: string;
}

export interface UserSite {
  site_id: string;
  name: string;
  url: string;
  login_url: string | null;
  section: GallerySection;
  tags: string[];
  open_mode: SiteOpenMode;
  favicon_url: string | null;
  has_credential: boolean;
  /** Only meaningful when open_mode is "embedded" — null until probed once. */
  frameable: boolean | null;
  frameable_checked_at: string | null;
  frameable_error: string | null;
  created_at: string;
  updated_at: string;
}

export const GALLERY_SECTIONS: { key: GallerySection; label: string }[] = [
  { key: "investigate", label: "Investigate" },
  { key: "intelligence", label: "Intelligence" },
  { key: "operations", label: "Operations" },
  { key: "sites", label: "Sites" },
  { key: "control", label: "Control" },
];

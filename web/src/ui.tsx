import React, { ReactNode, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

/**
 * In-page header. The "Black Onyx WORKSPACE" eyebrow that used to sit above
 * every title is gone: it was identical on all 20 pages, so it carried no
 * information while taking a line at the top of each one. Location is now the
 * top bar's breadcrumb, which states the actual section and page.
 */
export function Heading({ title, subtitle, actions, kicker }: { title: string; subtitle: string; actions?: ReactNode; kicker?: string }) {
  return <header className="page-head"><div className="page-head-copy">{kicker && <span className="page-kicker">{kicker}</span>}<h1>{title}</h1><p>{subtitle}</p></div>{actions&&<div className="page-actions">{actions}</div>}</header>;
}

export function ErrorState({ error }: { error: unknown }) {
  if (!error) return null;
  let text = "";
  if (error instanceof Error) text = error.message;
  else if (typeof error === "string") text = error;
  else {
    try { text = JSON.stringify(error); } catch { text = "Request failed"; }
  }
  if (!text || text.includes("[object Object]")) text = "Request failed";
  return <div role="alert" className="alert error">{text}</div>;
}

export function Notice({ children }: { children: ReactNode }) {
  return <div role="status" aria-live="polite" className="alert">{children}</div>;
}

/** Collapsed escape hatch so the exact API response stays reachable under any rendered view. */
export function RawJson({ data, label = "Raw JSON" }: { data: unknown; label?: string }) {
  if (data == null) return null;
  return <details className="raw-json"><summary>{label}</summary><pre className="data">{JSON.stringify(data, null, 2)}</pre></details>;
}

export function humanizeLabel(key: string) {
  const words = key.replace(/[_.-]+/g, " ").trim();
  const spaced = words.replace(/\b(ioc|iocs|ip|url|urls|cve|cves|id|ids|md5|sha1|sha256|sha512|asn|asns|ocr|cidr|gps|exif|ner|jarm|cpe|cpes|gpg|ssh|irc|rss|taxii|llm|api|misp|stix|yara|sigma|rag|mfa|totp|siem|edr|soc|ttp|ttps|dns|tls|ssl|http|https|json|csv|xml|pcap|utc)\b/gi, match => match.toUpperCase());
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/**
 * Thousands-separated integers for counts and totals. An unseparated "239281"
 * is genuinely hard to read at a glance, and glanceability is the entire point
 * of a KPI tile. Non-numeric values (placeholders like "—", version strings)
 * pass through untouched.
 */
export function formatCount(value: unknown): React.ReactNode {
  if (typeof value === "number" && Number.isFinite(value)) return value.toLocaleString();
  if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) {
    return Number(value).toLocaleString();
  }
  return value as React.ReactNode;
}

export function formatWhen(value: unknown) {
  if (!value) return "—";
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export type KeyValueItem = { label: string; value: ReactNode; hint?: ReactNode; wide?: boolean };

/** Label/value grid used wherever an object was previously dumped as JSON. */
export function KeyValues({ items, columns }: { items: KeyValueItem[]; columns?: number }) {
  const visible = items.filter(item => item.value !== undefined && item.value !== null && item.value !== "");
  if (!visible.length) return null;
  return <dl className="kv-grid" style={columns ? { gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` } : undefined}>
    {visible.map(item => <div key={item.label} className={item.wide ? "kv-item wide" : "kv-item"}>
      <dt>{item.label}</dt><dd>{item.value}{item.hint && <small>{item.hint}</small>}</dd>
    </div>)}
  </dl>;
}

/** Compact inline counters for job details, poll outcomes, and summaries. */
export function StatRow({ items }: { items: { label: string; value: ReactNode; tone?: "ok" | "warn" | "bad" }[] }) {
  if (!items.length) return null;
  return <ul className="stat-row">{items.map(item => <li key={item.label} className={item.tone ? `tone-${item.tone}` : undefined}><span>{item.label}</span><strong>{item.value}</strong></li>)}</ul>;
}

export function Chips({ items, max = 60, tone }: { items: (string | number)[]; max?: number; tone?: string }) {
  if (!items.length) return <span className="muted">—</span>;
  const shown = items.slice(0, max);
  return <span className="chip-list">
    {shown.map((item, index) => <span className={tone ? `chip ${tone}` : "chip"} key={`${item}-${index}`} title={String(item)}>{String(item)}</span>)}
    {items.length > shown.length && <span className="chip more">+{items.length - shown.length} more</span>}
  </span>;
}

export function ScoreBar({ value, label }: { value: number; label?: string }) {
  const ratio = Math.max(0, Math.min(1, Number(value) || 0));
  const tone = ratio >= 0.7 ? "ok" : ratio >= 0.3 ? "warn" : "bad";
  return <span className="score-bar" title={label || `${(ratio * 100).toFixed(0)}%`}>
    <span className={`score-fill ${tone}`} style={{ width: `${ratio * 100}%` }} />
    <b>{ratio.toFixed(2)}</b>
  </span>;
}

export type Column<T> = {
  key: string;
  label: string;
  render?: (row: T) => ReactNode;
  width?: string;
  /** Keep long values (hashes, URLs) on one ellipsized line instead of a tall cell. */
  clip?: boolean;
  /** Never wrap this column, e.g. timestamps. */
  nowrap?: boolean;
  /** Enable click-to-sort on this column (uses rendered text / raw field). */
  sortable?: boolean;
  sortValue?: (row: T) => string | number;
};

/** Sortable table with optional toolbar search/filter for list endpoints. */
export function DataTable<T extends Record<string, any>>({ columns, rows, rowKey, empty, searchable = false, searchPlaceholder = "Filter rows…" }: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string;
  empty?: ReactNode;
  searchable?: boolean;
  searchPlaceholder?: string;
}) {
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    let next = rows;
    if (needle) {
      next = rows.filter((row) => columns.some((column) => {
        const raw = column.render ? column.render(row) : row[column.key];
        const text = typeof raw === "string" || typeof raw === "number" ? String(raw) : JSON.stringify(row[column.key] ?? "");
        return text.toLowerCase().includes(needle);
      }));
    }
    if (!sortKey) return next;
    const column = columns.find((item) => item.key === sortKey);
    if (!column) return next;
    const sorted = [...next].sort((left, right) => {
      const lv = column.sortValue ? column.sortValue(left) : (left[column.key] ?? "");
      const rv = column.sortValue ? column.sortValue(right) : (right[column.key] ?? "");
      if (typeof lv === "number" && typeof rv === "number") return lv - rv;
      return String(lv).localeCompare(String(rv), undefined, { numeric: true, sensitivity: "base" });
    });
    return sortDir === "asc" ? sorted : sorted.reverse();
  }, [columns, query, rows, sortDir, sortKey]);

  if (!rows.length) return <>{empty}</>;
  return <div className="table-panel">
    {searchable && <div className="table-toolbar"><label>Search<input value={query} placeholder={searchPlaceholder} onChange={(e) => setQuery(e.target.value)} /></label><small className="muted">{filtered.length}/{rows.length}</small></div>}
    {!filtered.length ? <p className="muted">No rows match this filter.</p> : <div className="table-wrap"><table>
    <thead><tr>{columns.map(column => {
      const sortable = column.sortable !== false && (column.sortable || column.sortValue || typeof rows[0]?.[column.key] !== "undefined");
      const label = sortKey === column.key ? `${column.label} ${sortDir === "asc" ? "↑" : "↓"}` : column.label;
      return <th
        key={column.key}
        className={[column.nowrap ? "nowrap" : "", sortable ? "sortable" : ""].filter(Boolean).join(" ") || undefined}
        style={column.width ? { width: column.width } : undefined}
        onClick={sortable ? () => {
          if (sortKey === column.key) setSortDir((d) => d === "asc" ? "desc" : "asc");
          else { setSortKey(column.key); setSortDir("asc"); }
        } : undefined}
      >{label}</th>;
    })}</tr></thead>
    <tbody>{filtered.map((row, index) => <tr key={rowKey(row, index)}>{columns.map(column => {
      const content = column.render ? column.render(row) : (row[column.key] ?? "—");
      const classes = [column.clip ? "clip" : "", column.nowrap ? "nowrap" : ""].filter(Boolean).join(" ");
      const title = typeof content === "string" || typeof content === "number" ? String(content) : undefined;
      return <td key={column.key} className={classes || undefined}>
        {column.clip ? <span className="cell-clip" title={title}>{content}</span> : content}
      </td>;
    })}</tr>)}</tbody>
  </table></div>}
  </div>;
}

const PAYLOAD_META_KEYS = ["title", "source_file", "payload_type", "chunk_index", "total_chunks", "embedding_model", "embedding_type", "classification", "classification_score", "image_format", "image_width", "image_height", "image_hash", "capture_time", "camera_make", "camera_model", "ioc_status", "ioc_confidence", "ioc_decay_score", "ioc_first_seen", "ioc_last_seen", "case_id", "bookmarked", "indexed_at"];
const PAYLOAD_TEXT_KEYS = ["body_text", "ocr_text"];
const PAYLOAD_HIDDEN_KEYS = ["exif_data", "enrichment_data", "annotations", "messages", "code_snippets"];

/** Structured evidence payload viewer: metadata, text preview, then entity groups. */
export function PayloadView({ payload }: { payload: Record<string, any> }) {
  const meta: KeyValueItem[] = [];
  for (const key of PAYLOAD_META_KEYS) {
    const value = payload?.[key];
    if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) continue;
    meta.push({ label: humanizeLabel(key), value: typeof value === "boolean" ? (value ? "Yes" : "No") : String(value) });
  }
  const groups = Object.entries(payload || {})
    .filter(([key, value]) => !PAYLOAD_META_KEYS.includes(key) && !PAYLOAD_TEXT_KEYS.includes(key) && !PAYLOAD_HIDDEN_KEYS.includes(key) && Array.isArray(value) && value.length)
    .map(([key, value]) => ({ key, values: (value as any[]).map(item => typeof item === "string" ? item : JSON.stringify(item)) }));
  const scalars = Object.entries(payload || {})
    .filter(([key, value]) => !PAYLOAD_META_KEYS.includes(key) && !PAYLOAD_TEXT_KEYS.includes(key) && !PAYLOAD_HIDDEN_KEYS.includes(key) && !Array.isArray(value) && value !== null && value !== "" && typeof value !== "object")
    .map(([key, value]) => ({ label: humanizeLabel(key), value: String(value) }));
  const text = PAYLOAD_TEXT_KEYS.map(key => payload?.[key]).find(value => typeof value === "string" && value.trim());
  return <div className="payload-view">
    <KeyValues items={[...meta, ...scalars]} />
    {text && <div className="payload-text"><span className="section-kicker">Text</span><p>{String(text).slice(0, 2500)}</p></div>}
    {groups.length ? <div className="entity-groups">{groups.map(group => <div className="entity-group" key={group.key}>
      <span className="entity-group-label">{humanizeLabel(group.key)} <small>{group.values.length}</small></span>
      <Chips items={group.values} max={40} />
    </div>)}</div> : <p className="muted">No extracted entities in this item.</p>}
    <RawJson data={payload} label="Raw payload" />
  </div>;
}

export function EmptyState({ title, description, action, compact = false }: { title: string; description: string; action?: ReactNode; compact?: boolean }) {
  return <div className={`empty-state${compact ? " compact" : ""}`}><span className="empty-icon" aria-hidden="true">◇</span><div><strong>{title}</strong><p>{description}</p></div>{action}</div>;
}

export function ConfirmDialog({ label, expected, onConfirm }: { label: string; expected: string; onConfirm: () => Promise<void> | void }) {
  const [open, setOpen] = useState(false); const [value, setValue] = useState("");
  if (!open) return <button className="danger" onClick={() => setOpen(true)}>{label}</button>;
  return <div className="dialog" role="dialog" aria-modal="true" aria-labelledby={`confirm-${expected}`}>
    <h3 id={`confirm-${expected}`}>Confirm destructive action</h3>
    <p>Type <code>{expected}</code> to continue.</p>
    <label>Confirmation<input autoFocus value={value} onChange={event => setValue(event.target.value)} /></label>
    <div className="actions"><button className="ghost" onClick={() => { setOpen(false); setValue(""); }}>Cancel</button><button className="danger" disabled={value !== expected} onClick={async () => { await onConfirm(); setOpen(false); setValue(""); }}>Confirm</button></div>
  </div>;
}

export function downloadJson(filename: string, value: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url);
}

export type CollectionOption = { name: string; points_count?: number };

export function useCollections() {
  return useQuery({
    queryKey: ["collections"],
    queryFn: () => api<CollectionOption[]>("/collections"),
  });
}

/** Collection names from a /collections response, tolerating unexpected shapes. */
function collectionNames(data: unknown): string[] {
  if (!Array.isArray(data)) return [];
  return data
    .map((item) => (item && typeof item === "object" ? (item as CollectionOption).name : item))
    .filter((name): name is string => typeof name === "string" && name.length > 0);
}

/** Single-select collection dropdown backed by GET /collections. */
export function CollectionSelect({
  value,
  onChange,
  allowCustom = true,
  required = false,
  label = "Collection",
}: {
  value: string;
  onChange: (value: string) => void;
  allowCustom?: boolean;
  required?: boolean;
  label?: string;
}) {
  const collections = useCollections();
  const names = useMemo(() => collectionNames(collections.data), [collections.data]);
  const known = names.includes(value);
  return (
    <label>
      {label}
      <select value={known ? value : "__custom__"} onChange={(event) => {
        if (event.target.value === "__custom__") {
          if (allowCustom) onChange(value && !known ? value : "");
          return;
        }
        onChange(event.target.value);
      }} required={required && !allowCustom}>
        {!names.length && <option value="">No collections yet</option>}
        {names.map((name) => <option key={name} value={name}>{name}</option>)}
        {allowCustom && <option value="__custom__">Custom name…</option>}
      </select>
      {allowCustom && (!known || value === "") && (
        <input
          style={{ marginTop: ".45rem" }}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder="collection-name"
          required={required}
          pattern="^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
        />
      )}
    </label>
  );
}

/** Multi-select collection checklist for chat RAG targeting (full-width fieldset). */
export function CollectionMultiSelect({
  values,
  onChange,
  label = "RAG collections",
}: {
  values: string[];
  onChange: (values: string[]) => void;
  label?: string;
}) {
  const collections = useCollections();
  const names = collectionNames(collections.data);
  return (
    <fieldset className="collection-multi">
      <legend>{label}</legend>
      {!names.length && <p className="section-description">No collections available.</p>}
      <div className="toggle-grid">
        {names.map((name) => {
          const checked = values.includes(name);
          return (
            <label className="check setting-toggle" key={name}>
              <input
                type="checkbox"
                checked={checked}
                onChange={(event) => {
                  if (event.target.checked) onChange([...values, name]);
                  else onChange(values.filter((item) => item !== name));
                }}
              />
              {name}
            </label>
          );
        })}
      </div>
      <small>{values.length ? `${values.length} selected` : "None — RAG disabled for this message"}</small>
    </fieldset>
  );
}

/** Compact RAG collection picker for the chat composer toolbar. */
export function RagCollectionPicker({
  values,
  onChange,
}: {
  values: string[];
  onChange: (values: string[]) => void;
}) {
  const collections = useCollections();
  const names = collectionNames(collections.data);
  const summary = values.length ? `RAG (${values.length})` : "RAG off";
  return (
    <details className={`composer-menu ${values.length ? "active" : ""}`}>
      <summary>{summary}</summary>
      <div className="composer-menu-panel" role="group" aria-label="RAG collections">
        <div className="composer-menu-head">
          <span>Collections for this message</span>
          <button type="button" className="ghost compact" onClick={() => onChange([])}>Clear</button>
        </div>
        {!names.length && <p className="muted">No collections available.</p>}
        <div className="composer-menu-list">
          {names.map((name) => {
            const checked = values.includes(name);
            return (
              <label className="check" key={name}>
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={(event) => {
                    if (event.target.checked) onChange([...values, name]);
                    else onChange(values.filter((item) => item !== name));
                  }}
                />
                {name}
              </label>
            );
          })}
        </div>
        <small>{values.length ? "RAG enabled for selected collections" : "No collections selected — RAG off"}</small>
      </div>
    </details>
  );
}

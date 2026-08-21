import React, { FormEvent, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api";
import { ErrorState } from "../ui";
import { GallerySection, GalleryTile, SiteOpenMode, UserSite } from "./types";

function message(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed";
}

export function useSites() {
  return useQuery({ queryKey: ["sites"], queryFn: () => api<UserSite[]>("/sites") });
}

export function siteToTile(site: UserSite): GalleryTile {
  return {
    id: `site:${site.site_id}`,
    kind: "external",
    href: site.url,
    section: site.section,
    title: site.name,
    subtitle: site.url.replace(/^https?:\/\//, ""),
    preview: "favicon",
    badge: site.has_credential ? "SAVED" : undefined,
    openMode: site.open_mode,
    faviconUrl: site.favicon_url || undefined,
    siteId: site.site_id,
    hasCredential: site.has_credential,
    tags: site.tags,
    createdAt: site.created_at,
    updatedAt: site.updated_at,
  };
}

const SECTION_OPTIONS: { value: GallerySection; label: string }[] = [
  { value: "sites", label: "Sites" },
  { value: "investigate", label: "Investigate" },
  { value: "intelligence", label: "Intelligence" },
  { value: "operations", label: "Operations" },
];

const OPEN_MODE_OPTIONS: { value: SiteOpenMode; label: string }[] = [
  { value: "new_tab", label: "Open in a new tab" },
  { value: "launcher", label: "Launcher page (open / copy / edit)" },
  { value: "embedded", label: "Embedded popup — tries to show the site live, opens in a new tab if it blocks framing" },
];

/** Pin a new external site as a gallery tile, optionally saving a login for
 * it in the same step. Credential save is a second request after the site
 * is created (the site must exist first — `create_or_rotate` looks it up by
 * id), so a failure there leaves the site pinned without a saved login
 * rather than losing the whole submission. */
export function AddSiteForm({ onCreated, onCancel }: {
  onCreated: (siteId: string) => void;
  onCancel: () => void;
}) {
  const client = useQueryClient();
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [loginUrl, setLoginUrl] = useState("");
  const [section, setSection] = useState<GallerySection>("sites");
  const [tags, setTags] = useState("");
  const [openMode, setOpenMode] = useState<SiteOpenMode>("new_tab");
  const [saveLogin, setSaveLogin] = useState(false);
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(""); setBusy(true);
    try {
      const created = await api<{ site_id: string }>("/sites", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          url: url.trim(),
          login_url: loginUrl.trim() || null,
          section,
          tags: tags.split(",").map(tag => tag.trim()).filter(Boolean),
          open_mode: openMode,
        }),
      });
      if (saveLogin && username && secret) {
        await api(`/sites/${created.site_id}/credential`, {
          method: "POST",
          body: JSON.stringify({ username, secret, notes: notes.trim() || null }),
        });
      }
      await client.invalidateQueries({ queryKey: ["sites"] });
      onCreated(created.site_id);
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card form-grid gallery-add-site" onSubmit={submit}>
      <h2>Add site</h2>
      <ErrorState error={error} />
      <label>Display name<input value={name} onChange={e => setName(e.target.value)} required maxLength={200} /></label>
      <label>URL <small>HTTPS required (localhost allowed outside production)</small>
        <input type="url" value={url} onChange={e => setUrl(e.target.value)} required placeholder="https://siem.example.com" />
      </label>
      <label>Login page URL <small>optional, if different from the site URL</small>
        <input type="url" value={loginUrl} onChange={e => setLoginUrl(e.target.value)} placeholder="https://siem.example.com/login" />
      </label>
      <div className="field-row">
        <label>Section<select value={section} onChange={e => setSection(e.target.value as GallerySection)}>
          {SECTION_OPTIONS.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
        </select></label>
        <label>Open mode<select value={openMode} onChange={e => setOpenMode(e.target.value as SiteOpenMode)}>
          {OPEN_MODE_OPTIONS.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
        </select></label>
      </div>
      <label>Tags <small>comma-separated, optional</small><input value={tags} onChange={e => setTags(e.target.value)} placeholder="soc, edr" /></label>
      <label className="check setting-toggle">
        <input type="checkbox" checked={saveLogin} onChange={e => setSaveLogin(e.target.checked)} /> Save a login for this site
      </label>
      {saveLogin && (
        <div className="gallery-credential-fields">
          <label>Username / email<input value={username} onChange={e => setUsername(e.target.value)} required={saveLogin} autoComplete="off" /></label>
          <label>Password / API token<input type="password" value={secret} onChange={e => setSecret(e.target.value)} required={saveLogin} autoComplete="off" /></label>
          <label>Notes <small>MFA hint, tenant ID — not a second password</small><input value={notes} onChange={e => setNotes(e.target.value)} maxLength={2048} /></label>
        </div>
      )}
      <div className="actions">
        <button type="submit" disabled={busy}>{busy ? "Adding…" : "Add site"}</button>
        <button type="button" className="secondary" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

export function useDeleteSite() {
  const client = useQueryClient();
  return async (siteId: string) => {
    await api(`/sites/${siteId}`, { method: "DELETE" });
    await client.invalidateQueries({ queryKey: ["sites"] });
  };
}

import React, { FormEvent, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api";
import { ErrorState, Notice } from "../ui";
import { UserSite } from "./types";

const CLIPBOARD_CLEAR_MS = 30_000;
const AUTO_HIDE_MS = 60_000;

function requestMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 429) {
    return "Too many reveal attempts for this site — try again in a few minutes.";
  }
  return error instanceof Error ? error.message : "Request failed";
}

async function copyWithAutoClear(value: string) {
  await navigator.clipboard.writeText(value);
  window.setTimeout(() => { navigator.clipboard.writeText("").catch(() => {}); }, CLIPBOARD_CLEAR_MS);
}

interface Revealed { username: string; secret: string; notes: string | null }

/** Reveal/copy/edit/delete for a site's saved login — also doubles as the
 * "launcher" surface for sites pinned with open_mode "launcher" (Open Site,
 * copy username/secret, edit/rotate, delete). There is no client-side vault
 * passphrase: access control is the normal authenticated session plus
 * server-side rate limiting and a full audit trail on every reveal attempt.
 * Copy buttons clear the clipboard 30s after use; nothing is auto-copied. */
export function CredentialPanel({ site, onClose, onDeleteSite }: {
  site: UserSite;
  onClose: () => void;
  onDeleteSite?: (siteId: string) => Promise<void> | void;
}) {
  const client = useQueryClient();
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  // Always opens on the actions view, even for a site with no saved login
  // yet — entering the edit form is a deliberate click ("Save login"), never
  // the default, so there is always a way back out to "Delete site" without
  // being forced through the credential form first.
  const [editing, setEditing] = useState(false);
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [notes, setNotes] = useState("");
  const revealTimer = useRef<number | undefined>(undefined);

  useEffect(() => () => { if (revealTimer.current) window.clearTimeout(revealTimer.current); }, []);

  async function reveal() {
    setError(""); setBusy(true);
    try {
      const result = await api<Revealed>(`/sites/${site.site_id}/credential`);
      setRevealed(result);
      if (revealTimer.current) window.clearTimeout(revealTimer.current);
      revealTimer.current = window.setTimeout(() => setRevealed(null), AUTO_HIDE_MS);
    } catch (e) {
      setError(requestMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    setError(""); setBusy(true);
    try {
      await api(`/sites/${site.site_id}/credential`, {
        method: "POST",
        body: JSON.stringify({ username, secret, notes: notes || null }),
      });
      setSecret("");
      setEditing(false);
      setRevealed(null);
      await client.invalidateQueries({ queryKey: ["sites"] });
    } catch (e) {
      setError(requestMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setError(""); setBusy(true);
    try {
      await api(`/sites/${site.site_id}/credential`, { method: "DELETE" });
      setRevealed(null);
      await client.invalidateQueries({ queryKey: ["sites"] });
      onClose();
    } catch (e) {
      setError(requestMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card gallery-credential-panel" role="dialog" aria-label={`Saved login for ${site.name}`}>
      <div className="section-head">
        <div><span className="section-kicker">{site.has_credential ? "Saved login" : "No saved login yet"}</span><h2>{site.name}</h2></div>
        <button type="button" className="secondary compact" onClick={onClose}>Close</button>
      </div>
      <ErrorState error={error} />
      {!editing && (
        <div className="actions">
          <a className="button secondary" href={site.url} target="_blank" rel="noopener noreferrer">Open site</a>
          {site.has_credential && <button type="button" onClick={reveal} disabled={busy}>{revealed ? "Refresh reveal" : "Reveal"}</button>}
          <button type="button" className="secondary" onClick={() => setEditing(true)}>{site.has_credential ? "Edit / rotate" : "Save login"}</button>
          {site.has_credential && <button type="button" className="danger" onClick={remove} disabled={busy}>Remove saved login</button>}
          {onDeleteSite && <button type="button" className="danger" onClick={() => onDeleteSite(site.site_id)} disabled={busy}>Delete site</button>}
        </div>
      )}
      {revealed && (
        <div className="gallery-revealed">
          <div className="gallery-reveal-row"><span className="section-kicker">Username</span><code>{revealed.username}</code><button type="button" className="compact secondary" onClick={() => copyWithAutoClear(revealed.username)}>Copy</button></div>
          <div className="gallery-reveal-row"><span className="section-kicker">Secret</span><code>{"•".repeat(Math.min(revealed.secret.length, 24)) || "—"}</code><button type="button" className="compact secondary" onClick={() => copyWithAutoClear(revealed.secret)}>Copy</button></div>
          {revealed.notes && <p className="muted">{revealed.notes}</p>}
          <Notice>Copied values clear from your clipboard after 30 seconds. This reveal hides itself in a minute.</Notice>
        </div>
      )}
      {editing && (
        <form className="form-grid" onSubmit={save}>
          <label>Username / email<input value={username} onChange={e => setUsername(e.target.value)} required autoComplete="off" /></label>
          <label>Password / API token<input type="password" value={secret} onChange={e => setSecret(e.target.value)} required autoComplete="off" /></label>
          <label>Notes <small>MFA hint, tenant ID — not a second password</small><input value={notes} onChange={e => setNotes(e.target.value)} maxLength={2048} /></label>
          <div className="actions">
            <button type="submit" disabled={busy}>{site.has_credential ? "Rotate login" : "Save login"}</button>
            <button type="button" className="secondary" onClick={() => setEditing(false)}>Cancel</button>
          </div>
        </form>
      )}
    </section>
  );
}

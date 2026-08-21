import { FormEvent, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, Role } from "./api";
import { Icons } from "./icons";
import { EmptyState, ErrorState, Heading, Notice, formatWhen } from "./ui";
import { Admin as DetectionAdmin } from "./detection/pages/Admin";

export function AdminWorkflow() {
  const client = useQueryClient();
  const users = useQuery({ queryKey: ["admin-users"], queryFn: () => api<any>("/admin/users") });
  const invitations = useQuery({ queryKey: ["admin-invitations"], queryFn: () => api<any>("/admin/invitations") });
  const inventory = useQuery({ queryKey: ["admin-backup-inventory"], queryFn: () => api<any>("/admin/backup/inventory") });
  const backups = useQuery({ queryKey: ["admin-backups"], queryFn: () => api<any>("/admin/backup") });
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [send, setSend] = useState(false);
  const [link, setLink] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [includeQdrant, setIncludeQdrant] = useState(true);
  const [backupLabel, setBackupLabel] = useState("");
  const [busy, setBusy] = useState("");
  const uploadRef = useRef<HTMLInputElement>(null);

  async function refreshUsers() {
    await client.invalidateQueries({ queryKey: ["admin-users"] });
    await client.invalidateQueries({ queryKey: ["admin-invitations"] });
  }
  async function refreshBackups() {
    await client.invalidateQueries({ queryKey: ["admin-backups"] });
    await client.invalidateQueries({ queryKey: ["admin-backup-inventory"] });
  }

  async function invite(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      const value = await api<any>("/admin/invitations", { method: "POST", body: JSON.stringify({ email, role, send_email: send }) });
      setLink(value.invitation_url);
      setNotice(value.email_delivered ? "Invitation email sent." : "Invitation created; copy the single-use link.");
      setEmail("");
      refreshUsers();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Invitation failed");
    }
  }

  async function createBackup() {
    setBusy("create");
    setError("");
    try {
      const result = await api<any>("/admin/backup/create", {
        method: "POST",
        body: JSON.stringify({ include_qdrant: includeQdrant, label: backupLabel.trim() }),
      });
      setNotice(`Backup ${result.backup_id} created (${result.bytes || 0} bytes).`);
      setBackupLabel("");
      await refreshBackups();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Backup failed");
    } finally {
      setBusy("");
    }
  }

  async function restoreBackup(backupId: string) {
    if (!window.confirm(`Restore backup ${backupId}? Live SQLite databases and Qdrant collections will be overwritten. Restart the web container afterward.`)) {
      return;
    }
    setBusy(`restore:${backupId}`);
    setError("");
    try {
      const result = await api<any>("/admin/backup/restore", {
        method: "POST",
        body: JSON.stringify({ backup_id: backupId, include_qdrant: includeQdrant, include_sqlite: true }),
      });
      setNotice(result.message || `Restored ${backupId}. Restart recommended.`);
      await refreshBackups();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Restore failed");
    } finally {
      setBusy("");
    }
  }

  async function deleteBackup(backupId: string) {
    if (!window.confirm(`Delete backup ${backupId}?`)) return;
    setBusy(`delete:${backupId}`);
    setError("");
    try {
      await api(`/admin/backup/${encodeURIComponent(backupId)}`, { method: "DELETE" });
      setNotice(`Deleted backup ${backupId}.`);
      await refreshBackups();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Delete failed");
    } finally {
      setBusy("");
    }
  }

  async function uploadBackup(file: File | null) {
    if (!file) return;
    setBusy("upload");
    setError("");
    try {
      const body = new FormData();
      body.append("file", file);
      const result = await api<any>("/admin/backup/upload", { method: "POST", body });
      setNotice(`Uploaded ${result.filename} (${result.bytes || 0} bytes).`);
      await refreshBackups();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Upload failed");
    } finally {
      setBusy("");
      if (uploadRef.current) uploadRef.current.value = "";
    }
  }

  const userValues = users.data?.users || [];
  const inviteValues = invitations.data?.invitations || [];
  const backupRows = backups.data?.backups || [];
  const inv = inventory.data;

  return <>
    <Heading
      title="Administration"
      subtitle="TIP enrollment, backups, and detection-plane ops (notifications, deployments, outbox)."
    />
    <ErrorState error={error || users.error || invitations.error || inventory.error || backups.error} />
    {notice && <Notice>{notice}</Notice>}

    <div className="admin-overview">
      <form className="card form-grid admin-invite" onSubmit={invite}>
        <div className="section-head"><div><span className="section-kicker">Enrollment</span><h2>Create invitation</h2></div></div>
        <div className="field-row">
          <label>Email address<input type="email" placeholder="analyst@example.com" value={email} onChange={e => setEmail(e.target.value)} required /></label>
          <label>Access role<select value={role} onChange={e => setRole(e.target.value as Role)}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></label>
        </div>
        <label className="check"><input type="checkbox" checked={send} onChange={e => setSend(e.target.checked)} /> Send through configured SMTP</label>
        <button>Create secure invitation</button>
        {link && <label>Single-use URL<input readOnly value={link} onFocus={e => e.currentTarget.select()} /></label>}
      </form>
      <section className="card admin-summary">
        <div><span className="section-kicker">Directory</span><strong>{userValues.length}</strong><p>Total users</p></div>
        <div><span className="section-kicker">Invitations</span><strong>{inviteValues.filter((value: any) => !value.used_at).length}</strong><p>Pending enrollment</p></div>
        <div><span className="section-kicker">Backups</span><strong>{backupRows.length}</strong><p>Stored archives</p></div>
      </section>
    </div>

    <section className="card">
      <div className="section-head">
        <div><span className="section-kicker">Continuity</span><h2>Backup and restore</h2></div>
        <Icons.backup />
      </div>
      <p className="section-description">
        Snapshots cover every SQLite database under the configured state directory
        {inv?.sqlite ? ` (${inv.sqlite.length} files)` : ""} and optional Qdrant collection snapshots
        {inv?.qdrant_collections ? ` (${inv.qdrant_collections.length} collections)` : ""}.
        Restores overwrite live data — restart the web container afterward.
      </p>
      <div className="field-row">
        <label>Label (optional)<input value={backupLabel} onChange={e => setBackupLabel(e.target.value)} placeholder="pre-upgrade" maxLength={64} /></label>
        <label className="check setting-toggle" style={{ alignSelf: "end" }}>
          <input type="checkbox" checked={includeQdrant} onChange={e => setIncludeQdrant(e.target.checked)} />
          Include Qdrant collections
        </label>
      </div>
      <div className="actions">
        <button type="button" disabled={!!busy} onClick={createBackup}>{busy === "create" ? "Creating…" : "Create backup"}</button>
        <button type="button" className="secondary" disabled={!!busy} onClick={() => uploadRef.current?.click()}>Upload backup zip</button>
        <input ref={uploadRef} type="file" accept=".zip,application/zip" hidden onChange={e => uploadBackup(e.target.files?.[0] || null)} />
      </div>
      {inv && (
        <div className="stat-row" style={{ marginTop: "1rem" }}>
          <span className="muted">{(inv.sqlite || []).map((f: any) => f.name).join(", ") || "No sqlite files"}</span>
        </div>
      )}
      {backupRows.length ? (
        <div className="table-wrap" style={{ marginTop: "1rem" }}>
          <table>
            <thead><tr><th>Backup</th><th>Created</th><th>Size</th><th>Contents</th><th>Actions</th></tr></thead>
            <tbody>
              {backupRows.map((row: any) => (
                <tr key={row.backup_id}>
                  <td><strong>{row.backup_id}</strong></td>
                  <td className="nowrap">{formatWhen(row.created_at || row.manifest?.created_at)}</td>
                  <td className="nowrap">{row.bytes != null ? `${Math.round(row.bytes / 1024)} KB` : "—"}</td>
                  <td>
                    <small>
                      sqlite: {(row.manifest?.sqlite || []).length || "?"}
                      {" · "}
                      qdrant: {(row.manifest?.qdrant || []).length || 0}
                    </small>
                  </td>
                  <td>
                    <div className="actions">
                      <a className="button secondary compact" href={`/api/v1/admin/backup/${encodeURIComponent(row.backup_id)}/download`}>Download</a>
                      <button type="button" className="secondary" disabled={!!busy} onClick={() => restoreBackup(row.backup_id)}>
                        {busy === `restore:${row.backup_id}` ? "Restoring…" : "Restore"}
                      </button>
                      <button type="button" className="danger" disabled={!!busy} onClick={() => deleteBackup(row.backup_id)}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState title="No backups yet" description="Create a backup before upgrades or major connector changes." compact />
      )}
    </section>

    <section className="card">
      <div className="section-head"><div><span className="section-kicker">Access control</span><h2>Users</h2></div><span className="count-badge">{userValues.length}</span></div>
      {userValues.length ? (
        <div className="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead><tbody>
          {userValues.map((user: any) => (
            <tr key={user.user_id}>
              <td><strong>{user.display_name}</strong><small>{user.email}</small></td>
              <td>
                <select aria-label={`Role for ${user.email}`} value={user.role} onChange={async e => {
                  try { await api(`/admin/users/${user.user_id}`, { method: "PATCH", body: JSON.stringify({ role: e.target.value }) }); refreshUsers(); }
                  catch (reason) { setError(reason instanceof Error ? reason.message : "Update failed"); }
                }}><option>viewer</option><option>analyst</option><option>admin</option></select>
              </td>
              <td><span className={`status ${user.active ? "active" : "closed"}`}>{user.active ? "Active" : "Disabled"}</span></td>
              <td><div className="actions">
                <button className={user.active ? "danger" : "secondary"} onClick={async () => {
                  try { await api(`/admin/users/${user.user_id}`, { method: "PATCH", body: JSON.stringify({ active: !user.active }) }); refreshUsers(); }
                  catch (reason) { setError(reason instanceof Error ? reason.message : "Update failed"); }
                }}>{user.active ? "Disable" : "Enable"}</button>
                <button className="secondary" onClick={async () => {
                  const value = await api<any>(`/admin/users/${user.user_id}/password-reset`, { method: "POST" });
                  setLink(value.reset_url);
                  setNotice("Copy the generated single-use reset URL.");
                }}>Create reset link</button>
              </div></td>
            </tr>
          ))}
        </tbody></table></div>
      ) : <EmptyState title="No users" description="The bootstrap administrator will appear here." compact />}
    </section>

    <section className="card">
      <div className="section-head"><div><span className="section-kicker">Audit trail</span><h2>Invitation history</h2></div><span className="count-badge">{inviteValues.length}</span></div>
      {inviteValues.length ? (
        <div className="table-wrap"><table><thead><tr><th>Email</th><th>Role</th><th>Expires</th><th>State</th></tr></thead><tbody>
          {inviteValues.map((invRow: any) => (
            <tr key={invRow.invitation_id}>
              <td>{invRow.email}</td>
              <td>{invRow.role}</td>
              <td className="nowrap">{formatWhen(invRow.expires_at)}</td>
              <td><span className={`status ${invRow.used_at ? "completed" : "queued"}`}>{invRow.used_at ? "Used" : "Pending"}</span></td>
            </tr>
          ))}
        </tbody></table></div>
      ) : <EmptyState title="No invitations yet" description="New invitation activity will be recorded here." compact />}
    </section>

    <section className="card detection-admin-embed">
      <div className="section-head">
        <div><span className="section-kicker">Detection plane</span><h2>Notifications, deployments, outbox</h2></div>
      </div>
      <DetectionAdmin />
    </section>
  </>;
}

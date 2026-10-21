import React, { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { ErrorState, Notice } from "./ui";

export type SettingMeta = {
  desired: unknown;
  effective: unknown;
  default: unknown;
  source: string;
  restart_required: boolean;
  validation: Record<string, unknown>;
};

type InventoryItem = SettingMeta & {
  key: string;
  section: string;
  kind: "application" | "deployment";
  type: string;
  consumers: string[];
  editable: boolean;
  secret: boolean;
  description: string;
};

type Inventory = { items: InventoryItem[]; total: number; production: boolean; expired_exceptions: string[] };

type Revision = {
  revision_id: string;
  target: "compose" | "helm";
  parent_revision_id: string | null;
  status: string;
  changed_keys: string[];
  rendered_preview: string;
  preview_digest: string;
  exception_expires_at: string | null;
  created_by: string;
  approved_by: string | null;
  applied_at: string | null;
  health: Record<string, unknown> | null;
  error: string | null;
  created_at: string;
};

function show(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") {
    const configured = (value as { configured?: boolean }).configured;
    if (configured !== undefined) return configured ? "configured" : "not configured";
    return JSON.stringify(value);
  }
  return String(value);
}

/** Section badge: live vs restart, plus how many fields carry runtime overrides. */
export function SectionSource({ meta, section }: { meta?: Record<string, SettingMeta>; section: string }) {
  const fields = Object.entries(meta || {}).filter(([key]) => key.startsWith(`${section}.`));
  const overrides = fields.filter(([, item]) => item.source === "runtime").length;
  const external = fields.filter(([, item]) => item.source === "environment" || item.source === "config_file").length;
  const restart = fields.some(([, item]) => item.restart_required);
  const title = fields
    .map(([key, item]) => `${key}: ${show(item.effective)} (${item.source})`)
    .join("\n");
  return (
    <span className={`status ${restart ? "running" : "active"}`} title={title}>
      {restart ? "Restart required" : "Live apply"}
      {overrides ? ` · ${overrides} override${overrides === 1 ? "" : "s"}` : ""}
      {external ? ` · ${external} from deployment` : ""}
    </span>
  );
}

export function SettingsInventoryPanel() {
  const query = useQuery({ queryKey: ["settings-inventory"], queryFn: () => api<Inventory>("/admin/settings/inventory") });
  const [filter, setFilter] = useState("");
  const [kind, setKind] = useState<"all" | "application" | "deployment">("all");
  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return (query.data?.items || []).filter(
      (item) =>
        (kind === "all" || item.kind === kind) &&
        (!needle ||
          item.key.toLowerCase().includes(needle) ||
          item.section.toLowerCase().includes(needle) ||
          item.consumers.join(" ").toLowerCase().includes(needle)),
    );
  }, [query.data, filter, kind]);
  return (
    <section className="card settings-section">
      <div className="section-head">
        <div>
          <span className="section-kicker">Inventory</span>
          <h2>Every effective setting</h2>
        </div>
        <span className="status">{query.data ? `${rows.length} / ${query.data.total}` : "Loading"}</span>
      </div>
      <ErrorState error={query.error} />
      {query.data?.expired_exceptions.length ? (
        <Notice>
          Expired lab exceptions are still active: {query.data.expired_exceptions.join(", ")}. Draft a revision that
          restores the production value.
        </Notice>
      ) : null}
      <p className="section-description">
        Desired is what an administrator stored (runtime settings or the active deployment revision); effective is what
        this process is running with. Secrets are write-only and only report whether they are configured. Deployment
        settings owned by other services are changed from the Deployment tab.
      </p>
      <div className="field-row">
        <label>
          Filter
          <input value={filter} placeholder="key, section, or consumer" onChange={(e) => setFilter(e.target.value)} />
        </label>
        <label>
          Kind
          <select value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
            <option value="all">All</option>
            <option value="application">Application</option>
            <option value="deployment">Deployment</option>
          </select>
        </label>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Setting</th>
              <th>Desired</th>
              <th>Effective</th>
              <th>Source</th>
              <th>Consumer</th>
              <th>Apply</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((item) => (
              <tr key={`${item.kind}:${item.key}`}>
                <td title={item.description || item.type}>
                  <code>{item.key}</code>
                  {item.secret && <small> secret</small>}
                  {"production_required" in item.validation && (
                    <small> prod: {String(item.validation.production_required)}</small>
                  )}
                </td>
                <td>{show(item.desired)}</td>
                <td>{show(item.effective)}</td>
                <td>{item.source}</td>
                <td>{item.consumers.join(", ")}</td>
                <td>{item.restart_required ? "restart" : "live"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function DeploymentPanel() {
  const client = useQueryClient();
  const [target, setTarget] = useState<"compose" | "helm">("compose");
  const revisions = useQuery({
    queryKey: ["deployments", target],
    queryFn: () => api<{ items: Revision[]; handoff_configured: boolean }>(`/admin/deployments?target=${target}`),
    refetchInterval: (q) => ((q.state.data?.items || []).some((rev) => rev.status === "applying") ? 5000 : false),
  });
  const inventory = useQuery({ queryKey: ["settings-inventory"], queryFn: () => api<Inventory>("/admin/settings/inventory") });
  const [envText, setEnvText] = useState("");
  const [valuesText, setValuesText] = useState("");
  const [exceptionHours, setExceptionHours] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const managed = (inventory.data?.items || []).filter((item) => item.kind === "deployment");
  const publicScanSetting = (inventory.data?.items || []).find((item) => item.key === "ALLOW_PUBLIC_TARGETS");
  const publicScanEffective = String(publicScanSetting?.effective ?? "false").toLowerCase() === "true";
  const [publicScanDraft, setPublicScanDraft] = useState<boolean | null>(null);
  const publicScanDesired = publicScanDraft ?? publicScanEffective;

  async function run(action: () => Promise<unknown>, message: string) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
      setNotice(message);
      await client.invalidateQueries({ queryKey: ["deployments"] });
      await client.invalidateQueries({ queryKey: ["settings-inventory"] });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Deployment action failed");
    } finally {
      setBusy(false);
    }
  }

  function parseEnv(): Record<string, string | null> {
    const env: Record<string, string | null> = {};
    for (const raw of envText.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const index = line.indexOf("=");
      if (index < 1) throw new Error(`Expected NAME=value: ${line}`);
      const name = line.slice(0, index).trim();
      const value = line.slice(index + 1);
      env[name] = value === "<unset>" ? null : value;
    }
    return env;
  }

  function parseValues(): Record<string, unknown> {
    if (!valuesText.trim()) return {};
    const parsed = JSON.parse(valuesText);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Chart values must be a JSON object of dotted paths");
    return parsed as Record<string, unknown>;
  }

  async function draftPublicScanToggle(enabled: boolean) {
    await run(
      () =>
        api("/admin/deployments", {
          method: "POST",
          body: JSON.stringify({
            target,
            env: { ALLOW_PUBLIC_TARGETS: enabled ? "true" : "false" },
            values: target === "helm" ? parseValues() : {},
            lab_exception_hours: exceptionHours ? Number(exceptionHours) : null,
          }),
        }),
      `Draft revision created (${enabled ? "enable" : "disable"} non-lab public scanning). Review and approve the preview.`,
    );
    setPublicScanDraft(null);
  }

  return (
    <div className="settings-stack">
      <section className="card settings-section">
        <div className="section-head">
          <div>
            <span className="section-kicker">Egress</span>
            <h2>Public scanning policy</h2>
          </div>
          <span className={`status ${publicScanEffective ? "running" : "active"}`}>
            {publicScanEffective ? "Public scans allowed" : "Public scans blocked"}
          </span>
        </div>
        <p className="section-description">
          Controls whether the security-gateway may run tools against public third-party hosts outside isolated lab
          networks. Security Lab sessions still require analyst access, tool tiers, and lab profile selection.
        </p>
        <label className="check setting-toggle">
          <input
            type="checkbox"
            checked={publicScanDesired}
            onChange={(e) => setPublicScanDraft(e.target.checked)}
          />
          Allow non-lab public scanning of third-party hosts
        </label>
        <div className="actions">
          <button
            type="button"
            className="secondary"
            disabled={busy || publicScanDesired === publicScanEffective}
            onClick={() => void draftPublicScanToggle(publicScanDesired)}
          >
            Draft ALLOW_PUBLIC_TARGETS change
          </button>
        </div>
      </section>
      <section className="card settings-section">
        <div className="section-head">
          <div>
            <span className="section-kicker">Deployment controller</span>
            <h2>Compose and Helm revisions</h2>
          </div>
          <select value={target} onChange={(e) => setTarget(e.target.value as "compose" | "helm")}>
            <option value="compose">Compose</option>
            <option value="helm">Helm (detection chart)</option>
          </select>
        </div>
        <ErrorState error={error || revisions.error} />
        {notice && <Notice>{notice}</Notice>}
        {revisions.data && !revisions.data.handoff_configured && (
          <Notice>
            BLACK_ONYX_DEPLOY_HANDOFF_DIR is not set; revisions can be drafted and approved but not applied. Run
            scripts/deploy_applier.py on the host that owns Docker or Helm credentials.
          </Notice>
        )}
        <p className="section-description">
          Draft a revision, review its masked preview, approve that exact preview, then apply. The host applier verifies
          the signed bundle, validates the render, applies it, waits for health, and restores the previous state on
          failure. Production auth and isolation settings cannot be changed; isolated labs may attach a time-limited
          exception.
        </p>
        <label>
          Environment changes <small>NAME=value per line; NAME=&lt;unset&gt; removes it</small>
          <textarea rows={6} value={envText} onChange={(e) => setEnvText(e.target.value)} placeholder="BLACK_ONYX_DETECTION_TENANT=acme" />
        </label>
        {target === "helm" && (
          <label>
            Chart values <small>JSON object of dotted paths from values.yaml</small>
            <textarea rows={4} value={valuesText} onChange={(e) => setValuesText(e.target.value)} placeholder='{"responseOrchestrator.replicaCount": 2}' />
          </label>
        )}
        <div className="field-row">
          <label>
            Lab exception (hours, non-production only)
            <input type="number" min={1} max={72} value={exceptionHours} onChange={(e) => setExceptionHours(e.target.value)} />
          </label>
        </div>
        <div className="actions">
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              run(
                () =>
                  api("/admin/deployments", {
                    method: "POST",
                    body: JSON.stringify({
                      target,
                      env: parseEnv(),
                      values: target === "helm" ? parseValues() : {},
                      lab_exception_hours: exceptionHours ? Number(exceptionHours) : null,
                    }),
                  }),
                "Draft revision created. Review the preview before approving.",
              )
            }
          >
            Create draft
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => run(() => api(`/admin/deployments/rollback/${target}`, { method: "POST" }), "Rollback draft created.")}
          >
            Draft rollback
          </button>
        </div>
        <details>
          <summary>Managed settings ({managed.length})</summary>
          <ul>
            {managed.map((item) => (
              <li key={item.key}>
                <code>{item.key}</code> — {item.description} <small>({item.consumers.join(", ")})</small>
              </li>
            ))}
          </ul>
        </details>
      </section>
      {(revisions.data?.items || []).map((rev) => (
        <section className="card settings-section" key={rev.revision_id}>
          <div className="section-head">
            <div>
              <span className="section-kicker">{rev.target}</span>
              <h2>{rev.revision_id}</h2>
            </div>
            <span className={`status ${rev.status === "active" ? "active" : rev.status === "failed" ? "failed" : rev.status === "applying" ? "running" : ""}`}>{rev.status}</span>
          </div>
          <p className="section-description">
            Created by {rev.created_by} at {rev.created_at}
            {rev.approved_by ? ` · approved by ${rev.approved_by}` : ""}
            {rev.applied_at ? ` · applied ${rev.applied_at}` : ""}
            {rev.exception_expires_at ? ` · lab exception until ${rev.exception_expires_at}` : ""}
          </p>
          {rev.error && <Notice>{rev.error}</Notice>}
          <pre className="code-block">{rev.rendered_preview}</pre>
          {rev.health && <pre className="code-block">{JSON.stringify(rev.health, null, 2)}</pre>}
          <div className="actions">
            {rev.status === "draft" && (
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  run(
                    () => api(`/admin/deployments/${rev.revision_id}/approve`, { method: "POST", body: JSON.stringify({ preview_digest: rev.preview_digest }) }),
                    "Revision approved.",
                  )
                }
              >
                Approve this preview
              </button>
            )}
            {rev.status === "approved" && (
              <button type="button" disabled={busy} onClick={() => run(() => api(`/admin/deployments/${rev.revision_id}/apply`, { method: "POST" }), "Revision handed to the applier.")}>
                Apply
              </button>
            )}
            {(rev.status === "draft" || rev.status === "approved") && (
              <button type="button" className="secondary" disabled={busy} onClick={() => run(() => api(`/admin/deployments/${rev.revision_id}/reject`, { method: "POST" }), "Revision rejected.")}>
                Reject
              </button>
            )}
          </div>
        </section>
      ))}
    </div>
  );
}

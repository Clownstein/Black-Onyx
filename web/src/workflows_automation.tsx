import React, { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, Role } from "./api";
import { OpsSurfaceKpis } from "./components/ops_kpis";
import {
  ConfirmDialog,
  DataTable,
  EmptyState,
  ErrorState,
  Heading,
  KeyValues,
  Notice,
  StatRow,
  formatWhen,
} from "./ui";

function message(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

export function PlaybooksWorkflow({ role }: { role: Role }) {
  const client = useQueryClient();
  const playbooks = useQuery({ queryKey: ["playbooks"], queryFn: () => api<any>("/playbooks") });
  const runs = useQuery({ queryKey: ["playbook-runs"], queryFn: () => api<any>("/playbook-runs") });
  const analytics = useQuery({
    queryKey: ["analytics", "playbooks"],
    queryFn: () => api<any>("/analytics/playbooks?range=30d"),
  });
  const endpoints = useQuery({
    queryKey: ["outbound-endpoints"],
    queryFn: () => api<any>("/outbound-endpoints"),
  });
  const [name, setName] = useState("");
  const [trigger, setTrigger] = useState("manual");
  const [stepsJson, setStepsJson] = useState(
    '[{"type":"create_case","title":"Playbook case"},{"type":"notify_webhook","endpoint_name":"default"}]',
  );
  const [endpointName, setEndpointName] = useState("");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const admin = role === "admin";
  const canMutate = role !== "viewer";

  async function refresh() {
    await client.invalidateQueries({ queryKey: ["playbooks"] });
    await client.invalidateQueries({ queryKey: ["playbook-runs"] });
    await client.invalidateQueries({ queryKey: ["outbound-endpoints"] });
  }

  async function createPlaybook(event: FormEvent) {
    event.preventDefault();
    setError("");
    setNotice("");
    try {
      const steps = JSON.parse(stepsJson);
      if (!Array.isArray(steps)) throw new Error("Steps must be a JSON array");
      await api("/playbooks", {
        method: "POST",
        body: JSON.stringify({ name, trigger_type: trigger, steps, enabled: true }),
      });
      setName("");
      setNotice("Playbook created.");
      await refresh();
    } catch (e) {
      setError(message(e));
    }
  }

  return (
    <>
      <Heading
        title="SOAR-lite playbooks"
        subtitle="TIP automation (enrich, case, notify, Sigma) plus detection-spine SOAR approvals. Sigma/YARA are never executed locally."
        actions={<Link className="button secondary compact" to="/response-queue">Response approval queue</Link>}
      />
      <OpsSurfaceKpis metrics="automation_success,mttr,alert_case_ratio,closure_rate" />
      <ErrorState error={error || playbooks.error || runs.error || endpoints.error || analytics.error} />
      {notice && <Notice>{notice}</Notice>}

      <StatRow
        items={[
          { label: "Playbooks", value: (playbooks.data?.playbooks || []).length },
          { label: "Runs (30d)", value: analytics.data?.n ?? (runs.data?.runs || []).length },
          {
            label: "Success rate",
            value: analytics.data?.success_rate != null
              ? `${(Number(analytics.data.success_rate) * 100).toFixed(0)}%`
              : "—",
            tone: analytics.data?.success_rate != null && Number(analytics.data.success_rate) >= 0.8 ? "ok" : undefined,
          },
          {
            label: "Avg duration",
            value: analytics.data?.avg_duration_seconds != null
              ? `${Math.round(Number(analytics.data.avg_duration_seconds))}s`
              : "—",
          },
          {
            label: "Avg approval wait",
            value: analytics.data?.avg_approval_wait_seconds != null
              ? `${Math.round(Number(analytics.data.avg_approval_wait_seconds))}s`
              : "—",
          },
          { label: "Endpoints", value: (endpoints.data?.endpoints || []).length },
        ]}
      />

      {admin && (
        <form className="card form-grid" onSubmit={createPlaybook}>
          <div className="section-head">
            <div>
              <span className="section-kicker">Definition</span>
              <h2>Create playbook</h2>
            </div>
          </div>
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} required />
          </label>
          <label>
            Trigger
            <select value={trigger} onChange={(e) => setTrigger(e.target.value)}>
              <option value="manual">manual</option>
              <option value="watchlist_alert">watchlist_alert</option>
              <option value="webhook_event">webhook_event</option>
            </select>
          </label>
          <label>
            Steps (JSON)
            <textarea rows={5} value={stepsJson} onChange={(e) => setStepsJson(e.target.value)} required />
          </label>
          <button type="submit">Create playbook</button>
        </form>
      )}

      <section className="card">
        <div className="section-head">
          <div>
            <span className="section-kicker">Library</span>
            <h2>Playbooks</h2>
          </div>
        </div>
        <DataTable
          columns={[
            { key: "name", label: "Name" },
            { key: "trigger_type", label: "Trigger" },
            {
              key: "steps",
              label: "Steps",
              render: (row: any) => (row.steps || []).map((s: any) => s.type).join(" → ") || "—",
            },
            {
              key: "enabled",
              label: "Status",
              render: (row: any) => (
                <span className={`status ${row.enabled ? "completed" : "failed"}`}>
                  {row.enabled ? "enabled" : "disabled"}
                </span>
              ),
            },
            {
              key: "actions",
              label: "Actions",
              render: (row: any) =>
                canMutate ? (
                  <div className="actions">
                    <button
                      type="button"
                      className="secondary"
                      onClick={async () => {
                        try {
                          setError("");
                          await api(`/playbooks/${row.id}/run`, {
                            method: "POST",
                            body: JSON.stringify({ context: {} }),
                          });
                          setNotice(`Started run for ${row.name}`);
                          await refresh();
                        } catch (e) {
                          setError(message(e));
                        }
                      }}
                    >
                      Run
                    </button>
                    {admin && (
                      <>
                        <button
                          type="button"
                          className="secondary"
                          onClick={async () => {
                            await api(`/playbooks/${row.id}/${row.enabled ? "disable" : "enable"}`, {
                              method: "POST",
                            });
                            await refresh();
                          }}
                        >
                          {row.enabled ? "Disable" : "Enable"}
                        </button>
                        <ConfirmDialog
                          label="Delete"
                          expected={row.name}
                          onConfirm={async () => {
                            await api(`/playbooks/${row.id}`, { method: "DELETE" });
                            await refresh();
                          }}
                        />
                      </>
                    )}
                  </div>
                ) : (
                  "—"
                ),
            },
          ]}
          rows={playbooks.data?.playbooks || []}
          rowKey={(row: any) => row.id}
          empty={
            <EmptyState
              title="No playbooks"
              description="Admins can create playbooks that react to watchlist alerts, webhook events, or manual runs."
              compact
            />
          }
        />
      </section>

      <section className="card">
        <div className="section-head">
          <div>
            <span className="section-kicker">History</span>
            <h2>Playbook runs</h2>
          </div>
        </div>
        <DataTable
          columns={[
            { key: "run_id", label: "Run", clip: true },
            { key: "playbook_id", label: "Playbook", clip: true },
            {
              key: "status",
              label: "Status",
              render: (row: any) => <span className={`status ${row.status}`}>{row.status}</span>,
            },
            {
              key: "created_at",
              label: "Created",
              nowrap: true,
              render: (row: any) => formatWhen(row.created_at),
            },
            {
              key: "actions",
              label: "Actions",
              render: (row: any) =>
                canMutate && row.status === "waiting_approval" ? (
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        setError("");
                        await api(`/playbook-runs/${row.run_id}/approve`, { method: "POST" });
                        setNotice("Run approved and resumed.");
                        await refresh();
                      } catch (e) {
                        setError(message(e));
                      }
                    }}
                  >
                    Approve
                  </button>
                ) : (
                  "—"
                ),
            },
          ]}
          rows={runs.data?.runs || []}
          rowKey={(row: any) => row.run_id}
          empty={<EmptyState title="No runs yet" description="Trigger a playbook to see run history." compact />}
        />
      </section>

      <section className="card">
        <div className="section-head">
          <div>
            <span className="section-kicker">Delivery</span>
            <h2>Outbound endpoints</h2>
          </div>
        </div>
        {admin && (
          <form
            className="form-grid"
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                setError("");
                await api("/outbound-endpoints", {
                  method: "POST",
                  body: JSON.stringify({ name: endpointName, url: endpointUrl, enabled: true }),
                });
                setEndpointName("");
                setEndpointUrl("");
                await refresh();
              } catch (err) {
                setError(message(err));
              }
            }}
          >
            <label>
              Name
              <input value={endpointName} onChange={(e) => setEndpointName(e.target.value)} required />
            </label>
            <label>
              URL
              <input
                type="url"
                value={endpointUrl}
                onChange={(e) => setEndpointUrl(e.target.value)}
                required
              />
            </label>
            <button type="submit">Add endpoint</button>
          </form>
        )}
        <ul className="item-list">
          {(endpoints.data?.endpoints || []).map((ep: any) => (
            <li key={ep.id}>
              <span>
                {ep.name}
                <small>
                  {ep.url} · {ep.enabled ? "enabled" : "disabled"}
                </small>
              </span>
              {admin && (
                <div className="actions">
                  <button
                    type="button"
                    className="secondary"
                    onClick={async () => {
                      await api(`/outbound-endpoints/${ep.id}/${ep.enabled ? "disable" : "enable"}`, {
                        method: "POST",
                      });
                      await refresh();
                    }}
                  >
                    {ep.enabled ? "Disable" : "Enable"}
                  </button>
                  <ConfirmDialog
                    label="Remove"
                    expected={ep.name}
                    onConfirm={async () => {
                      await api(`/outbound-endpoints/${ep.id}`, { method: "DELETE" });
                      await refresh();
                    }}
                  />
                </div>
              )}
            </li>
          ))}
        </ul>
        {!(endpoints.data?.endpoints || []).length && (
          <EmptyState
            title="No outbound endpoints"
            description="Register HTTPS webhook URLs for notify_webhook playbook steps."
            compact
          />
        )}
      </section>
    </>
  );
}

export function PublishingWorkflow({ role }: { role: Role }) {
  const client = useQueryClient();
  const collections = useQuery({
    queryKey: ["taxii-collections"],
    queryFn: () => api<any>("/taxii/collections"),
  });
  const keys = useQuery({
    queryKey: ["taxii-keys"],
    queryFn: () => api<any>("/taxii/keys"),
    enabled: role === "admin",
    retry: false,
  });
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [keyName, setKeyName] = useState("");
  const [createdKey, setCreatedKey] = useState<any>();
  const [collectionId, setCollectionId] = useState("");
  const [iocType, setIocType] = useState("ip");
  const [iocValue, setIocValue] = useState("");
  const [selectedObjects, setSelectedObjects] = useState<any[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const admin = role === "admin";
  const canMutate = role !== "viewer";

  async function refresh() {
    await client.invalidateQueries({ queryKey: ["taxii-collections"] });
    await client.invalidateQueries({ queryKey: ["taxii-keys"] });
  }

  return (
    <>
      <Heading
        title="TAXII 2.1 publishing"
        subtitle="Publish STIX collections for external consumers. Clients authenticate with Bearer API keys against /taxii2/."
      />
      <ErrorState error={error || collections.error || keys.error} />
      {notice && <Notice>{notice}</Notice>}

      <StatRow
        items={[
          { label: "Collections", value: (collections.data?.collections || []).length },
          { label: "API keys", value: (keys.data?.keys || []).length },
        ]}
      />

      {canMutate && (
        <form
          className="card form-grid"
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              setError("");
              const created = await api<any>("/taxii/collections", {
                method: "POST",
                body: JSON.stringify({ title, description, enabled: true }),
              });
              setTitle("");
              setDescription("");
              setCollectionId(created.collection_id);
              setNotice(`Collection created: ${created.collection_id}`);
              await refresh();
            } catch (err) {
              setError(message(err));
            }
          }}
        >
          <div className="section-head">
            <div>
              <span className="section-kicker">Collections</span>
              <h2>Create collection</h2>
            </div>
          </div>
          <label>
            Title
            <input value={title} onChange={(e) => setTitle(e.target.value)} required />
          </label>
          <label>
            Description
            <input value={description} onChange={(e) => setDescription(e.target.value)} />
          </label>
          <button type="submit">Create collection</button>
        </form>
      )}

      <section className="card">
        <div className="section-head">
          <div>
            <span className="section-kicker">Catalog</span>
            <h2>Collections</h2>
          </div>
        </div>
        <DataTable
          columns={[
            { key: "title", label: "Title" },
            { key: "collection_id", label: "ID", clip: true },
            { key: "description", label: "Description" },
            {
              key: "enabled",
              label: "Enabled",
              render: (row: any) => (row.enabled ? "yes" : "no"),
            },
            {
              key: "actions",
              label: "Actions",
              render: (row: any) => (
                <button
                  type="button"
                  className="ghost"
                  onClick={async () => {
                    setCollectionId(row.collection_id);
                    try {
                      const data = await api<any>(
                        `/taxii/collections/${row.collection_id}/objects?limit=50`,
                      );
                      setSelectedObjects(data.objects || []);
                    } catch (err) {
                      setError(message(err));
                    }
                  }}
                >
                  View objects
                </button>
              ),
            },
          ]}
          rows={collections.data?.collections || []}
          rowKey={(row: any) => row.collection_id}
          empty={
            <EmptyState
              title="No collections"
              description="Create a TAXII collection, then publish IOCs as STIX 2.1 objects."
              compact
            />
          }
        />
      </section>

      {canMutate && (
        <form
          className="card form-grid"
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              setError("");
              const result = await api<any>("/taxii/publish", {
                method: "POST",
                body: JSON.stringify({
                  collection_id: collectionId,
                  iocs: [{ ioc_type: iocType, ioc_value: iocValue }],
                }),
              });
              setNotice(`Published ${result.objects_stored} STIX object(s).`);
              setIocValue("");
              const data = await api<any>(`/taxii/collections/${collectionId}/objects?limit=50`);
              setSelectedObjects(data.objects || []);
            } catch (err) {
              setError(message(err));
            }
          }}
        >
          <div className="section-head">
            <div>
              <span className="section-kicker">Publish</span>
              <h2>Publish IOC as STIX</h2>
            </div>
          </div>
          <label>
            Collection ID
            <input value={collectionId} onChange={(e) => setCollectionId(e.target.value)} required />
          </label>
          <label>
            IOC type
            <select value={iocType} onChange={(e) => setIocType(e.target.value)}>
              <option value="ip">ip</option>
              <option value="domain">domain</option>
              <option value="url">url</option>
              <option value="md5">md5</option>
              <option value="sha256">sha256</option>
              <option value="email">email</option>
            </select>
          </label>
          <label>
            IOC value
            <input value={iocValue} onChange={(e) => setIocValue(e.target.value)} required />
          </label>
          <button type="submit">Publish</button>
        </form>
      )}

      {selectedObjects.length > 0 && (
        <section className="card">
          <h2>Collection objects</h2>
          <KeyValues
            items={selectedObjects.slice(0, 8).map((obj: any, index: number) => ({
              label: obj.type || `object-${index}`,
              value: obj.id || obj.name || JSON.stringify(obj).slice(0, 120),
              wide: true,
            }))}
          />
        </section>
      )}

      {admin && (
        <section className="card">
          <div className="section-head">
            <div>
              <span className="section-kicker">Access</span>
              <h2>TAXII API keys</h2>
            </div>
          </div>
          <p className="section-description">
            Consumers call <code>GET /taxii2/</code> with <code>Authorization: Bearer &lt;token&gt;</code>.
          </p>
          <form
            className="form-grid"
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                setError("");
                const created = await api<any>("/taxii/keys", {
                  method: "POST",
                  body: JSON.stringify({ name: keyName }),
                });
                setCreatedKey(created);
                setKeyName("");
                await refresh();
              } catch (err) {
                setError(message(err));
              }
            }}
          >
            <label>
              Key name
              <input value={keyName} onChange={(e) => setKeyName(e.target.value)} required />
            </label>
            <button type="submit">Create API key</button>
          </form>
          {createdKey && (
            <Notice>
              Copy this token now — it is shown once: <code>{createdKey.token}</code>
            </Notice>
          )}
          <ul className="item-list">
            {(keys.data?.keys || []).map((key: any) => (
              <li key={key.key_id}>
                <span>
                  {key.name}
                  <small>
                    prefix {key.token_prefix}… · {key.enabled ? "enabled" : "disabled"}
                  </small>
                </span>
                <span className="actions">
                  <button
                    type="button"
                    className="secondary"
                    onClick={async () => {
                      try {
                        setError("");
                        await api(`/taxii/keys/${key.key_id}`, {
                          method: "PATCH",
                          body: JSON.stringify({ enabled: !key.enabled }),
                        });
                        await refresh();
                      } catch (err) {
                        setError(message(err));
                      }
                    }}
                  >
                    {key.enabled ? "Disable" : "Enable"}
                  </button>
                  <button
                    type="button"
                    className="secondary"
                    onClick={async () => {
                      try {
                        setError("");
                        await api(`/taxii/keys/${key.key_id}`, { method: "DELETE" });
                        await refresh();
                      } catch (err) {
                        setError(message(err));
                      }
                    }}
                  >
                    Revoke
                  </button>
                </span>
              </li>
            ))}
          </ul>
          {!(keys.data?.keys || []).length && (
            <EmptyState title="No TAXII keys" description="Create a key for external TAXII clients." compact />
          )}
        </section>
      )}
    </>
  );
}

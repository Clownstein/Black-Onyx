import { FormEvent, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useUser } from "./user_context";
import { isAdmin } from "./rbac";
import { ConfirmDialog, DataTable, EmptyState, ErrorState, Heading, KeyValues, Notice, formatWhen, humanizeLabel } from "./ui";
import { HorizontalBars } from "./components/charts";
import { OpsSurfaceKpis } from "./components/ops_kpis";
import { Link } from "react-router-dom";

function message(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed";
}

type ConnectorType = "generic_rest" | "microsoft_defender" | "crowdstrike_falcon";

const CONNECTOR_TYPE_LABELS: Record<ConnectorType, string> = {
  generic_rest: "Generic REST (config-driven)",
  microsoft_defender: "Microsoft Defender for Endpoint",
  crowdstrike_falcon: "CrowdStrike Falcon",
};

const AUTH_TYPE_OPTIONS = [
  { value: "api_key_header", label: "API key header" },
  { value: "bearer_token", label: "Bearer token" },
  { value: "oauth2_client_credentials", label: "OAuth2 client credentials" },
] as const;

/**
 * Detections page: configure pull-based SIEM/EDR connectors and see what
 * they've pulled in. This is admin-only end to end — every /api/v1/connectors*
 * endpoint is require_admin-gated server-side (connector credentials and the
 * collections they populate are shared, org-wide data, unlike a personal
 * gallery site), so `rbac.ts` keeps this off the nav for anyone else rather
 * than showing a page that would just 403.
 *
 * Follows the same conventions as WatchlistsWorkflow/FeedsWorkflow in
 * workflows_operations.tsx: one useQuery per resource, no useMutation —
 * inline async handlers calling `api()` then invalidating queries.
 */
export function DetectionsWorkflow() {
  const user = useUser();
  const admin = isAdmin(user.role);
  const client = useQueryClient();
  const connectors = useQuery({ queryKey: ["connectors"], queryFn: () => api<any[]>("/connectors"), enabled: admin });
  const recent = useQuery({ queryKey: ["recent-detections"], queryFn: () => api<any[]>("/connectors/detections/recent") });

  const [name, setName] = useState("");
  const [connectorType, setConnectorType] = useState<ConnectorType>("generic_rest");
  const [baseUrl, setBaseUrl] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [pollIntervalMinutes, setPollIntervalMinutes] = useState(60);
  const [authType, setAuthType] = useState<(typeof AUTH_TYPE_OPTIONS)[number]["value"]>("oauth2_client_credentials");
  const [detectionsPath, setDetectionsPath] = useState("/alerts");
  const [responseItemsPath, setResponseItemsPath] = useState("items");
  const [apiKeyEnv, setApiKeyEnv] = useState("");
  const [bearerTokenEnv, setBearerTokenEnv] = useState("");
  const [clientIdEnv, setClientIdEnv] = useState("");
  const [clientSecretEnv, setClientSecretEnv] = useState("");
  const [advancedConfig, setAdvancedConfig] = useState("");

  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [testResults, setTestResults] = useState<Record<string, any>>({});
  const [pollResults, setPollResults] = useState<Record<string, any>>({});
  const [busyId, setBusyId] = useState("");
  const [pushTokens, setPushTokens] = useState<Record<string, string>>({});

  async function refresh() {
    await client.invalidateQueries({ queryKey: ["connectors"] });
    await client.invalidateQueries({ queryKey: ["recent-detections"] });
  }

  function credentialEnv(): Record<string, string> {
    const env: Record<string, string> = {};
    if (connectorType === "generic_rest") {
      if (authType === "api_key_header" && apiKeyEnv) env.api_key = apiKeyEnv;
      if (authType === "bearer_token" && bearerTokenEnv) env.bearer_token = bearerTokenEnv;
      if (authType === "oauth2_client_credentials") {
        if (clientIdEnv) env.client_id = clientIdEnv;
        if (clientSecretEnv) env.client_secret = clientSecretEnv;
      }
    } else {
      // Both presets are OAuth2 client-credentials only.
      if (clientIdEnv) env.client_id = clientIdEnv;
      if (clientSecretEnv) env.client_secret = clientSecretEnv;
    }
    return env;
  }

  function buildConfig(): Record<string, any> {
    if (connectorType === "microsoft_defender") {
      return { tenant_id: tenantId.trim() };
    }
    if (connectorType === "crowdstrike_falcon") {
      return baseUrl.trim() ? { base_url: baseUrl.trim() } : {};
    }
    // generic_rest: start from the form fields, then let the advanced JSON
    // textarea override/extend anything it names — the escape hatch for
    // pagination styles and field mappings too varied for dedicated inputs.
    const config: Record<string, any> = {
      base_url: baseUrl.trim(),
      detections_path: detectionsPath.trim() || "/alerts",
      response_items_path: responseItemsPath.trim(),
      auth: { type: authType, ...(authType === "api_key_header" ? { header_name: "X-API-Key" } : {}) },
    };
    if (advancedConfig.trim()) {
      try {
        Object.assign(config, JSON.parse(advancedConfig));
      } catch {
        throw new Error("Advanced config is not valid JSON");
      }
    }
    return config;
  }

  async function createConnector(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      const config = buildConfig();
      await api("/connectors", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          connector_type: connectorType,
          base_url: connectorType === "microsoft_defender" ? "https://graph.microsoft.com" : (baseUrl.trim() || "https://api.crowdstrike.com"),
          config,
          credential_env: credentialEnv(),
          poll_interval_minutes: pollIntervalMinutes,
        }),
      });
      setName(""); setBaseUrl(""); setTenantId(""); setApiKeyEnv(""); setBearerTokenEnv("");
      setClientIdEnv(""); setClientSecretEnv(""); setAdvancedConfig("");
      await refresh();
    } catch (e) {
      setError(message(e));
    }
  }

  async function pollNow(connectorId: string) {
    setBusyId(connectorId); setError("");
    try {
      const outcome = await api<any>(`/connectors/${connectorId}/poll`, { method: "POST" });
      setPollResults(prev => ({ ...prev, [connectorId]: outcome }));
      if (outcome?.error) setError(`${outcome.connector || connectorId}: ${outcome.error}`);
      await refresh();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusyId("");
    }
  }

  async function testConnection(connectorId: string) {
    setBusyId(connectorId); setError("");
    try {
      const result = await api<any>(`/connectors/${connectorId}/test`, { method: "POST" });
      setTestResults(prev => ({ ...prev, [connectorId]: result }));
    } catch (e) {
      setError(message(e));
    } finally {
      setBusyId("");
    }
  }

  async function toggleEnabled(connectorId: string, enabled: boolean) {
    await api(`/connectors/${connectorId}`, { method: "PATCH", body: JSON.stringify({ enabled }) });
    await refresh();
  }

  async function rotatePushToken(connectorId: string) {
    setBusyId(connectorId);
    setError("");
    try {
      const result = await api<any>(`/connectors/${connectorId}/push-token`, { method: "POST" });
      setPushTokens(prev => ({ ...prev, [connectorId]: result.token }));
      setNotice(`Push token for ${connectorId} rotated. Copy it now — it is shown once. Auth: ${result.auth_header}`);
      await refresh();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusyId("");
    }
  }

  const list = connectors.data || [];

  return (
    <>
      <Heading
        title="Detection connectors"
        subtitle="Analysts review pulled detections here. Connector credentials and config remain admin-only."
        actions={<Link className="button secondary compact" to="/analytics">Analytics</Link>}
      />
      <OpsSurfaceKpis metrics="mtta,fpr,alert_case_ratio" />
      <ErrorState error={error || connectors.error || recent.error} />
      {notice && <Notice>{notice}</Notice>}
      <DetectionsByConnectorChart />

      {admin && <form className="card form-grid" onSubmit={createConnector}>
        <h2>Add connector</h2>
        <div className="field-row">
          <label>Name<input value={name} onChange={e => setName(e.target.value)} required maxLength={200} placeholder="falcon-prod" /></label>
          <label>Connector type
            <select value={connectorType} onChange={e => setConnectorType(e.target.value as ConnectorType)}>
              {Object.entries(CONNECTOR_TYPE_LABELS).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </label>
        </div>

        {connectorType === "microsoft_defender" && (
          <label>Azure AD tenant ID<input value={tenantId} onChange={e => setTenantId(e.target.value)} required /></label>
        )}
        {connectorType !== "microsoft_defender" && (
          <label>Base URL {connectorType === "crowdstrike_falcon" && <small>optional — defaults to the US-1 cloud</small>}
            <input
              type="url" value={baseUrl} onChange={e => setBaseUrl(e.target.value)}
              required={connectorType === "generic_rest"}
              placeholder={connectorType === "crowdstrike_falcon" ? "https://api.crowdstrike.com" : "https://api.example.com"}
            />
          </label>
        )}

        {connectorType === "generic_rest" && (
          <>
            <div className="field-row">
              <label>Detections path<input value={detectionsPath} onChange={e => setDetectionsPath(e.target.value)} placeholder="/alerts" /></label>
              <label>Response items path <small>dotted path to the list in the response body</small>
                <input value={responseItemsPath} onChange={e => setResponseItemsPath(e.target.value)} placeholder="items" />
              </label>
            </div>
            <label>Auth type<select value={authType} onChange={e => setAuthType(e.target.value as typeof authType)}>
              {AUTH_TYPE_OPTIONS.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
            </select></label>
          </>
        )}

        {(connectorType !== "generic_rest" || authType === "oauth2_client_credentials") && (
          <div className="field-row">
            <label>Client ID environment variable<input value={clientIdEnv} onChange={e => setClientIdEnv(e.target.value)} placeholder="FALCON_CLIENT_ID" /></label>
            <label>Client secret environment variable<input value={clientSecretEnv} onChange={e => setClientSecretEnv(e.target.value)} placeholder="FALCON_CLIENT_SECRET" /></label>
          </div>
        )}
        {connectorType === "generic_rest" && authType === "api_key_header" && (
          <label>API key environment variable<input value={apiKeyEnv} onChange={e => setApiKeyEnv(e.target.value)} placeholder="MY_API_KEY" /></label>
        )}
        {connectorType === "generic_rest" && authType === "bearer_token" && (
          <label>Bearer token environment variable<input value={bearerTokenEnv} onChange={e => setBearerTokenEnv(e.target.value)} placeholder="MY_BEARER_TOKEN" /></label>
        )}
        <small>Credentials are never entered here — set the named environment variable(s) on the server, and reference their names above.</small>

        {connectorType === "generic_rest" && (
          <label>Advanced config (JSON) <small>optional — pagination style, field mapping; merges over/extends the fields above</small>
            <textarea rows={4} value={advancedConfig} onChange={e => setAdvancedConfig(e.target.value)}
              placeholder='{"pagination": {"style": "cursor", "cursor_response_path": "next", "cursor_param": "cursor"}, "field_map": {"title": "summary", "ip_addresses": "network.ip"}}' />
          </label>
        )}

        <label>Poll interval (minutes)<input type="number" min={5} max={1440} value={pollIntervalMinutes} onChange={e => setPollIntervalMinutes(Number(e.target.value) || 60)} /></label>
        <button type="submit">Add connector</button>
      </form>}

      {admin && <div className="result-grid">
        {list.map((connector: any) => {
          const testResult = testResults[connector.id];
          const pollResult = pollResults[connector.id];
          const status = connector.last_poll_status === "failed" ? "failed" : connector.last_poll_status === "ok" ? "completed" : "";
          const statusLabel = status === "failed" ? "Failing" : status === "completed" ? "Healthy" : "Never polled";
          return (
            <article className="card" key={connector.id}>
              <div className="section-head">
                <div><span className="section-kicker">{CONNECTOR_TYPE_LABELS[connector.connector_type as ConnectorType] || connector.connector_type}</span><h2>{connector.name}</h2></div>
                <span className={`status ${status}`}>{connector.enabled ? statusLabel : "Disabled"}</span>
              </div>
              <KeyValues items={[
                { label: "Base URL", value: connector.base_url, wide: true },
                { label: "Collection", value: connector.collection },
                { label: "Interval", value: `${connector.poll_interval_minutes} min` },
                { label: "Last poll", value: formatWhen(connector.last_poll_at) },
                { label: "Push token", value: connector.has_push_token ? `configured (${connector.push_token_prefix || "****"}…)` : "not issued" },
              ]} />
              {connector.last_poll_error && <p className="feed-outcome failed">{connector.last_poll_error}</p>}
              {pollResult && (pollResult.error
                ? <p className="feed-outcome failed">{pollResult.error}</p>
                : pollResult.skipped
                  ? <p className="feed-outcome">{pollResult.skipped}</p>
                  : <p className="feed-outcome">Pulled {pollResult.raw_count ?? 0}, ingested {pollResult.processed ?? 0}{pollResult.errors ? `, ${pollResult.errors} failed` : ""}.</p>)}
              {testResult && <p className={testResult.status === "ok" ? "feed-outcome" : "feed-outcome failed"}>{testResult.status === "ok" ? "Connection OK" : testResult.error}</p>}
              {pushTokens[connector.id] && (
                <label>One-time push token
                  <input readOnly value={pushTokens[connector.id]} onFocus={e => e.currentTarget.select()} />
                </label>
              )}
              <div className="actions">
                <button type="button" disabled={busyId === connector.id} onClick={() => pollNow(connector.id)}>{busyId === connector.id ? "Working…" : "Poll now"}</button>
                <button type="button" className="secondary" disabled={busyId === connector.id} onClick={() => testConnection(connector.id)}>Test connection</button>
                <button type="button" className="secondary" disabled={busyId === connector.id} onClick={() => rotatePushToken(connector.id)}>
                  {connector.has_push_token ? "Rotate push token" : "Issue push token"}
                </button>
                <button type="button" className="secondary" onClick={() => toggleEnabled(connector.id, !connector.enabled)}>{connector.enabled ? "Disable" : "Enable"}</button>
                <ConfirmDialog label="Delete" expected={connector.name} onConfirm={async () => { await api(`/connectors/${connector.id}`, { method: "DELETE" }); await refresh(); }} />
              </div>
            </article>
          );
        })}
      </div>}
      {admin && !list.length && (
        <section className="card">
          <EmptyState title="No connectors configured" description="Add a connector above to start pulling detections in from a SIEM or EDR source." compact />
        </section>
      )}

      <section className="card">
        <div className="section-head"><div><span className="section-kicker">Activity</span><h2>Recent detections</h2></div><Link className="button secondary compact" to="/triage">Review in triage</Link></div>
        <DataTable
          columns={[
            { key: "connector", label: "Connector" },
            { key: "title", label: "Title", clip: true },
            { key: "severity", label: "Severity", render: (row: any) => row.severity || "—" },
            { key: "disposition", label: "Disposition", render: (row: any) => row.disposition ? humanizeLabel(String(row.disposition)) : "—" },
            { key: "acknowledged", label: "Ack", render: (row: any) => row.acknowledged ? "Yes" : "No" },
            { key: "ioc_status", label: "Status" },
            { key: "indexed_at", label: "Indexed", nowrap: true, render: (row: any) => formatWhen(row.indexed_at) },
          ]}
          rows={recent.data || []}
          rowKey={(row: any, index: number) => `${row.connector}-${row.source_file}-${index}`}
          empty={<EmptyState title="No detections yet" description="Pulled detections from an enabled connector will show up here after its first poll." compact />}
        />
      </section>
    </>
  );
}

function DetectionsByConnectorChart() {
  const dist = useQuery({
    queryKey: ["detections-by-connector"],
    queryFn: () => api<any>("/analytics/distributions?metric=detections_by_connector&range=30d"),
  });
  const series = (dist.data?.items || []).map((row: any) => ({
    label: String(row.label || row.key || ""),
    value: Number(row.value ?? row.count ?? 0),
  }));
  if (!series.length) return null;
  return (
    <section className="card">
      <div className="section-head"><div><span className="section-kicker">Volume</span><h2>Detections by connector (30d)</h2></div><Link className="button ghost compact" to="/analytics">Analytics</Link></div>
      <HorizontalBars data={series} />
    </section>
  );
}

import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { useToast } from "./components/toast";
import { useUser } from "./user_context";
import { isOperational } from "./rbac";
import { OpsSurfaceKpis } from "./components/ops_kpis";
import { DataTable, EmptyState, ErrorState, Heading, formatWhen, humanizeLabel } from "./ui";
import { api as detectionApi } from "./detection/api/client";

const DISPOSITIONS = ["true_positive", "false_positive", "benign_positive", "duplicate", "informational", "escalated"] as const;

export function TriageWorkflow() {
  const user = useUser();
  const toast = useToast();
  const qc = useQueryClient();
  const [selected, setSelected] = useState<any | null>(null);
  const [disposition, setDisposition] = useState<typeof DISPOSITIONS[number]>("true_positive");
  const [note, setNote] = useState("");
  const [suppress, setSuppress] = useState(false);
  const [mispNote, setMispNote] = useState(false);
  const [playbookId, setPlaybookId] = useState("");

  const triage = useQuery({
    queryKey: ["triage"],
    queryFn: () => api<{ items: any[] }>("/triage?limit=100"),
  });
  const detectionIncidents = useQuery({
    queryKey: ["triage-detection-incidents"],
    queryFn: async () => {
      try {
        const rows = await detectionApi.listIncidents();
        return (rows || []).slice(0, 100).map((inc: any) => {
          const incidentId = String(inc.incident_id || inc.id || "").trim();
          return {
            kind: "detection_incident",
            id: `di:${incidentId}`,
            incident_id: incidentId,
            title: inc.title || incidentId,
            severity: inc.severity || "medium",
            source: "detection-spine",
            disposition: inc.status || "",
            triggered_at: inc.last_seen || inc.first_seen,
            technique_ids: inc.techniques || inc.mitre_techniques || [],
            raw: inc,
          };
        }).filter((row: any) => Boolean(row.incident_id));
      } catch {
        return [] as any[];
      }
    },
    retry: false,
  });
  const playbooks = useQuery({
    queryKey: ["playbooks"],
    queryFn: () => api<any>("/playbooks"),
    enabled: isOperational(user.role),
  });

  const dispose = useMutation({
    mutationFn: async () => {
      if (selected?.alert_id) {
        return api(`/alerts/${selected.alert_id}/disposition`, {
          method: "POST",
          body: JSON.stringify({
            disposition,
            note,
            suppress_item: suppress && disposition === "false_positive",
            lower_confidence: suppress && disposition === "false_positive",
            misp_note: mispNote && disposition === "false_positive",
          }),
        });
      }
      if (selected?.detection_key || selected?.kind === "detection") {
        const detection_key = selected.detection_key || selected.raw?.source_file || selected.raw?.detection_key;
        if (!detection_key) throw new Error("Detection key missing");
        return api("/detections/disposition", {
          method: "POST",
          body: JSON.stringify({
            detection_key,
            disposition,
            note,
            connector: selected.source || "",
            title: selected.title || "",
          }),
        });
      }
      if (selected?.event_id || selected?.kind === "webhook_event") {
        const eventId = selected.event_id || String(selected.id || "").replace(/^wh:/, "");
        if (!eventId) throw new Error("Webhook event id missing");
        return api(`/webhook-events/${eventId}/disposition`, {
          method: "POST",
          body: JSON.stringify({ disposition, note }),
        });
      }
      if (selected?.kind === "detection_incident" && selected.incident_id) {
        const mapped =
          disposition === "benign_positive" ? "benign_anomaly"
          : disposition === "informational" || disposition === "escalated" ? "unknown"
          : disposition;
        return detectionApi.disposition(
          String(selected.incident_id),
          mapped as "true_positive" | "false_positive" | "benign_anomaly" | "duplicate" | "unknown",
          note,
        );
      }
      throw new Error("Select an item that supports disposition");
    },
    onSuccess: (data: any) => {
      toast.push(data?.misp?.error ? `Disposition saved (MISP: ${data.misp.error})` : "Disposition saved", "ok");
      qc.invalidateQueries({ queryKey: ["triage"] });
      qc.invalidateQueries({ queryKey: ["triage-detection-incidents"] });
      qc.invalidateQueries({ queryKey: ["analytics"] });
    },
    onError: (err) => toast.push(err instanceof Error ? err.message : "Disposition failed", "bad"),
  });

  const promote = useMutation({
    mutationFn: async () => {
      const body = {
        title: selected?.title || undefined,
        description: note.trim() || undefined,
      };
      if (selected?.alert_id) {
        return api<{ case_id: string }>(`/alerts/${selected.alert_id}/promote`, {
          method: "POST",
          body: JSON.stringify(body),
        });
      }
      if (selected?.detection_key || selected?.kind === "detection") {
        const detection_key = selected.detection_key || selected.raw?.source_file || selected.raw?.detection_key;
        if (!detection_key) throw new Error("Detection key missing");
        return api<{ case_id: string }>("/detections/promote", {
          method: "POST",
          body: JSON.stringify({
            ...body,
            detection_key,
            connector: selected.source || "",
            detection_title: selected.title || "",
          }),
        });
      }
      if (selected?.event_id || selected?.kind === "webhook_event") {
        const eventId = selected.event_id || String(selected.id || "").replace(/^wh:/, "");
        if (!eventId) throw new Error("Webhook event id missing");
        return api<{ case_id: string }>(`/webhook-events/${eventId}/promote`, {
          method: "POST",
          body: JSON.stringify(body),
        });
      }
      if (selected?.kind === "detection_incident" && selected.incident_id) {
        return api<{ case_id: string }>("/detection-incidents/promote", {
          method: "POST",
          body: JSON.stringify({
            ...body,
            incident_id: selected.incident_id,
            incident_title: selected.title || "",
            severity: selected.severity || undefined,
          }),
        });
      }
      throw new Error("Select an item that supports case promotion");
    },
    onSuccess: (data) => {
      toast.push(`Promoted to case ${data.case_id}`, "ok");
      qc.invalidateQueries({ queryKey: ["triage"] });
      qc.invalidateQueries({ queryKey: ["triage-detection-incidents"] });
      qc.invalidateQueries({ queryKey: ["cases"] });
    },
    onError: (err) => toast.push(err instanceof Error ? err.message : "Promote failed", "bad"),
  });

  const ack = useMutation({
    mutationFn: async () => {
      if (selected?.alert_id) {
        return api(`/alerts/${selected.alert_id}/acknowledge`, { method: "POST" });
      }
      if (selected?.detection_key || selected?.kind === "detection") {
        const detection_key = selected.detection_key || selected.raw?.source_file;
        if (!detection_key) throw new Error("Detection key missing");
        return api("/detections/acknowledge", {
          method: "POST",
          body: JSON.stringify({ detection_key }),
        });
      }
      if (selected?.event_id || selected?.kind === "webhook_event") {
        const eventId = selected.event_id || String(selected.id || "").replace(/^wh:/, "");
        return api(`/webhook-events/${eventId}/acknowledge`, { method: "POST" });
      }
      if (selected?.kind === "detection_incident" && selected.incident_id) {
        return detectionApi.acknowledge(String(selected.incident_id));
      }
      throw new Error("Select an item to acknowledge");
    },
    onSuccess: () => {
      toast.push("Acknowledged", "ok");
      qc.invalidateQueries({ queryKey: ["triage"] });
      qc.invalidateQueries({ queryKey: ["triage-detection-incidents"] });
    },
    onError: (err) => toast.push(err instanceof Error ? err.message : "Ack failed", "bad"),
  });

  const enrich = useMutation({
    mutationFn: async () => {
      const iocType = String(selected?.ioc_type || "").toLowerCase();
      const iocValue = String(selected?.ioc_value || "");
      if (!iocType || !iocValue) throw new Error("Selected item has no IOC to enrich");
      return api("/enrich", {
        method: "POST",
        body: JSON.stringify({ ioc_type: iocType, ioc_value: iocValue }),
      });
    },
    onSuccess: () => toast.push("Enrichment requested", "ok"),
    onError: (err) => toast.push(err instanceof Error ? err.message : "Enrich failed", "bad"),
  });

  const runPlaybook = useMutation({
    mutationFn: async () => {
      if (!playbookId) throw new Error("Select a playbook");
      return api(`/playbooks/${playbookId}/run`, {
        method: "POST",
        body: JSON.stringify({
          context: {
            alert_id: selected?.alert_id,
            event_id: selected?.event_id,
            detection_key: selected?.detection_key,
            ioc_type: selected?.ioc_type,
            ioc_value: selected?.ioc_value,
            title: selected?.title,
            source: selected?.source,
            kind: selected?.kind,
          },
        }),
      });
    },
    onSuccess: () => {
      toast.push("Playbook started", "ok");
      qc.invalidateQueries({ queryKey: ["playbook-runs"] });
    },
    onError: (err) => toast.push(err instanceof Error ? err.message : "Playbook failed", "bad"),
  });

  const tipRows = triage.data?.items || (Array.isArray(triage.data) ? triage.data as any[] : []);
  const rows = [...(detectionIncidents.data || []), ...tipRows];
  const playbookRows = playbooks.data?.playbooks || [];
  const canDispose = !!(
    selected?.alert_id
    || selected?.detection_key
    || selected?.kind === "detection"
    || selected?.event_id
    || selected?.kind === "webhook_event"
    || (selected?.kind === "detection_incident" && selected?.incident_id)
  );
  const canPromote = canDispose;

  return <>
    <Heading
      kicker="Operations"
      title="Unified triage"
      subtitle="Merge watchlist alerts, connector detections, webhook events, and detection-spine incidents. Acknowledge, disposition, enrich, run a playbook, or promote to a case."
      actions={<>
        <Link className="button secondary compact" to="/incidents">Incidents</Link>
        <Link className="button secondary compact" to="/hunt">Hunt</Link>
        <Link className="button secondary compact" to="/analytics">Analytics</Link>
      </>}
    />
    <OpsSurfaceKpis metrics="mtta,fpr,alert_case_ratio,escalation_rate" />
    <ErrorState error={triage.error} />
    <div className="result-grid">
      <section className="card">
        <div className="section-head"><div><span className="section-kicker">Queue</span><h2>Open items</h2></div><span className="count-badge">{rows.length}</span></div>
        <DataTable
          searchable
          columns={[
            { key: "severity", label: "Severity", sortable: true },
            { key: "kind", label: "Kind", render: (row: any) => humanizeLabel(String(row.kind || "item")) },
            { key: "source", label: "Source", sortable: true },
            { key: "title", label: "Title", clip: true, render: (row: any) => (
              <button type="button" className="ghost compact" onClick={() => setSelected(row)}>{row.title || row.ioc_value || row.alert_id || row.id}</button>
            ) },
            { key: "ioc", label: "IOC", clip: true, render: (row: any) => row.ioc || (row.ioc_type ? `${row.ioc_type}: ${row.ioc_value}` : "—") },
            { key: "technique_ids", label: "ATT&CK", render: (row: any) => (row.technique_ids || row.raw?.technique_ids || []).join(", ") || "—" },
            { key: "disposition", label: "Disposition", render: (row: any) => row.disposition ? humanizeLabel(String(row.disposition)) : "—" },
            { key: "age", label: "Age", nowrap: true, render: (row: any) => row.age || formatWhen(row.triggered_at || row.event_time || row.indexed_at) },
          ]}
          rows={rows}
          rowKey={(row: any, i) => row.alert_id || row.detection_key || row.event_id || row.incident_id || row.id || String(i)}
          empty={<EmptyState title="Triage queue empty" description="Watchlist hits, connector detections, webhook events, and detection-spine incidents will land here." compact />}
        />
      </section>
      <section className="card">
        <div className="section-head"><div><span className="section-kicker">Detail</span><h2>Selected item</h2></div></div>
        {!selected ? <EmptyState title="Select an item" description="Choose a row to acknowledge, disposition, enrich, or promote." compact /> : <>
          <p><strong>{selected.title || selected.ioc_value || selected.alert_id}</strong></p>
          <p className="muted">{humanizeLabel(selected.kind || "item")} · {humanizeLabel(selected.source || "source")} · {formatWhen(selected.triggered_at || selected.event_time || selected.indexed_at)}</p>
          {selected.disposition && <p>Disposition: <span className="status completed">{humanizeLabel(String(selected.disposition))}</span></p>}
          {selected.promoted_case_id && <p>Linked case: <Link to="/cases">{selected.promoted_case_id}</Link></p>}
          {selected.kind === "detection_incident" && selected.incident_id && (
            <p>Detection incident: <Link to={`/incidents/${selected.incident_id}`}>{selected.incident_id}</Link> (Postgres SoR — open for disposition / timeline).</p>
          )}
          {isOperational(user.role) && <>
            {canDispose && <>
              <label>Disposition
                <select value={disposition} onChange={(e) => setDisposition(e.target.value as typeof DISPOSITIONS[number])}>
                  {DISPOSITIONS.map((d) => <option key={d} value={d}>{humanizeLabel(d)}</option>)}
                </select>
              </label>
              <label>Note<textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} /></label>
              {selected.alert_id && disposition === "false_positive" && (
                <>
                  <label className="check setting-toggle">
                    <input type="checkbox" checked={suppress} onChange={(e) => setSuppress(e.target.checked)} />
                    Suppress / lower watchlist confidence
                  </label>
                  <label className="check setting-toggle">
                    <input type="checkbox" checked={mispNote} onChange={(e) => setMispNote(e.target.checked)} />
                    Publish FP note to MISP (when configured)
                  </label>
                </>
              )}
            </>}
            <label>Playbook
              <select value={playbookId} onChange={(e) => setPlaybookId(e.target.value)}>
                <option value="">Select playbook…</option>
                {playbookRows.map((pb: any) => (
                  <option key={pb.id || pb.playbook_id} value={pb.id || pb.playbook_id}>{pb.name}</option>
                ))}
              </select>
            </label>
            <div className="triage-actions">
              <button type="button" onClick={() => ack.mutate()} disabled={ack.isPending || !canDispose}>Acknowledge</button>
              {canDispose && <button type="button" onClick={() => dispose.mutate()} disabled={dispose.isPending}>Save disposition</button>}
              {canPromote && <button type="button" className="secondary" onClick={() => promote.mutate()} disabled={promote.isPending}>Promote to case</button>}
              {(selected.ioc_type && selected.ioc_value) && (
                <button type="button" className="secondary" onClick={() => enrich.mutate()} disabled={enrich.isPending}>Enrich IOC</button>
              )}
              <button type="button" className="secondary" onClick={() => runPlaybook.mutate()} disabled={runPlaybook.isPending || !playbookId}>Run playbook</button>
              <Link className="button ghost compact" to={`/search?q=${encodeURIComponent(selected.ioc_value || selected.title || "")}`}>Search</Link>
              <Link className="button ghost compact" to="/hunt">Hunt</Link>
              <Link className="button ghost compact" to="/graph">Graph</Link>
              <Link className="button ghost compact" to="/response-queue">SOAR queue</Link>
            </div>
          </>}
          {selected.kind === "detection" && <p className="muted">Connector detection disposition is stored locally for quality metrics — not a vendor console clone.</p>}
          {selected.kind === "webhook_event" && <p className="muted">Webhook events enter triage for review; related watchlist alerts (if any) remain separately dispositionable.</p>}
          {selected.kind === "detection_incident" && <p className="muted">Streaming detection-spine incident — dispositions and timeline live in Postgres via /incidents.</p>}
        </>}
      </section>
    </div>
  </>;
}

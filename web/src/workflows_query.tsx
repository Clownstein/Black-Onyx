import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { api } from "./api";
import { useToast } from "./components/toast";
import { DataTable, EmptyState, ErrorState, Heading, downloadJson } from "./ui";

const STORAGE_KEY = "blackonyx_saved_queries_v1";

const EXAMPLES = [
  'alerts | where disposition == "false_positive" | limit 50',
  "cases | where status == \"open\" | project title, priority, created_at",
  "detections | where indexed_at ago 7d | limit 50",
  "assets | where criticality == \"high\" | limit 100",
  'evidence | where text contains "powershell" | project collection, source_file, text | limit 50',
  'evidence | where indexed_at ago 7d | project collection, point_id, source_file | limit 100',
  'webhooks | where created_at ago 7d | project webhook_name, ioc_count, disposition | limit 50',
  'alerts | where disposition in ("false_positive", "informational") | sort triggered_at desc | limit 50',
  'cases | where status != "closed" | summarize count() by priority',
];

type SavedQuery = { name: string; query: string };

function loadSaved(): SavedQuery[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((item) => item?.name && item?.query) : [];
  } catch {
    return [];
  }
}

export function QueryWorkflow() {
  const toast = useToast();
  const [query, setQuery] = useState(EXAMPLES[0]);
  const [rows, setRows] = useState<any[]>([]);
  const [columns, setColumns] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState<SavedQuery[]>([]);
  const [saveName, setSaveName] = useState("");

  useEffect(() => { setSaved(loadSaved()); }, []);

  const run = useMutation({
    mutationFn: () => api<{ columns: string[]; rows: any[]; n?: number }>("/query", {
      method: "POST",
      body: JSON.stringify({ query }),
    }),
    onSuccess: (data) => {
      setError("");
      setColumns(data.columns || (data.rows?.[0] ? Object.keys(data.rows[0]) : []));
      setRows(data.rows || []);
      toast.push(`Returned ${data.rows?.length ?? 0} row(s)`, "ok");
    },
    onError: (err) => {
      const message = err instanceof Error ? err.message : "Query failed";
      setError(message);
      toast.push(message, "bad");
    },
  });

  function persist(next: SavedQuery[]) {
    setSaved(next);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  }

  async function promoteRow(row: any) {
    const title = row.title || row.hostname || row.ioc_value || row.name || "Query promotion";
    try {
      const created = await api<{ case_id: string }>("/cases", {
        method: "POST",
        body: JSON.stringify({
          title: `Query: ${String(title).slice(0, 120)}`,
          description: `Promoted from Query workspace.\n\nQuery:\n${query}\n\nRow:\n${JSON.stringify(row, null, 2)}`,
          priority: "medium",
          tags: ["query-promote"],
        }),
      });
      toast.push(`Created case ${created.case_id}`, "ok");
    } catch (err) {
      toast.push(err instanceof Error ? err.message : "Promote failed", "bad");
    }
  }

  return <>
    <Heading
      kicker="Investigate"
      title="Query"
      subtitle="KQL/SPL-inspired filters over alerts, cases, detections, and assets. Complements semantic Search."
      actions={<Link className="button secondary compact" to="/search">Semantic search</Link>}
    />
    <section className="card">
      <div className="section-head"><div><span className="section-kicker">Editor</span><h2>Run query</h2></div>
        <button type="button" onClick={() => run.mutate()} disabled={run.isPending}>Run</button>
      </div>
      <div className="prompt-chips">
        {EXAMPLES.map((example) => (
          <button key={example} type="button" className="ghost compact" onClick={() => setQuery(example)}>{example.slice(0, 42)}…</button>
        ))}
      </div>
      {saved.length > 0 && <div className="prompt-chips">
        {saved.map((item) => (
          <button key={item.name} type="button" className="secondary compact" onClick={() => setQuery(item.query)} title={item.query}>{item.name}</button>
        ))}
      </div>}
      <label>Query<textarea className="query-editor" rows={6} value={query} onChange={(e) => setQuery(e.target.value)} /></label>
      <div className="field-row">
        <label>Save as<input value={saveName} onChange={(e) => setSaveName(e.target.value)} placeholder="My triage filter" /></label>
        <button type="button" className="secondary" disabled={!saveName.trim() || !query.trim()} onClick={() => {
          const next = [{ name: saveName.trim(), query }, ...saved.filter((item) => item.name !== saveName.trim())].slice(0, 20);
          persist(next);
          setSaveName("");
          toast.push("Query saved", "ok");
        }}>Save query</button>
      </div>
      <p className="muted">Supported subset: <code>where == / != / contains / in / ago</code>, <code>project</code>, <code>sort</code>, <code>summarize count() by</code>, <code>limit</code>.</p>
      <ErrorState error={error} />
    </section>
    <section className="card">
      <div className="section-head"><div><span className="section-kicker">Results</span><h2>Table</h2></div>
        <div className="actions">
          <button type="button" className="secondary compact" disabled={!rows.length} onClick={() => downloadJson("query-results.json", rows)}>Export JSON</button>
          <button type="button" className="secondary compact" disabled={!rows.length} onClick={() => {
            const cols = columns.length ? columns : Object.keys(rows[0] || {});
            const csv = [cols.join(","), ...rows.map((row) => cols.map((c) => JSON.stringify(row[c] ?? "")).join(","))].join("\n");
            const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
            const a = document.createElement("a"); a.href = url; a.download = "query-results.csv"; a.click(); URL.revokeObjectURL(url);
          }}>Export CSV</button>
          <Link className="button ghost compact" to="/triage">Open triage</Link>
          <Link className="button ghost compact" to="/graph">Graph</Link>
        </div>
      </div>
      <DataTable
        searchable
        columns={[
          ...(columns.length ? columns : Object.keys(rows[0] || { result: "" })).map((key) => ({ key, label: key, clip: true, sortable: true })),
          {
            key: "_actions",
            label: "Actions",
            sortable: false,
            render: (row: any) => {
              const hunt = String(row.ioc_value || row.hostname || row.technique_id || row.title || row.source_file || "").trim();
              return <div className="actions">
                <button type="button" className="ghost compact" onClick={() => promoteRow(row)}>Promote</button>
                {hunt && <Link className="button ghost compact" to={`/triage`}>Triage</Link>}
                {hunt && <Link className="button ghost compact" to={`/search?q=${encodeURIComponent(hunt)}`}>Search</Link>}
                {hunt && <Link className="button ghost compact" to={`/graph`}>Graph</Link>}
              </div>;
            },
          },
        ]}
        rows={rows}
        rowKey={(row, i) => String(row.id || row.alert_id || row.case_id || i)}
        empty={<EmptyState title="No results" description="Run a query against operational tables." compact />}
      />
    </section>
  </>;
}

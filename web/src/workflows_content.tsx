import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { DataTable, EmptyState, ErrorState, Heading, formatWhen, humanizeLabel } from "./ui";

/** Content / intel library: reports, digests, playbook docs — CMS layout patterns only. */
export function ContentWorkflow() {
  const [filter, setFilter] = useState<"all" | "intel" | "ops_digest">("all");
  const reports = useQuery({
    queryKey: ["reports-library", filter],
    queryFn: async () => {
      try {
        const q = filter === "all" ? "" : `?template=${filter}`;
        return await api<any>(`/reports${q}`);
      } catch {
        return { reports: [] };
      }
    },
  });
  const playbooks = useQuery({
    queryKey: ["playbooks-library"],
    queryFn: async () => {
      try {
        return await api<any>("/playbooks");
      } catch {
        return { playbooks: [] };
      }
    },
  });

  const reportRows = reports.data?.reports || reports.data?.items || (Array.isArray(reports.data) ? reports.data : []);
  const playbookRows = playbooks.data?.playbooks || playbooks.data?.items || (Array.isArray(playbooks.data) ? playbooks.data : []);
  const intelCount = reportRows.filter((r: any) => (r.template || "intel") === "intel").length;
  const digestCount = reportRows.filter((r: any) => r.template === "ops_digest").length;

  return <>
    <Heading
      kicker="Content"
      title="Intel & content library"
      subtitle="Generated intel briefs, ops digests, and playbook documentation for analyst handoff."
      actions={<Link className="button compact" to="/reports">Generate report</Link>}
    />
    <ErrorState error={reports.error || playbooks.error} />
    <div className="tabs" role="tablist" aria-label="Report templates">
      {([
        ["all", `All (${reportRows.length})`],
        ["intel", `Intel briefs${filter === "all" ? ` (${intelCount})` : ""}`],
        ["ops_digest", `Ops digests${filter === "all" ? ` (${digestCount})` : ""}`],
      ] as const).map(([id, label]) => (
        <button key={id} type="button" role="tab" aria-selected={filter === id} onClick={() => setFilter(id)}>{label}</button>
      ))}
    </div>
    <div className="content-library-grid">
      <section className="card">
        <div className="section-head"><div><span className="section-kicker">Reports</span><h2>Library</h2></div><Link className="button secondary compact" to="/reports">Open</Link></div>
        <DataTable
          searchable
          columns={[
            { key: "title", label: "Title", clip: true },
            { key: "template", label: "Template", render: (row: any) => humanizeLabel(String(row.template || "intel")) },
            { key: "format", label: "Format" },
            { key: "created_by", label: "Author", render: (row: any) => row.created_by || "—" },
            { key: "created_at", label: "Created", nowrap: true, render: (row: any) => formatWhen(row.created_at || row.generated_at) },
            { key: "download", label: "Download", render: (row: any) => {
              const id = row.report_id || row.id;
              if (!id) return "—";
              const fmt = row.format || "markdown";
              return <a className="button compact secondary" href={`/api/v1/reports/${id}/download?format=${fmt}`}>Download</a>;
            } },
          ]}
          rows={reportRows}
          rowKey={(row: any, i) => row.report_id || row.id || row.title || String(i)}
          empty={<EmptyState title="No saved reports" description="Generate an ops digest or intel brief from Reports — they persist here for the team." compact />}
        />
      </section>
      <section className="card">
        <div className="section-head"><div><span className="section-kicker">Playbooks</span><h2>Documentation</h2></div><Link className="button secondary compact" to="/playbooks">Open</Link></div>
        <DataTable
          searchable
          columns={[
            { key: "name", label: "Playbook", render: (row: any) => row.name || row.title },
            { key: "status", label: "Status" },
            { key: "updated_at", label: "Updated", nowrap: true, render: (row: any) => formatWhen(row.updated_at) },
          ]}
          rows={playbookRows}
          rowKey={(row: any, i) => row.id || row.name || String(i)}
          empty={<EmptyState title="No playbook docs" description="Approved playbooks appear here for quick reference." compact />}
        />
      </section>
      <section className="card">
        <div className="section-head"><div><span className="section-kicker">Templates</span><h2>Quick create</h2></div></div>
        <p className="muted">Intel briefs sanitize IOC packages. Ops digests include disposition-aware MTTA/MTTR/FPR with sample sizes.</p>
        <div className="actions">
          <Link className="button" to="/reports">Create intel brief</Link>
          <Link className="button secondary" to="/reports">Create ops digest</Link>
          <Link className="button ghost" to="/analytics">Open analytics</Link>
        </div>
      </section>
    </div>
  </>;
}

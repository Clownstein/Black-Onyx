import React from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { KpiRow, KpiItem } from "./kpi";

const LABELS: Record<string, { label: string; href?: string }> = {
  mtta: { label: "MTTA", href: "/triage" },
  mtti: { label: "MTTI", href: "/cases" },
  ingest_latency: { label: "Ingest latency", href: "/detections" },
  intel_hit_rate: { label: "Intel hit rate", href: "/watchlists" },
  automation_success: { label: "Automation success", href: "/playbooks" },
  mttr: { label: "MTTR", href: "/cases" },
  fpr: { label: "FPR", href: "/analytics" },
  alert_case_ratio: { label: "Alert→case", href: "/triage" },
  fresh_ioc_ratio: { label: "Fresh IOC %", href: "/decay" },
  closure_rate: { label: "Closure rate", href: "/cases" },
  escalation_rate: { label: "Escalation", href: "/cases" },
  reopen_rate: { label: "Reopen rate", href: "/cases" },
  sla_breach_rate: { label: "SLA breach", href: "/cases" },
};

/** Compact disposition-aware KPI strip for embedding on ops pages. */
export function OpsSurfaceKpis({
  metrics = "mtta,mttr,fpr,alert_case_ratio,fresh_ioc_ratio",
  range = "30d",
  extras = [],
}: {
  metrics?: string;
  range?: string;
  extras?: KpiItem[];
}) {
  const keys = metrics.split(",").map((m) => m.trim()).filter(Boolean);
  const kpis = useQuery({
    queryKey: ["ops-surface-kpis", metrics, range],
    queryFn: () => api<{ metrics: Record<string, any> }>(`/analytics/kpis?metrics=${keys.join(",")}&range=${range}`),
  });
  const data = kpis.data?.metrics || {};
  const items: KpiItem[] = keys.map((key) => {
    const meta = LABELS[key] || { label: key };
    const row = data[key] || {};
    const value = row.value ?? row.seconds ?? row.rate ?? row.ratio;
    let display: React.ReactNode = "—";
    if (typeof value === "number") {
      if (key.startsWith("mtt")) display = `${Math.round(value / 60)}m`;
      else if (key.includes("ratio") || key === "fpr" || key.endsWith("_rate")) display = `${(value * 100).toFixed(1)}%`;
      else display = value;
    }
    return { label: meta.label, value: display, n: row.n, hint: row.hint, href: meta.href };
  });
  return <KpiRow items={[...items, ...extras]} />;
}

import React, { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Sparkline } from "./charts";
import { formatCount } from "../ui";

export type KpiItem = {
  label: string;
  value: ReactNode;
  hint?: string;
  n?: number;
  sparkline?: number[];
  href?: string;
  tone?: "ok" | "warn" | "bad";
};

export function KpiCard({ item }: { item: KpiItem }) {
  const body = (
    <article className={`kpi-card ${item.tone ? `tone-${item.tone}` : ""}`}>
      <span className="kpi-label">{item.label}</span>
      <strong className="kpi-value">{typeof item.value === "number" ? formatCount(item.value) : item.value}</strong>
      {(item.hint || item.n != null) && (
        <small className="kpi-hint">{item.hint}{item.n != null ? ` · n=${item.n}` : ""}</small>
      )}
      {item.sparkline && item.sparkline.length > 1 && <Sparkline data={item.sparkline} />}
    </article>
  );
  return item.href ? <Link className="kpi-link" to={item.href}>{body}</Link> : body;
}

export function KpiRow({ items }: { items: KpiItem[] }) {
  if (!items.length) return null;
  return <div className="kpi-row">{items.map((item) => <KpiCard key={item.label} item={item} />)}</div>;
}

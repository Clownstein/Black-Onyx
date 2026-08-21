import { useMemo, useState } from "react";
import { EmptyState } from "./ui";

export type HeatmapTechnique = { technique_id: string; name?: string; count?: number };
export type HeatmapTactic = { tactic: string; techniques: HeatmapTechnique[] };
export type HeatmapData = { tactics?: HeatmapTactic[] };

/** Canonical Enterprise ATT&CK kill-chain order; anything unmapped is appended. */
const TACTIC_ORDER = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
];

function tacticLabel(value: string) {
  return value.replace(/[-_]+/g, " ").replace(/\b\w/g, character => character.toUpperCase());
}

function cellStyle(count: number, max: number) {
  if (max <= 0) return { background: "rgba(113, 151, 178, .08)", borderColor: "rgba(132, 169, 195, .19)" };
  const ratio = Math.min(1, count / max);
  return {
    background: `rgba(75, 212, 189, ${(0.09 + ratio * 0.46).toFixed(3)})`,
    borderColor: `rgba(75, 212, 189, ${(0.18 + ratio * 0.42).toFixed(3)})`,
  };
}

/**
 * ATT&CK matrix: one column per tactic in kill-chain order, one cell per
 * technique shaded by sighting count.
 */
export function AttackHeatmap({ data }: { data: HeatmapData }) {
  const [selected, setSelected] = useState<(HeatmapTechnique & { tactic: string }) | null>(null);
  const columns = useMemo(() => {
    const tactics = (data?.tactics || []).filter(entry => entry && entry.tactic);
    return [...tactics].sort((left, right) => {
      const leftIndex = TACTIC_ORDER.indexOf(String(left.tactic).toLowerCase());
      const rightIndex = TACTIC_ORDER.indexOf(String(right.tactic).toLowerCase());
      if (leftIndex === -1 && rightIndex === -1) return String(left.tactic).localeCompare(String(right.tactic));
      if (leftIndex === -1) return 1;
      if (rightIndex === -1) return -1;
      return leftIndex - rightIndex;
    });
  }, [data]);

  const max = useMemo(() => columns.reduce((highest, column) => column.techniques.reduce((inner, technique) => Math.max(inner, Number(technique.count) || 1), highest), 0), [columns]);
  const totalTechniques = useMemo(() => new Set(columns.flatMap(column => column.techniques.map(technique => technique.technique_id))).size, [columns]);
  const totalSightings = useMemo(() => columns.reduce((sum, column) => sum + column.techniques.reduce((inner, technique) => inner + (Number(technique.count) || 1), 0), 0), [columns]);

  if (!columns.length) {
    return <EmptyState title="Nothing mapped yet" description="Enter valid technique IDs such as T1566 or T1059 and build the heatmap to populate the matrix." compact />;
  }

  return <div className="heatmap">
    <div className="heatmap-summary">
      <span><b>{columns.length}</b> tactics</span>
      <span><b>{totalTechniques}</b> techniques</span>
      <span><b>{totalSightings}</b> mapped occurrences</span>
      <span className="heatmap-legend">Low<i className="scale" />High</span>
    </div>
    <div className="heatmap-scroll">
      <div className="heatmap-matrix">
        {columns.map(column => <div className="heatmap-column" key={column.tactic}>
          <div className="heatmap-column-head">
            <b>{tacticLabel(String(column.tactic))}</b>
            <small>{column.techniques.length} technique{column.techniques.length === 1 ? "" : "s"}</small>
          </div>
          {column.techniques.map(technique => {
            const count = Number(technique.count) || 1;
            const active = selected?.technique_id === technique.technique_id && selected?.tactic === column.tactic;
            return <button
              type="button"
              key={`${column.tactic}-${technique.technique_id}`}
              className={`heatmap-cell${active ? " selected" : ""}`}
              style={cellStyle(count, max)}
              onClick={() => setSelected(active ? null : { ...technique, tactic: String(column.tactic) })}
              title={`${technique.technique_id} · ${technique.name || "Unknown"} · ${count} occurrence(s)`}
            >
              <span className="heatmap-cell-id">{technique.technique_id}</span>
              <span className="heatmap-cell-name">{technique.name || "Unknown technique"}</span>
              <span className="heatmap-cell-count">{count}</span>
            </button>;
          })}
        </div>)}
      </div>
    </div>
    {selected && <div className="heatmap-detail">
      <div>
        <span className="section-kicker">{tacticLabel(selected.tactic)}</span>
        <b>{selected.technique_id} · {selected.name || "Unknown technique"}</b>
        <p>{Number(selected.count) || 1} occurrence(s) in the current selection.</p>
      </div>
      <a className="button secondary" href={`https://attack.mitre.org/techniques/${selected.technique_id.replace(".", "/")}/`} target="_blank" rel="noreferrer">Open in ATT&CK</a>
    </div>}
  </div>;
}

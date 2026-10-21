import { describe, expect, it } from "vitest";
import { triageDestinations } from "./triage_pivot";

/** Mirrors triage mapping for detection-spine incidents (incident_id SoR field). */
function mapDetectionIncident(inc: { incident_id?: string; id?: string; title?: string }) {
  const incidentId = String(inc.incident_id || inc.id || "").trim();
  if (!incidentId) return null;
  return {
    kind: "detection_incident",
    id: `di:${incidentId}`,
    incident_id: incidentId,
    title: inc.title || incidentId,
  };
}

describe("detection triage id mapping", () => {
  it("prefers incident_id over id", () => {
    const row = mapDetectionIncident({ incident_id: "inc-abc", id: "wrong", title: "T" });
    expect(row?.incident_id).toBe("inc-abc");
    expect(row?.id).toBe("di:inc-abc");
  });

  it("falls back to id when incident_id missing", () => {
    const row = mapDetectionIncident({ id: "inc-xyz" });
    expect(row?.incident_id).toBe("inc-xyz");
  });

  it("drops rows without any id", () => {
    expect(mapDetectionIncident({ title: "orphan" })).toBeNull();
  });
});

describe("triage destination pivot", () => {
  it("carries the incident id into hunt, graph, and the response queue", () => {
    const links = triageDestinations({
      incident_id: "inc-586ec3bac314",
      title: "Correlated anomaly on wazuh:007",
      technique_ids: ["T1558"],
    }, "auto-enrich");
    expect(links.hunt).toContain("incident=inc-586ec3bac314");
    expect(links.hunt).toContain("q=inc-586ec3bac314");
    expect(links.hunt).toContain("playbook=auto-enrich");
    expect(links.hunt).toContain("techniques=T1558");
    expect(links.graph).toContain("q=wazuh%3A007");
    expect(links.graph).toContain("incident=inc-586ec3bac314");
    expect(links.response).toBe("/response-queue?incident=inc-586ec3bac314&playbook=auto-enrich");
  });

  it("falls back to the title when there is no incident id", () => {
    const links = triageDestinations({ title: "watchlist hit" }, "");
    expect(links.hunt).toBe("/hunt?q=watchlist+hit");
    expect(links.graph).toBe("/graph?q=watchlist+hit");
    expect(links.response).toBe("/response-queue");
  });
});

import { describe, expect, it } from "vitest";

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

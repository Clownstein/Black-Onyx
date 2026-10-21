export type TriagePivotItem = {
  incident_id?: string
  title?: string
  ioc_value?: string
  technique_ids?: unknown
  raw?: { technique_ids?: unknown }
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : ""
}

function graphNeedle(ioc: string, title: string, incident: string): string {
  if (ioc) return ioc
  const asset = title.match(/\bon\s+(\S+)\s*$/i)?.[1]?.replace(/[.,;]+$/g, "")
  if (asset) return asset
  return title || incident
}

function techniqueList(...groups: unknown[]): string[] {
  const seen = new Set<string>()
  for (const group of groups) {
    if (!Array.isArray(group)) continue
    for (const item of group) {
      const id = text(item)
      if (id) seen.add(id)
    }
  }
  return [...seen]
}

/** Query strings that carry a selected triage item into Hunt, Graph, and the response queue. */
export function triageDestinations(selected: TriagePivotItem | null | undefined, playbookId = "") {
  const incident = text(selected?.incident_id)
  const ioc = text(selected?.ioc_value)
  const title = text(selected?.title)
  const huntQuery = incident || ioc || title
  const graphQuery = graphNeedle(ioc, title, incident)
  const techniques = techniqueList(selected?.technique_ids, selected?.raw?.technique_ids)
  const playbook = playbookId.trim()
  const shared = new URLSearchParams()
  if (incident) shared.set("incident", incident)
  if (techniques.length) shared.set("techniques", techniques.join(","))
  if (playbook) shared.set("playbook", playbook)

  const hunt = new URLSearchParams(shared)
  if (huntQuery) hunt.set("q", huntQuery)
  const graph = new URLSearchParams(shared)
  if (graphQuery) graph.set("q", graphQuery)
  const response = new URLSearchParams()
  if (incident) response.set("incident", incident)
  if (playbook) response.set("playbook", playbook)

  return {
    hunt: hunt.toString() ? `/hunt?${hunt}` : "/hunt",
    graph: graph.toString() ? `/graph?${graph}` : "/graph",
    response: response.toString() ? `/response-queue?${response}` : "/response-queue",
  }
}

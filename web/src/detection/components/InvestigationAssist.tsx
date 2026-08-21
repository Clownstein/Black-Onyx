import { useState } from 'react'
import { api } from '../../api'
import type { Incident } from '../api/contracts'

type Props = {
  incident: Incident
  onUseDraft?: (text: string) => void
}

type ChatResponse = {
  response: string
  session_id: string
  model: string
}

function investigationPrompt(incident: Incident): string {
  return [
    'Act as a blue-team SOC investigation assistant.',
    'Produce concise, suggest-only investigation notes in Markdown.',
    'Do not claim evidence that is absent and never instruct automatic containment.',
    'Include hypotheses, evidence to validate, and next questions.',
    `Incident: ${incident.title}`,
    `Summary: ${incident.summary}`,
    `Severity: ${incident.severity}`,
    `Risk score: ${incident.risk_score}`,
    `Assets: ${incident.assets.join(', ') || 'none recorded'}`,
    `Services: ${incident.services.join(', ') || 'none recorded'}`,
    `Context: ${JSON.stringify(incident.context ?? {})}`,
  ].join('\n')
}

function localTemplateDraft(incident: Incident): string {
  const findings = (incident.finding_ids ?? []).map((id) => `- \`${id}\``).join('\n') || '- none recorded'
  const assets = incident.assets.map((a) => `- \`${a}\``).join('\n') || '- none recorded'
  const evidence = (incident.evidence ?? [])
    .slice(0, 8)
    .map((e) => `- **${e.kind}** / ${e.model}: ${e.title}`)
    .join('\n') || '- none attached'
  return [
    `# Investigation draft (local template)`,
    ``,
    `> Suggest-only. Generated locally because the chat assistant was unavailable.`,
    `> Do not treat this as confirmed evidence or authorization to contain.`,
    ``,
    `## Incident`,
    `- **Title:** ${incident.title}`,
    `- **Severity:** ${incident.severity}`,
    `- **Risk score:** ${incident.risk_score}`,
    `- **Status:** ${incident.status}`,
    `- **Summary:** ${incident.summary || '_none_'}`,
    ``,
    `## Assets`,
    assets,
    ``,
    `## Findings`,
    findings,
    ``,
    `## Evidence snapshot`,
    evidence,
    ``,
    `## Hypotheses (review)`,
    `1. Activity on the listed assets is related to the stated severity and needs confirmation.`,
    `2. Correlated findings may share a common service or change window.`,
    ``,
    `## Evidence to validate`,
    `- Confirm first/last seen windows against change and deploy history.`,
    `- Cross-check asset owners and services for expected maintenance.`,
    `- Review related incidents sharing the same assets or services.`,
    ``,
    `## Next questions`,
    `- What changed on these assets around first_seen?`,
    `- Are any findings false positives or expected noise?`,
    `- Which playbook would you suggest (not execute) if confirmed?`,
  ].join('\n')
}

export function InvestigationAssist({ incident, onUseDraft }: Props) {
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [source, setSource] = useState<'llm' | 'template' | null>(null)

  async function generate() {
    setBusy(true)
    setError(null)
    setSource(null)
    try {
      const result = await api<ChatResponse>('/chat', {
        method: 'POST',
        body: JSON.stringify({
          message: investigationPrompt(incident),
          use_rag: false,
          use_web_search: false,
        }),
      })
      if (!result.response.trim()) throw new Error('The configured LLM returned an empty draft')
      setDraft(result.response.trim())
      setSource('llm')
    } catch (e) {
      const template = localTemplateDraft(incident)
      setDraft(template)
      setSource('template')
      setError(
        `Chat assist unavailable (${e instanceof Error ? e.message : 'error'}); showing local template draft.`,
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <h2>Investigation assist</h2>
      <p className="muted">
        Suggest-only notes from the server-configured Black Onyx LLM provider when available; otherwise
        a local markdown template from incident fields. The draft never acknowledges, resolves, or
        executes playbooks.
      </p>
      <div className="actions" style={{ marginBottom: '0.75rem' }}>
        <button type="button" className="btn" disabled={busy} onClick={() => void generate()}>
          {busy ? 'Drafting…' : 'Generate draft'}
        </button>
        <button
          type="button"
          className="btn"
          disabled={!draft.trim() || !onUseDraft}
          onClick={() => onUseDraft?.(draft)}
        >
          Copy into comment
        </button>
      </div>
      {error ? <div className="error">{error}</div> : null}
      {source === 'template' && !error ? (
        <p className="muted">Local template draft (suggest-only).</p>
      ) : null}
      <textarea
        aria-label="Investigation draft"
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        rows={12}
        placeholder="Generate a draft to edit before posting…"
        style={{ width: '100%' }}
      />
    </section>
  )
}

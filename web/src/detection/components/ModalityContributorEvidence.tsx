import { useState } from 'react'
import type { EvidenceItem } from '../api/contracts'
import { api } from '../api/client'
import { ContributorList, EvidenceSection, extractRawContext } from './EvidencePanel'

type Contributor = {
  type?: string
  summary?: string
  contribution?: number
  template_id?: string
  name?: string
}

function asContributors(value: unknown): Contributor[] {
  return Array.isArray(value) ? (value as Contributor[]) : []
}

function refUri(item: unknown): string | null {
  if (typeof item === 'string' && item.trim()) return item.trim()
  if (item && typeof item === 'object' && typeof (item as { uri?: string }).uri === 'string') {
    const uri = (item as { uri: string }).uri.trim()
    return uri || null
  }
  return null
}

type Props = {
  item: EvidenceItem
  emptyMessage: string
}

export function ModalityContributorEvidence({ item, emptyMessage }: Props) {
  const { raw, context } = extractRawContext(item)
  const contributors = asContributors(raw.contributors)
  const refsRaw = Array.isArray(raw.evidence_refs) ? raw.evidence_refs : []
  const contextRefs = Array.isArray(context.evidence_refs) ? context.evidence_refs : []
  const evidenceRefs = [...refsRaw, ...contextRefs]
  const findingId = typeof raw.finding_id === 'string' ? raw.finding_id : null
  const [downloadError, setDownloadError] = useState<string | null>(null)
  const [busyUri, setBusyUri] = useState<string | null>(null)

  async function download(uri: string) {
    if (!findingId) {
      setDownloadError('Finding id missing; cannot download artifact.')
      return
    }
    setDownloadError(null)
    setBusyUri(uri)
    try {
      const { blob, filename } = await api.downloadFindingEvidence(findingId, uri)
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = filename
      anchor.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusyUri(null)
    }
  }

  const refUris = evidenceRefs.map(refUri).filter((u): u is string => u != null)

  return (
    <div className="modality-panel">
      {contributors.length > 0 ? (
        <EvidenceSection title="Contributors">
          <ContributorList
            items={contributors.map((c, idx) => ({
              key: `${c.type ?? 'c'}-${idx}`,
              label: c.summary ?? c.name ?? c.template_id ?? c.type ?? 'signal',
              value:
                c.contribution != null ? `${(c.contribution * 100).toFixed(0)}%` : '—',
            }))}
          />
        </EvidenceSection>
      ) : (
        <p className="muted" style={{ margin: 0 }}>
          {item.detail || emptyMessage}
        </p>
      )}

      {refUris.length > 0 ? (
        <EvidenceSection title="Evidence artifacts">
          <ul className="contributor-list">
            {refUris.map((uri) => (
              <li key={uri}>
                <span className="mono">{uri}</span>
                <button
                  type="button"
                  className="btn"
                  disabled={busyUri === uri}
                  onClick={() => void download(uri)}
                >
                  {busyUri === uri ? 'Downloading…' : 'Download'}
                </button>
              </li>
            ))}
          </ul>
          {downloadError ? <div className="error">{downloadError}</div> : null}
        </EvidenceSection>
      ) : null}

      {Object.keys(context).length > 0 ? (
        <EvidenceSection title="Context">
          <ul className="contributor-list">
            {Object.entries(context)
              .filter(([key]) => key !== 'evidence_refs')
              .slice(0, 12)
              .map(([key, value]) => (
                <li key={key}>
                  <span>{key}</span>
                  <span className="mono">{typeof value === 'string' ? value : JSON.stringify(value)}</span>
                </li>
              ))}
          </ul>
        </EvidenceSection>
      ) : null}
    </div>
  )
}

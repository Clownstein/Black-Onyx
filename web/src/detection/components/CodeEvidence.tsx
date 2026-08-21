import type { EvidenceItem } from '../api/contracts'
import { EvidenceEmpty, extractRawContext } from './EvidencePanel'

type FileHit = {
  path?: string
  line?: number
  risk?: string
}

type Contributor = {
  summary?: string
  type?: string
  contribution?: number
  path?: string
  line?: number
}

type Props = {
  item: EvidenceItem
}

function asFiles(raw: Record<string, unknown>, context: Record<string, unknown>): FileHit[] {
  const files = raw.files ?? context.files
  if (!Array.isArray(files)) return []
  return files.map((entry) => {
    if (typeof entry === 'string') return { path: entry }
    if (entry && typeof entry === 'object') return entry as FileHit
    return {}
  })
}

export function CodeEvidence({ item }: Props) {
  const { raw, context } = extractRawContext(item)
  const files = asFiles(raw, context)
  const contributors = Array.isArray(raw.contributors)
    ? (raw.contributors as Contributor[])
    : []
  const commit =
    typeof raw.commit === 'string'
      ? raw.commit
      : typeof context.commit === 'string'
        ? String(context.commit)
        : null
  const prUrl =
    typeof raw.pr_url === 'string'
      ? raw.pr_url
      : typeof context.pr_url === 'string'
        ? String(context.pr_url)
        : null
  const diff =
    typeof raw.diff === 'string'
      ? raw.diff
      : typeof context.diff === 'string'
        ? String(context.diff)
        : null
  const advisory =
    typeof raw.advisory === 'string'
      ? raw.advisory
      : 'Code findings are advisory risk signals correlated to deployments; they are not proof of a vulnerability or exploit.'

  return (
    <div className="modality-panel">
      <div className="callout callout-advisory" role="note">
        <strong>Advisory</strong>
        <p>{advisory}</p>
      </div>

      {commit ? (
        <p className="muted" style={{ margin: '0 0 0.5rem' }}>
          Commit <span className="mono">{commit}</span>
          {prUrl ? (
            <>
              {' '}
              ·{' '}
              <a href={prUrl} target="_blank" rel="noreferrer">
                Pull request
              </a>
            </>
          ) : null}
        </p>
      ) : null}

      {diff ? (
        <section>
          <h5>Unified diff</h5>
          <pre className="mono" style={{ whiteSpace: 'pre-wrap', fontSize: '0.85rem' }}>
            {diff}
          </pre>
        </section>
      ) : null}

      {files.length > 0 ? (
        <section>
          <h5>File / line hits</h5>
          <ul className="contributor-list">
            {files.map((f, idx) => (
              <li key={`${f.path ?? 'file'}-${f.line ?? idx}`}>
                <span className="mono">
                  {f.path ?? 'unknown'}
                  {typeof f.line === 'number' ? `:${f.line}` : ''}
                </span>
                <span>{f.risk ?? 'risk signal'}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {contributors.length > 0 ? (
        <section>
          <h5>Scanner results</h5>
          <ul className="contributor-list">
            {contributors.map((c, idx) => (
              <li key={`${c.summary ?? c.type ?? 'scan'}-${idx}`}>
                <span>
                  {c.path ? (
                    <span className="mono">
                      {c.path}
                      {typeof c.line === 'number' ? `:${c.line}` : ''}{' '}
                    </span>
                  ) : null}
                  {c.summary ?? c.type ?? `finding-${idx + 1}`}
                </span>
                <span className="mono">
                  {typeof c.contribution === 'number' ? c.contribution.toFixed(2) : '—'}
                </span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {files.length === 0 && contributors.length === 0 && !diff ? (
        <EvidenceEmpty item={item} message="No file/line details in evidence payload." />
      ) : null}
    </div>
  )
}

import type { EvidenceItem } from '../api/contracts'
import { EvidenceEmpty, extractRawContext } from './EvidencePanel'

type PeerContributor = {
  peer?: string
  role?: string
  service?: string
  contribution?: number
  type?: string
  summary?: string
}

type TimelinePoint = {
  t?: string
  event?: string
  peer?: string
}

type Props = {
  item: EvidenceItem
}

function asPeers(raw: Record<string, unknown>, context: Record<string, unknown>): PeerContributor[] {
  if (Array.isArray(raw.peers)) return raw.peers as PeerContributor[]
  if (Array.isArray(raw.contributors)) {
    return (raw.contributors as PeerContributor[]).map((c) => ({
      peer: c.peer ?? c.summary ?? c.type,
      role: c.role ?? c.type ?? 'peer',
      service: c.service,
      contribution: c.contribution,
    }))
  }
  if (typeof raw.dst === 'string' || typeof context.dst === 'string') {
    return [
      {
        peer: String(raw.dst ?? context.dst),
        role: 'destination',
        service: typeof raw.service === 'string' ? raw.service : 'unknown',
        contribution: typeof raw.score === 'number' ? raw.score : undefined,
      },
    ]
  }
  return []
}

export function NetworkEvidence({ item }: Props) {
  const { raw, context } = extractRawContext(item)
  const peers = asPeers(raw, context)
  const timeline = Array.isArray(raw.timeline)
    ? (raw.timeline as TimelinePoint[])
    : Array.isArray(context.timeline)
      ? (context.timeline as TimelinePoint[])
      : []
  const dns =
    typeof raw.dns === 'string'
      ? raw.dns
      : typeof context.dns === 'string'
        ? String(context.dns)
        : null
  const tls =
    typeof raw.tls_sni === 'string'
      ? raw.tls_sni
      : typeof context.tls_sni === 'string'
        ? String(context.tls_sni)
        : null

  return (
    <div className="modality-panel">
      {(dns || tls) && (
        <dl className="kv compact-kv">
          {dns ? (
            <>
              <dt>DNS</dt>
              <dd className="mono">{dns}</dd>
            </>
          ) : null}
          {tls ? (
            <>
              <dt>TLS SNI</dt>
              <dd className="mono">{tls}</dd>
            </>
          ) : null}
        </dl>
      )}

      {timeline.length > 0 ? (
        <section>
          <h5>Connection timeline</h5>
          <ul className="contributor-list">
            {timeline.map((pt, idx) => (
              <li key={`${pt.t ?? idx}`}>
                <span className="mono">{pt.t ?? `t-${idx}`}</span>
                <span>
                  {pt.event ?? 'flow'}
                  {pt.peer ? ` · ${pt.peer}` : ''}
                </span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {peers.length > 0 ? (
        <section>
          <h5>Peer / service contributors</h5>
          <ul className="contributor-list">
            {peers.map((p, idx) => (
              <li key={`${p.peer ?? 'peer'}-${idx}`}>
                <span>
                  <span className="mono">{p.peer ?? `peer-${idx + 1}`}</span>
                  <span className="muted">
                    {' '}
                    · {p.role ?? 'peer'}
                    {p.service ? ` · ${p.service}` : ''}
                  </span>
                </span>
                <span className="mono">
                  {typeof p.contribution === 'number' ? p.contribution.toFixed(2) : '—'}
                </span>
              </li>
            ))}
          </ul>
        </section>
      ) : (
        <EvidenceEmpty item={item} message="No peer/service contributor details in evidence payload." />
      )}
    </div>
  )
}

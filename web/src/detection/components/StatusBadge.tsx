type Props = {
  value: string
  kind?: 'severity' | 'status' | 'health' | 'generic'
}

export function StatusBadge({ value, kind = 'generic' }: Props) {
  const slug = value.toLowerCase().replace(/[^a-z0-9]+/g, '-')
  return <span className={`badge badge-kind-${kind} badge-${slug}`}>{value}</span>
}

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api } from '../api/client'
import type { DeploymentEvent, NotificationSetting } from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'

export function Admin() {
  const [rows, setRows] = useState<NotificationSetting[]>([])
  const [deployments, setDeployments] = useState<DeploymentEvent[]>([])
  const [outbox, setOutbox] = useState<
    Array<{ id: number; tenant_id: string; recipient: string; subject: string; status: string }>
  >([])
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [channel, setChannel] = useState('email')
  const [enabled, setEnabled] = useState(false)
  const [configText, setConfigText] = useState('{}')
  const [depId, setDepId] = useState('')
  const [depService, setDepService] = useState('')
  const [depVersion, setDepVersion] = useState('')
  const [depEnv, setDepEnv] = useState('prod')

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [data, deps, box] = await Promise.all([
        api.listNotificationSettings(),
        api.listDeployments().catch(() => [] as DeploymentEvent[]),
        api.listNotificationOutbox().catch(() => []),
      ])
      setRows(data)
      setDeployments(deps)
      setOutbox(box)
      setSelectedId((current) => current ?? data[0]?.setting_id ?? null)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const selected = rows.find((row) => row.setting_id === selectedId) ?? null

  useEffect(() => {
    if (!selected) return
    setChannel(selected.channel)
    setEnabled(selected.enabled)
    setConfigText(JSON.stringify(selected.config, null, 2))
  }, [selected])

  async function save(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setMessage(null)
    let config: Record<string, unknown>
    try {
      config = JSON.parse(configText) as Record<string, unknown>
    } catch {
      setError('Configuration must be a valid JSON object.')
      return
    }
    if (!config || Array.isArray(config) || typeof config !== 'object') {
      setError('Configuration must be a JSON object.')
      return
    }
    setSaving(true)
    try {
      const saved = await api.saveNotificationSetting({
        setting_id: selected?.setting_id,
        channel,
        enabled,
        config,
      })
      setRows((current) => {
        const remaining = current.filter((row) => row.setting_id !== saved.setting_id)
        return [...remaining, saved].sort((a, b) => a.channel.localeCompare(b.channel))
      })
      setSelectedId(saved.setting_id)
      setMessage('Notification setting saved and audited.')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  async function onTest() {
    setSaving(true)
    setError(null)
    setMessage(null)
    try {
      const config = JSON.parse(configText) as { to?: unknown }
      const result = await api.testNotification({
        channels: [channel || 'email'],
        email_to: typeof config.to === 'string' ? config.to : 'ops@example.com',
      })
      setMessage(`Test sent: ${JSON.stringify(result)}`)
      setOutbox(await api.listNotificationOutbox().catch(() => []))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  async function onFlush() {
    setSaving(true)
    setError(null)
    try {
      const result = await api.flushNotificationOutbox()
      setMessage(`Outbox flush: ${JSON.stringify(result)}`)
      setOutbox(await api.listNotificationOutbox().catch(() => []))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  async function onDeployment(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setMessage(null)
    try {
      await api.upsertDeployment({
        deployment_id: depId.trim(),
        service_id: depService.trim(),
        version: depVersion.trim() || undefined,
        environment: depEnv.trim() || 'prod',
      })
      setMessage(`Deployment ${depId} recorded.`)
      setDepId('')
      setDeployments(await api.listDeployments())
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <div className="loading">Loading administration…</div>

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>Detection operations</h1>
          <p>Notification settings, test delivery, outbox flush, and deployment events.</p>
        </div>
        <button type="button" className="btn" onClick={() => void load()}>
          Retry
        </button>
      </header>

      {error ? <div className="error">{error}</div> : null}
      {message ? <div className="panel">{message}</div> : null}

      <div className="panel" style={{ marginBottom: '1rem' }}>
        <h2>Runtime</h2>
        <dl className="kv">
          <dt>Mode</dt>
          <dd>{api.useMock ? 'explicit mock adapter' : 'live services'}</dd>
          <dt>Incident API</dt>
          <dd className="mono">{api.apiBase || '(same origin /api)'}</dd>
        </dl>
      </div>

      <div className="list-detail">
        <div className="panel" style={{ padding: 0 }}>
          {rows.length === 0 ? (
            <div className="empty">No notification settings exist for this tenant.</div>
          ) : (
            rows.map((row) => (
              <button
                key={row.setting_id}
                type="button"
                className={`list-item${selectedId === row.setting_id ? ' active' : ''}`}
                onClick={() => setSelectedId(row.setting_id)}
              >
                <strong>{row.channel}</strong>
                <div className="muted">
                  <StatusBadge value={row.enabled ? 'ready' : 'disabled'} kind="health" />{' '}
                  <span className="mono">{row.setting_id}</span>
                </div>
              </button>
            ))
          )}
          <button
            type="button"
            className="btn"
            style={{ margin: '1rem' }}
            onClick={() => {
              setSelectedId(null)
              setChannel('email')
              setEnabled(false)
              setConfigText('{}')
            }}
          >
            New setting
          </button>
        </div>

        <form className="panel" onSubmit={save}>
          <h2>{selected ? `Edit ${selected.channel}` : 'New notification setting'}</h2>
          <label>
            Channel
            <input value={channel} onChange={(e) => setChannel(e.target.value)} required />
          </label>
          <label style={{ display: 'block', marginTop: '1rem' }}>
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />{' '}
            Enabled
          </label>
          <label style={{ display: 'block', marginTop: '1rem' }}>
            Configuration JSON
            <textarea
              className="mono"
              rows={10}
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
            />
          </label>
          <div className="toolbar" style={{ marginTop: '0.75rem', flexWrap: 'wrap' }}>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? 'Saving…' : 'Save setting'}
            </button>
            <button type="button" className="btn" disabled={saving} onClick={() => void onTest()}>
              Send test
            </button>
            <button type="button" className="btn" disabled={saving} onClick={() => void onFlush()}>
              Flush outbox
            </button>
          </div>
          <p className="muted">
            Secret-valued fields are masked by the API after saving. Admin role is required.
          </p>
        </form>
      </div>

      <section className="panel" style={{ marginTop: '1rem' }}>
        <h2>Email outbox</h2>
        {outbox.length === 0 ? (
          <div className="empty">Outbox empty.</div>
        ) : (
          <table className="table data">
            <thead>
              <tr>
                <th>ID</th>
                <th>Recipient</th>
                <th>Subject</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {outbox.map((row) => (
                <tr key={row.id}>
                  <td className="mono">{row.id}</td>
                  <td>{row.recipient}</td>
                  <td>{row.subject}</td>
                  <td>
                    <StatusBadge value={row.status} kind="status" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel" style={{ marginTop: '1rem' }}>
        <h2>Record deployment</h2>
        <form className="toolbar" onSubmit={onDeployment} style={{ flexWrap: 'wrap', gap: '0.75rem' }}>
          <input
            required
            aria-label="Deployment ID"
            placeholder="deployment-id"
            value={depId}
            onChange={(e) => setDepId(e.target.value)}
          />
          <input
            required
            aria-label="Service ID"
            placeholder="service-id"
            value={depService}
            onChange={(e) => setDepService(e.target.value)}
          />
          <input
            aria-label="Version"
            placeholder="version"
            value={depVersion}
            onChange={(e) => setDepVersion(e.target.value)}
          />
          <input
            aria-label="Environment"
            placeholder="environment"
            value={depEnv}
            onChange={(e) => setDepEnv(e.target.value)}
          />
          <button type="submit" className="btn btn-primary" disabled={saving}>
            Upsert
          </button>
        </form>
        {deployments.length ? (
          <table className="table data" style={{ marginTop: '1rem' }}>
            <thead>
              <tr>
                <th>Deployment</th>
                <th>Service</th>
                <th>Version</th>
                <th>Environment</th>
              </tr>
            </thead>
            <tbody>
              {deployments.slice(0, 20).map((d) => (
                <tr key={d.deployment_id}>
                  <td className="mono">{d.deployment_id}</td>
                  <td className="mono">{d.service_id}</td>
                  <td className="mono">{d.version ?? '—'}</td>
                  <td>{d.environment ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </div>
  )
}

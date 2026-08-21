import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { api } from '../api/client'
import type {
  ProfileCoverage,
  SecurityPack,
  SecurityPreset,
  SecurityProfile,
} from '../api/contracts'
import { StatusBadge } from '../components/StatusBadge'
import { downloadBlob } from '../utils/download'
import { useUser } from '../../user_context'

const SURFACES = ['network', 'host', 'identity', 'code', 'webapp', 'cloud'] as const

export function SecurityProfiles() {
  const user = useUser()
  const [packs, setPacks] = useState<SecurityPack[]>([])
  const [presets, setPresets] = useState<SecurityPreset[]>([])
  const [profiles, setProfiles] = useState<SecurityProfile[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [coverage, setCoverage] = useState<ProfileCoverage | null>(null)
  const [name, setName] = useState('New security profile')
  const [selectedPacks, setSelectedPacks] = useState<string[]>(['cis-v8-ig1'])
  const [surfaces, setSurfaces] = useState<string[]>(['network', 'host', 'identity', 'code'])
  const [certTarget, setCertTarget] = useState('soc2')
  const [certMsg, setCertMsg] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [exceptions, setExceptions] = useState<
    Array<{ exception_id: string; check_id: string; rationale: string; status: string }>
  >([])

  async function refresh() {
    setLoading(true)
    setError(null)
    try {
      const [packBody, profileRows] = await Promise.all([
        api.listSecurityPacks(),
        api.listSecurityProfiles(),
      ])
      setPacks(packBody.items)
      setPresets(packBody.presets)
      setProfiles(profileRows)
      // Functional update: reads the live selection (not a stale closure) and
      // re-selects when the current selection was deleted or nothing is selected.
      setSelectedId((prev) =>
        prev && profileRows.some((p) => p.profile_id === prev)
          ? prev
          : (profileRows[0]?.profile_id ?? null),
      )
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void refresh()
     
  }, [])

  useEffect(() => {
    if (!selectedId) {
      setCoverage(null)
      setExceptions([])
      return
    }
    void Promise.all([
      api.getSecurityProfileCoverage(selectedId),
      api.listProfileExceptions(selectedId),
    ])
      .then(([cov, excs]) => {
        setCoverage(cov)
        setExceptions(excs)
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
  }, [selectedId])

  const selected = useMemo(
    () => profiles.find((p) => p.profile_id === selectedId) ?? null,
    [profiles, selectedId],
  )

  function togglePack(packId: string) {
    setSelectedPacks((prev) =>
      prev.includes(packId) ? prev.filter((p) => p !== packId) : [...prev, packId],
    )
  }

  function toggleSurface(surface: string) {
    setSurfaces((prev) =>
      prev.includes(surface) ? prev.filter((s) => s !== surface) : [...prev, surface],
    )
  }

  function applyPreset(preset: SecurityPreset) {
    setName(preset.name)
    setSelectedPacks([...preset.packs])
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    if (!selectedPacks.length) {
      setError('Select at least one pack')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const created = await api.createSecurityProfile({
        name,
        selected_packs: selectedPacks,
        enabled_surfaces: surfaces,
      })
      await refresh()
      setSelectedId(created.profile_id)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function onEvaluate() {
    if (!selectedId) return
    setBusy(true)
    try {
      const result = await api.evaluateSecurityProfile(selectedId)
      setCoverage(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function onAttest(checkId: string) {
    if (!selectedId) return
    setBusy(true)
    try {
      await api.attestSecurityCheck(selectedId, checkId, 'Operator attestation')
      const result = await api.getSecurityProfileCoverage(selectedId)
      setCoverage(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function onCertPackage() {
    if (!selectedId) return
    setBusy(true)
    setCertMsg(null)
    try {
      const pkg = await api.generateCertificationPackage(selectedId, certTarget, 'zip')
      if (pkg instanceof Blob) {
        downloadBlob(pkg, `cert-${selectedId}-${certTarget}.zip`)
        setCertMsg(`Downloaded certification package ZIP for ${certTarget}`)
      } else {
        setCertMsg(`${pkg.package_id}: ${pkg.disclaimer}`)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function onDeleteProfile() {
    if (!selectedId) return
    if (!window.confirm(`Delete profile ${selected?.name ?? selectedId}?`)) return
    setBusy(true)
    setError(null)
    try {
      await api.deleteSecurityProfile(selectedId)
      setSelectedId(null)
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function onRenameProfile() {
    if (!selectedId || !selected) return
    const next = window.prompt('Rename profile', selected.name)
    if (!next || !next.trim()) return
    setBusy(true)
    setError(null)
    try {
      await api.patchSecurityProfile(selectedId, { name: next.trim() })
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function onException(checkId: string) {
    if (!selectedId) return
    const rationale = window.prompt('Exception rationale', 'Accepted risk for this check')
    if (!rationale) return
    setBusy(true)
    try {
      await api.createProfileException(selectedId, {
        check_id: checkId,
        rationale,
        owner: user.email || user.user_id || 'session',
      })
      const result = await api.getSecurityProfileCoverage(selectedId)
      setCoverage(result)
      setExceptions(await api.listProfileExceptions(selectedId))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const passPct =
    coverage && coverage.checks.length
      ? Math.round(
          (100 * ((coverage.summary.pass ?? 0) + (coverage.summary.attested ?? 0))) /
            coverage.checks.length,
        )
      : 0

  return (
    <div>
      <header className="page-header">
        <div>
          <h1>Security Profiles</h1>
          <p className="muted">
            Multi-select framework and industry packs with union-strictest merge, coverage
            checklist, attestations, and certification evidence packages.
          </p>
        </div>
      </header>

      {error ? <div className="error">{error}</div> : null}
      {loading ? <div className="loading">Loading profiles…</div> : null}

      <section className="panel" style={{ marginBottom: '1.25rem' }}>
        <h2>Create profile</h2>
        <form className="toolbar" onSubmit={onCreate} style={{ flexWrap: 'wrap', gap: '0.75rem' }}>
          <input
            aria-label="Profile name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            style={{ minWidth: '14rem' }}
          />
          <button type="submit" className="btn btn-primary" disabled={busy}>
            Create profile
          </button>
        </form>
        {presets.length ? (
          <div className="toolbar" style={{ marginTop: '0.75rem', flexWrap: 'wrap' }}>
            <span className="muted">Presets:</span>
            {presets.map((p) => (
              <button key={p.id} type="button" className="btn" onClick={() => applyPreset(p)}>
                {p.name}
              </button>
            ))}
          </div>
        ) : null}
        <div style={{ marginTop: '1rem' }}>
          <div className="muted" style={{ marginBottom: '0.35rem' }}>
            Packs
          </div>
          <div className="toolbar" style={{ flexWrap: 'wrap' }}>
            {packs.map((pack) => {
              const on = selectedPacks.includes(pack.pack_id)
              return (
                <button
                  key={pack.pack_id}
                  type="button"
                  className={on ? 'btn btn-primary' : 'btn'}
                  aria-pressed={on}
                  onClick={() => togglePack(pack.pack_id)}
                >
                  {pack.title}
                </button>
              )
            })}
          </div>
        </div>
        <div style={{ marginTop: '1rem' }}>
          <div className="muted" style={{ marginBottom: '0.35rem' }}>
            Surfaces
          </div>
          <div className="toolbar" style={{ flexWrap: 'wrap' }}>
            {SURFACES.map((surface) => {
              const on = surfaces.includes(surface)
              return (
                <button
                  key={surface}
                  type="button"
                  className={on ? 'btn btn-primary' : 'btn'}
                  aria-pressed={on}
                  onClick={() => toggleSurface(surface)}
                >
                  {surface}
                </button>
              )
            })}
          </div>
        </div>
      </section>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(14rem, 22rem) 1fr', gap: '1rem' }}>
        <section className="panel">
          <h2>Profiles</h2>
          {profiles.length === 0 ? (
            <div className="empty">No profiles yet.</div>
          ) : (
            <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
              {profiles.map((p) => (
                <li key={p.profile_id}>
                  <button
                    type="button"
                    className={selectedId === p.profile_id ? 'btn btn-primary' : 'btn'}
                    style={{ width: '100%', marginBottom: '0.35rem', textAlign: 'left' }}
                    onClick={() => setSelectedId(p.profile_id)}
                  >
                    {p.name}
                    <div className="muted mono" style={{ fontSize: '0.8rem' }}>
                      {p.selected_packs.join(', ')}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="panel">
          <div className="toolbar" style={{ justifyContent: 'space-between' }}>
            <h2 style={{ margin: 0 }}>{selected?.name ?? 'Coverage'}</h2>
            <div className="toolbar" style={{ flexWrap: 'wrap' }}>
              <button type="button" className="btn" disabled={!selectedId || busy} onClick={() => void onRenameProfile()}>
                Rename
              </button>
              <button type="button" className="btn" disabled={!selectedId || busy} onClick={() => void onDeleteProfile()}>
                Delete
              </button>
              <button type="button" className="btn" disabled={!selectedId || busy} onClick={() => void onEvaluate()}>
                Evaluate
              </button>
              <select
                aria-label="Certification target"
                value={certTarget}
                onChange={(e) => setCertTarget(e.target.value)}
              >
                <option value="soc2">SOC 2</option>
                <option value="pci_dss_4">PCI DSS 4</option>
                <option value="cmmc_l2">CMMC L2</option>
                <option value="fedramp_mod">FedRAMP Moderate</option>
              </select>
              <button
                type="button"
                className="btn"
                disabled={!selectedId || busy}
                onClick={() => void onCertPackage()}
              >
                Generate certification package
              </button>
            </div>
          </div>

          {certMsg ? <p className="muted">{certMsg}</p> : null}

          {coverage ? (
            <>
              <p className="muted">
                Checks passing (pass+attested): <strong>{passPct}%</strong> · pass{' '}
                {coverage.summary.pass ?? 0} · fail {coverage.summary.fail ?? 0} · unknown{' '}
                {coverage.summary.unknown ?? 0} · attested {coverage.summary.attested ?? 0}
              </p>
              <table className="table data">
                <thead>
                  <tr>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Automation</th>
                    <th>Surfaces</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {coverage.checks.map((c) => (
                    <tr key={c.check_id}>
                      <td>
                        <div>{c.title}</div>
                        <div className="mono muted" style={{ fontSize: '0.8rem' }}>
                          {c.check_id}
                        </div>
                        {c.reason ? (
                          <div className="muted" style={{ fontSize: '0.8rem' }}>
                            {c.reason}
                          </div>
                        ) : null}
                      </td>
                      <td>
                        <StatusBadge value={c.status} kind="status" />
                      </td>
                      <td className="mono">{c.automation}</td>
                      <td className="muted">{c.surfaces.join(', ')}</td>
                      <td>
                        <div className="toolbar">
                          {c.status === 'unknown' || c.status === 'fail' ? (
                            <button
                              type="button"
                              className="btn"
                              disabled={busy}
                              onClick={() => void onAttest(c.check_id)}
                            >
                              Attest
                            </button>
                          ) : null}
                          {c.status !== 'not_applicable' ? (
                            <button
                              type="button"
                              className="btn"
                              disabled={busy}
                              onClick={() => void onException(c.check_id)}
                            >
                              Exception
                            </button>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : (
            <div className="empty">Select a profile to view coverage.</div>
          )}

          {exceptions.length ? (
            <>
              <h3>Open exceptions</h3>
              <ul>
                {exceptions.map((ex) => (
                  <li key={ex.exception_id}>
                    <span className="mono">{ex.check_id}</span> — {ex.rationale}{' '}
                    <StatusBadge value={ex.status} kind="status" />
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </section>
      </div>
    </div>
  )
}

import { useState } from 'react'
import { useSourceInfo, useRunIndex } from '../../data/hooks.ts'
import { useUi } from '../../state/ui.ts'
import type { AudienceMode } from '../../state/ui.ts'
import { PageHeader, Panel } from '../../ui/Panel.tsx'
import { Button } from '../../ui/Button.tsx'
import { Field, KV, Segmented } from '../../ui/controls.tsx'
import { ThemeSwitcher } from '../../shell/ThemeToggle.tsx'
import { getAdminToken, setAdminToken } from '../../lib/admin.ts'

export function Settings() {
  const mode = useUi((s) => s.mode)
  const setMode = useUi((s) => s.setMode)
  const info = useSourceInfo()
  const index = useRunIndex()
  const [token, setToken] = useState('')
  const [hasToken, setHasToken] = useState(() => !!getAdminToken())
  const api = info.status === 'ready' && info.data.kind === 'api'
  return (
    <>
      <PageHeader eyebrow="Settings" title="Settings" lede="Preferences are stored in this browser." />
      <div className="grid max-w-4xl gap-6">
        <Panel title="Appearance">
          <ThemeSwitcher />
          <p className="mt-3 text-[0.8rem] text-ink-3">System follows your operating system’s light or dark setting.</p>
        </Panel>
        <Panel title="Audience mode" description="Changes emphasis on vendor profiles, never the numbers.">
          <Segmented<AudienceMode>
            label="Audience mode"
            value={mode}
            onChange={setMode}
            options={[
              { value: 'procurement', label: 'Procurement' },
              { value: 'researcher', label: 'Researcher' },
              { value: 'ciso', label: 'CISO' },
            ]}
          />
          <ul className="mt-4 space-y-1.5 text-[0.84rem] text-ink-2">
            <li>
              <span className="font-semibold text-ink">Procurement</span> · scorecard first, with the assessment-scope note.
            </li>
            <li>
              <span className="font-semibold text-ink">Researcher</span> · adds queries, attributions, exclusions and snapshots to each profile.
            </li>
            <li>
              <span className="font-semibold text-ink">CISO</span> · opens each profile with a brief: measured evidence, unverified areas, trend and questions to ask.
            </li>
          </ul>
        </Panel>
        <Panel title="Data source">
          <KV
            rows={[
              ['Source', info.status === 'ready' ? (api ? 'TOUCHSTONE API (/api)' : 'Static bundle (published files)') : 'Detecting…'],
              ['Dataset mode', index.status === 'ready' ? index.data.mode : '—'],
              ['Latest run', index.status === 'ready' ? <span className="font-mono text-[0.8rem]">{index.data.latestRunId}</span> : '—'],
              ['Built from', index.status === 'ready' ? index.data.builtFrom : '—'],
              ['Administration', info.status === 'ready' ? (info.data.adminEnabled ? 'Enabled on this server' : 'Not available') : '—'],
            ]}
          />
          <p className="mt-3 text-[0.8rem] text-ink-3">Append ?source=static to any URL to force the static bundle.</p>
        </Panel>
        {api && info.status === 'ready' && info.data.adminEnabled && (
          <Panel title="Admin token" description="Needed to start a refresh. Kept in this tab’s session storage only, sent only to this server’s /api, and cleared when the tab closes.">
            {hasToken ? (
              <div className="flex flex-wrap items-center gap-3">
                <p className="text-[0.86rem] text-ink-2">A token is set for this tab.</p>
                <Button
                  size="sm"
                  onClick={() => {
                    setAdminToken(null)
                    setHasToken(false)
                  }}
                >
                  Forget token
                </Button>
              </div>
            ) : (
              <form
                className="flex flex-wrap items-end gap-3"
                onSubmit={(e) => {
                  e.preventDefault()
                  if (!token.trim()) return
                  setAdminToken(token.trim())
                  setToken('')
                  setHasToken(true)
                }}
              >
                <div className="min-w-0 flex-1 basis-64">
                  <Field label="Token" htmlFor="admin-token">
                    <input id="admin-token" type="password" autoComplete="off" className="ts-input" value={token} onChange={(e) => setToken(e.target.value)} />
                  </Field>
                </div>
                <Button type="submit" variant="primary">
                  Use for this tab
                </Button>
              </form>
            )}
          </Panel>
        )}
      </div>
    </>
  )
}

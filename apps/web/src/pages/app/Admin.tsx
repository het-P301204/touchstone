/**
 * Administration. Shown in navigation only when the API reports an enabled
 * admin surface. Disputes are reviewed through the API with the admin token.
 */
import { Link } from 'react-router'
import { useActiveSummary, useDisputes, useSourceInfo } from '../../data/hooks.ts'
import { PageHeader, Panel } from '../../ui/Panel.tsx'
import { EmptyState, Load } from '../../ui/States.tsx'
import { RefreshPipeline } from '../../features/RefreshPipeline.tsx'
import { DISPUTE_STATUS } from '../../lib/status.ts'
import { getAdminToken } from '../../lib/admin.ts'

export function Admin() {
  const info = useSourceInfo()
  const active = useActiveSummary()
  const disputes = useDisputes()
  if (info.status !== 'ready') return null
  if (info.data.kind !== 'api' || !info.data.adminEnabled) {
    return (
      <>
        <PageHeader eyebrow="Administration" title="Administration" />
        <EmptyState title="Administration is not available here">
          The static demo has no administrative surface. With the API, set TOUCHSTONE_ADMIN_TOKEN on the server to enable it.
        </EmptyState>
      </>
    )
  }
  return (
    <>
      <PageHeader eyebrow="Administration" title="Administration" lede="Refresh the dataset and review disputes. Every action is recorded by the API." />
      {!getAdminToken() && (
        <p className="mb-5 text-[0.86rem] text-marigold-ink">
          No admin token for this tab. <Link to="/app/settings" className="ts-link">Add it in Settings</Link>.
        </p>
      )}
      <div className="grid gap-6">
        <Load value={active} what="the run">
          {({ summary }) => (
            <Panel title="Refresh" eyebrow="Pipeline">
              <RefreshPipeline manifest={summary.manifest} />
            </Panel>
          )}
        </Load>
        <Load value={disputes} what="disputes">
          {(list) => (
            <Panel title="Disputes awaiting review" eyebrow={`${list.filter((d) => d.status === 'OPEN' || d.status === 'UNDER_REVIEW').length} active`}>
              <ul className="space-y-2 text-[0.84rem]">
                {list
                  .filter((d) => d.status === 'OPEN' || d.status === 'UNDER_REVIEW')
                  .map((d) => (
                    <li key={d.id} className="flex flex-wrap items-center justify-between gap-2 rounded-[12px] border border-line bg-surface-raised px-4 py-2.5">
                      <span className="font-mono text-[0.78rem]">
                        {d.id} · {d.vendorId} · {d.target.kind} {d.target.id}
                      </span>
                      <span className="text-ink-2">{DISPUTE_STATUS[d.status].label}</span>
                    </li>
                  ))}
              </ul>
              <p className="mt-3 text-[0.8rem] text-ink-3">Transitions are made with POST /api/disputes/:id/transition and the admin token (see docs/api.md); the log keeps every step.</p>
            </Panel>
          )}
        </Load>
      </div>
    </>
  )
}

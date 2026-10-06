/**
 * Compare vendors on the measured dimensions. Table on wide screens, one
 * stacked card per vendor on small screens. Wording compares observable
 * evidence, never security.
 */
import { useMemo } from 'react'
import { Link, useSearchParams } from 'react-router'
import { X } from 'lucide-react'
import type { DimensionId, RunSummary, VendorSummary } from '@touchstone/core/model'
import { useActiveSummary } from '../../data/hooks.ts'
import { useUi } from '../../state/ui.ts'
import { PageHeader, Panel } from '../../ui/Panel.tsx'
import { DemoLabel } from '../../ui/controls.tsx'
import { EmptyState, Load } from '../../ui/States.tsx'
import { StatusBadge } from '../../ui/StatusBadge.tsx'
import { DIMENSION_LABEL, defOf, formatMetric, metricOf } from '../../lib/vocab.ts'
import { pct } from '../../lib/format.ts'
import { HowCalculated, dimensionValue } from '../../features/figures.tsx'
import { ProcurementNote } from './VendorProfile.tsx'

const MAX = 4
const ROWS: { id: string; label?: string; context?: boolean }[] = [
  { id: 'vdp.criteria_met' },
  { id: 'vdp.pledge_elements_met' },
  { id: 'cve.complete_records' },
  { id: 'cve.cwe_coverage' },
  { id: 'cve.cpe_coverage' },
  { id: 'cve.cpe_namespace_consistency' },
  { id: 'cve.timely_issuance' },
  { id: 'cve.high_impact_with_cve' },
  { id: 'cve.publication_latency' },
  { id: 'cve.enriched_only', context: true },
]
const DIMS: DimensionId[] = ['VDP', 'CVE_QUALITY', 'CVE_TIMELINESS']

/** Plain-language comparison, only over dimensions where every selected vendor has a value. */
export function compareSentence(vendors: VendorSummary[]): string {
  if (vendors.length < 2) return ''
  const measured = DIMS.filter((d) => vendors.every((v) => dimensionValue(v, d) !== null))
  if (measured.length === 0) return 'No measured dimension has a value for every selected vendor, so no comparison is stated.'
  const leader = vendors.find((a) => vendors.every((b) => a === b || (measured.every((d) => dimensionValue(a, d)! >= dimensionValue(b, d)!) && measured.some((d) => dimensionValue(a, d)! > dimensionValue(b, d)!))))
  const dims = measured.map((d) => DIMENSION_LABEL[d]).join(', ')
  const allEqual = measured.every((d) => vendors.every((v) => dimensionValue(v, d) === dimensionValue(vendors[0]!, d)))
  if (allEqual) return `The selected vendors show the same publicly observable evidence on the measured dimensions where each has a value (${dims}).`
  if (leader) return `${leader.vendor.canonicalName} demonstrates stronger publicly observable evidence on the measured dimensions (${dims}).`
  return `No selected vendor shows stronger publicly observable evidence on every measured dimension (${dims}); read each row on its own.`
}

function Picker({ summary, selected, onChange }: { summary: RunSummary; selected: string[]; onChange: (ids: string[]) => void }) {
  const available = summary.vendors.filter((v) => !selected.includes(v.vendor.id))
  return (
    <div className="flex flex-wrap items-center gap-2">
      {selected.map((id) => {
        const v = summary.vendors.find((x) => x.vendor.id === id)
        return (
          <span key={id} className="inline-flex h-9 max-w-full items-center gap-1 rounded-control border border-line-strong bg-surface-raised pl-3 pr-1 text-sm font-semibold text-ink">
            <span className="ts-ident truncate">{v?.vendor.canonicalName ?? id}</span>
            <button type="button" aria-label={`Remove ${v?.vendor.canonicalName ?? id}`} onClick={() => onChange(selected.filter((x) => x !== id))} className="inline-flex size-7 items-center justify-center rounded-[10px] text-ink-3 hover:bg-paper-2 hover:text-ink">
              <X aria-hidden="true" className="size-3.5" />
            </button>
          </span>
        )
      })}
      {selected.length < MAX && (
        <select className="ts-select h-9" aria-label="Add a vendor to compare" value="" onChange={(e) => e.target.value && onChange([...selected, e.target.value])}>
          <option value="">Add a vendor…</option>
          {available.map((v) => (
            <option key={v.vendor.id} value={v.vendor.id}>
              {v.vendor.canonicalName}
            </option>
          ))}
        </select>
      )}
      <span className="text-[0.78rem] text-ink-3">Up to {MAX} vendors.</span>
    </div>
  )
}

function cellFor(summary: RunSummary, v: VendorSummary, metricId: string, runId: string) {
  const found = metricOf(v, metricId)
  const def = defOf(summary, metricId)
  if (!found) return <span className="text-ink-3">—</span>
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={found.metric.value === null ? 'text-[0.8rem] text-ink-3' : 'ts-num text-ink'}>{found.metric.value === null ? 'not measured' : formatMetric(found.metric.value, def)}</span>
      <HowCalculated vendorId={v.vendor.id} runId={runId} goalId={found.goal.goalId} metricId={metricId} iconOnly />
    </span>
  )
}

export function Compare() {
  const value = useActiveSummary()
  const mode = useUi((s) => s.mode)
  const [params, setParams] = useSearchParams()
  const selected = useMemo(() => (params.get('v') ?? '').split(',').filter(Boolean).slice(0, MAX), [params])
  const setSelected = (next: string[]) => setParams({ v: next.join(',') }, { replace: true })

  return (
    <Load value={value} what="the comparison">
      {({ summary, index, runId }) => {
        // With nothing chosen yet, start with the first two vendors so the page is never empty.
        const ids = params.has('v') ? selected : summary.vendors.slice(0, 2).map((v) => v.vendor.id)
        const chosen = ids.map((id) => summary.vendors.find((v) => v.vendor.id === id)).filter((v): v is VendorSummary => !!v)
        return (
          <>
            <PageHeader
              eyebrow="Compare"
              title="Compare vendors"
              lede="Side by side on the measured dimensions. A dimension is compared only where each vendor has a value."
              actions={index.mode === 'DEMO' ? <DemoLabel /> : undefined}
            />
            <div className="space-y-5">
              <Picker summary={summary} selected={ids} onChange={setSelected} />
              {mode === 'procurement' && <ProcurementNote />}
              {chosen.length < 2 ? (
                <EmptyState title="Choose at least two vendors">Add vendors with the selector above.</EmptyState>
              ) : (
                <>
                  <p className="max-w-3xl text-lede text-ink" aria-live="polite">
                    {compareSentence(chosen)}
                  </p>

                  {/* Wide screens: one column per vendor. */}
                  <div className="ts-panel hidden overflow-hidden lg:block">
                    <div className="ts-scroll-thin overflow-x-auto">
                      <table className="ts-tbl">
                        <caption className="sr-only">Comparison of {chosen.map((v) => v.vendor.canonicalName).join(', ')}</caption>
                        <thead>
                          <tr>
                            <th scope="col" className="w-[30%]">
                              Measurement
                            </th>
                            {chosen.map((v) => (
                              <th key={v.vendor.id} scope="col">
                                <Link to={`/app/vendors/${v.vendor.id}`} className="ts-ident normal-case tracking-normal text-ink hover:underline">
                                  {v.vendor.canonicalName}
                                </Link>
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <th scope="row" className="text-left text-[0.84rem] font-semibold text-ink">
                              Evidence coverage
                            </th>
                            {chosen.map((v) => (
                              <td key={v.vendor.id} className="ts-num">
                                {pct(v.coverage.percent, 0)} <span className="text-[0.75rem] text-ink-3">({v.coverage.observedSlots}/{v.coverage.totalSlots})</span>
                              </td>
                            ))}
                          </tr>
                          {ROWS.map((r) => (
                            <tr key={r.id}>
                              <th scope="row" className="text-left text-[0.84rem] font-normal text-ink-2">
                                {defOf(summary, r.id)?.name ?? r.id}
                                {r.context && <span className="block text-[0.72rem] text-iris-ink">context only, not credited</span>}
                              </th>
                              {chosen.map((v) => (
                                <td key={v.vendor.id}>{cellFor(summary, v, r.id, runId)}</td>
                              ))}
                            </tr>
                          ))}
                          {summary.goals.map((g) => (
                            <tr key={g.id}>
                              <th scope="row" className="text-left text-[0.84rem] font-normal text-ink-2">
                                {g.id} {g.name}
                              </th>
                              {chosen.map((v) => {
                                const st = v.goals.find((x) => x.goalId === g.id)?.status
                                return <td key={v.vendor.id}>{st ? <StatusBadge status={st} size="sm" short /> : '—'}</td>
                              })}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Small screens: stacked, one card per vendor. */}
                  <div className="grid gap-4 sm:grid-cols-2 lg:hidden">
                    {chosen.map((v) => (
                      <Panel key={v.vendor.id} title={<Link to={`/app/vendors/${v.vendor.id}`} className="ts-ident hover:underline">{v.vendor.canonicalName}</Link>}>
                        <dl className="space-y-2.5 text-[0.84rem]">
                          <div className="flex items-baseline justify-between gap-3">
                            <dt className="text-ink-2">Evidence coverage</dt>
                            <dd className="ts-num text-ink">{pct(v.coverage.percent, 0)}</dd>
                          </div>
                          {ROWS.map((r) => (
                            <div key={r.id} className="flex items-baseline justify-between gap-3 border-t border-line pt-2.5">
                              <dt className="min-w-0 text-ink-2">{defOf(summary, r.id)?.name ?? r.id}</dt>
                              <dd className="shrink-0">{cellFor(summary, v, r.id, runId)}</dd>
                            </div>
                          ))}
                        </dl>
                      </Panel>
                    ))}
                  </div>
                </>
              )}
            </div>
          </>
        )
      }}
    </Load>
  )
}

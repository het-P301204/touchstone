/**
 * Landing: a live excerpt of the published demo run. Sorted by evidence
 * coverage only because a table needs an order; there is no overall rank.
 */
import { Link } from 'react-router'
import { ArrowRight } from 'lucide-react'
import { useActiveSummary } from '../data/hooks.ts'
import { date } from '../lib/format.ts'
import { CATEGORY_LABEL } from '../lib/vocab.ts'
import { CoverageCell, DimensionCell } from '../features/figures.tsx'
import { DemoLabel } from '../ui/controls.tsx'
import { ButtonLink } from '../ui/Button.tsx'
import { Load, Skeleton } from '../ui/States.tsx'

export function DemoBoard() {
  const value = useActiveSummary()
  return (
    <Load value={value} what="the published run" loading={<Skeleton className="h-80 w-full" />}>
      {({ summary, index }) => {
        const rows = [...summary.vendors].sort((a, b) => b.coverage.percent - a.coverage.percent || a.vendor.canonicalName.localeCompare(b.vendor.canonicalName)).slice(0, 8)
        return (
          <div className="ts-panel overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-4 sm:px-6">
              <div className="flex min-w-0 flex-wrap items-center gap-2.5">
                {index.mode === 'DEMO' && <DemoLabel long />}
                <span className="ts-num text-[0.78rem] text-ink-3">
                  Run {summary.manifest.runId} · as of {date(summary.manifest.asOf)} · methodology {summary.manifest.methodologyVersion}
                </span>
              </div>
              <span className="text-[0.78rem] text-ink-3">Ordered by evidence coverage. There is no overall rank.</span>
            </div>
            <div className="ts-scroll-thin overflow-x-auto">
              <table className="ts-tbl min-w-[44rem]">
                <caption className="sr-only">Excerpt of the published run: evidence coverage and measured dimensions per vendor</caption>
                <thead>
                  <tr>
                    <th scope="col">Vendor</th>
                    <th scope="col">Evidence coverage</th>
                    <th scope="col">CVE quality</th>
                    <th scope="col">VDP</th>
                    <th scope="col">CVE timeliness</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((v) => (
                    <tr key={v.vendor.id}>
                      <td className="min-w-[12rem] max-w-[16rem]">
                        <Link to={`/app/vendors/${v.vendor.id}`} className="ts-ident font-semibold text-ink hover:underline">
                          {v.vendor.canonicalName}
                        </Link>
                        <span className="block text-[0.75rem] text-ink-3">{CATEGORY_LABEL[v.vendor.category]}</span>
                      </td>
                      <td>
                        <CoverageCell v={v} />
                      </td>
                      <td>
                        <DimensionCell v={v} dim="CVE_QUALITY" compact />
                      </td>
                      <td>
                        <DimensionCell v={v} dim="VDP" compact />
                      </td>
                      <td>
                        <DimensionCell v={v} dim="CVE_TIMELINESS" compact />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line px-5 py-4 sm:px-6">
              <p className="text-[0.8rem] text-ink-3">
                {summary.vendors.length} vendors in this run. {index.mode === 'DEMO' ? 'Fictional names, synthetic records. ' : ''}Every figure opens to its query and evidence.
              </p>
              <ButtonLink to="/app/vendors" size="sm" variant="secondary" trailing={<ArrowRight />}>
                Explore Demo
              </ButtonLink>
            </div>
          </div>
        )
      }}
    </Load>
  )
}

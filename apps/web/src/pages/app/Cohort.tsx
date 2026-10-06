/**
 * Cohort research view: medians, distributions and the category breakdown.
 * Only sourced dimensions: the registry category is sourced; size band and
 * region are shown only where a source states them.
 */
import type { DimensionId } from '@touchstone/core/model'
import { useActiveSummary } from '../../data/hooks.ts'
import { PageHeader, Panel } from '../../ui/Panel.tsx'
import { Histogram } from '../../ui/charts.tsx'
import { DemoLabel } from '../../ui/controls.tsx'
import { Load } from '../../ui/States.tsx'
import { bucket20 } from '../../lib/history.ts'
import { CATEGORY_LABEL, DIMENSION_LABEL, defOf, formatMetric } from '../../lib/vocab.ts'
import { dimensionValue } from '../../features/figures.tsx'
import type { VendorCategory } from '@touchstone/core/model'

const DIMS: DimensionId[] = ['VDP', 'CVE_QUALITY', 'CVE_TIMELINESS']
const MEDIAN_METRICS = ['vdp.criteria_met', 'cve.complete_records', 'cve.cwe_coverage', 'cve.cpe_coverage', 'cve.timely_issuance', 'cve.publication_latency', 'cve.enriched_only']

export function Cohort() {
  const value = useActiveSummary()
  return (
    <Load value={value} what="the cohort">
      {({ summary, index }) => {
        const allSig = summary.cohort.find((c) => c.peerGroup === 'ALL_SIGNATORIES')
        const groups = summary.cohort.filter((c) => c.peerGroup !== 'ALL_SIGNATORIES')
        const sized = summary.vendors.filter((v) => v.vendor.sizeBand).length
        const regioned = summary.vendors.filter((v) => v.vendor.region).length
        return (
          <>
            <PageHeader
              eyebrow="Cohort"
              title="The signatories as a group"
              lede="Medians and distributions over vendors with a value. A vendor without a value is counted as not measured, never as zero."
              actions={index.mode === 'DEMO' ? <DemoLabel /> : undefined}
            />
            {allSig && (
              <Panel title="Medians, all signatories" eyebrow={`${allSig.vendorCount} vendors`}>
                <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-card bg-line sm:grid-cols-3 xl:grid-cols-4">
                  {MEDIAN_METRICS.map((m) => (
                    <div key={m} className="min-w-0 bg-surface p-4">
                      <dt className="text-[0.78rem] text-ink-2">{defOf(summary, m)?.name ?? m}</dt>
                      <dd className="ts-num mt-1.5 text-[1.4rem] text-ink">{formatMetric(allSig.medians[m] ?? null, defOf(summary, m))}</dd>
                    </div>
                  ))}
                </dl>
              </Panel>
            )}
            <div className="mt-6 grid gap-6 lg:grid-cols-3">
              {DIMS.map((d) => (
                <Panel key={d} title={DIMENSION_LABEL[d]} eyebrow="Distribution">
                  <Histogram buckets={bucket20(summary.vendors.map((v) => dimensionValue(v, d)))} tone={d === 'VDP' ? 'iris' : d === 'CVE_QUALITY' ? 'sage' : 'marigold'} />
                </Panel>
              ))}
            </div>
            <Panel className="mt-6" title="By category" eyebrow="Registry category" description="Peer groups used for category benchmarks. A position is stated only when at least three peers have a value." flush>
              <div className="ts-scroll-thin overflow-x-auto">
                <table className="ts-tbl min-w-[48rem]">
                  <thead>
                    <tr>
                      <th scope="col">Category</th>
                      <th scope="col" className="text-right">
                        Vendors
                      </th>
                      {['vdp.criteria_met', 'cve.complete_records', 'cve.timely_issuance'].map((m) => (
                        <th key={m} scope="col" className="text-right">
                          Median {defOf(summary, m)?.name ?? m}
                        </th>
                      ))}
                      <th scope="col">VDP status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {groups.map((g) => (
                      <tr key={g.peerGroup}>
                        <td className="font-semibold text-ink">{CATEGORY_LABEL[g.peerGroup as VendorCategory] ?? g.peerGroup}</td>
                        <td className="ts-num text-right">{g.vendorCount}</td>
                        {['vdp.criteria_met', 'cve.complete_records', 'cve.timely_issuance'].map((m) => (
                          <td key={m} className="ts-num text-right text-ink-2">
                            {g.vendorCount < 3 ? <span className="text-[0.75rem] text-ink-3">too few</span> : formatMetric(g.medians[m] ?? null, defOf(summary, m))}
                          </td>
                        ))}
                        <td className="text-[0.78rem] text-ink-2">
                          {Object.entries(g.vdpStatusCounts)
                            .map(([k, n]) => `${k.replace(/_/g, ' ').toLowerCase()} ${n}`)
                            .join(' · ')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
            <p className="mt-4 max-w-prose text-[0.8rem] text-ink-3">
              Size band is sourced for {sized} of {summary.vendors.length} vendors and region for {regioned}; neither is used as a peer group until it is sourced for every
              vendor.
            </p>
          </>
        )
      }}
    </Load>
  )
}

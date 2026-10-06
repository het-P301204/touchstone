import { Link, useSearchParams } from 'react-router'
import { ArrowUpRight } from 'lucide-react'
import type { FreshnessState, RunSummary } from '@touchstone/core/model'
import { useActiveSummary, useHistory } from '../../data/hooks.ts'
import { PageHeader, Panel, Stat } from '../../ui/Panel.tsx'
import { CountUp, HBar, Histogram, StackBar } from '../../ui/charts.tsx'
import { DemoLabel } from '../../ui/controls.tsx'
import { Load } from '../../ui/States.tsx'
import { FreshnessBadge } from '../../ui/StatusBadge.tsx'
import { OBSERVABLE_GOAL_IDS, UNVERIFIABLE_GOAL_IDS } from '../../lib/core.ts'
import { FRESHNESS_STATE } from '../../lib/status.ts'
import { date, num, pct, shortHash } from '../../lib/format.ts'
import { bucket20, deltas } from '../../lib/history.ts'
import { criterionLabel, defOf, slotLabel, vendorName } from '../../lib/vocab.ts'
import { dimensionValue } from '../../features/figures.tsx'
import { RefreshPipeline } from '../../features/RefreshPipeline.tsx'

const FRESH: FreshnessState[] = ['CURRENT', 'AGING', 'STALE', 'UNKNOWN']

function FreshnessSummary({ summary }: { summary: RunSummary }) {
  const counts = FRESH.map((s) => ({ s, n: summary.freshness.filter((f) => f.state === s).length }))
  const current = counts[0]!.n
  return (
    <div className="min-w-0">
      <p className="ts-eyebrow">Data freshness</p>
      <p className="ts-num mt-1.5 text-[1.9rem] font-medium leading-none text-ink">
        {current}
        <span className="text-[1rem] text-ink-3"> / {summary.freshness.length}</span>
      </p>
      <p className="mt-1.5 text-[0.8rem] text-ink-3">sources current</p>
      <div className="mt-3">
        <StackBar showLegend={false} parts={counts.map(({ s, n }) => ({ key: s, label: FRESHNESS_STATE[s].label, value: n, tone: FRESHNESS_STATE[s].tone, dashed: s === 'UNKNOWN' }))} />
      </div>
    </div>
  )
}

export function Overview() {
  const value = useActiveSummary()
  const history = useHistory()
  const [params] = useSearchParams()
  return (
    <Load value={value} what="the overview">
      {({ summary, index }) => {
        const m = summary.manifest
        const all = summary.cohort.find((c) => c.peerGroup === 'ALL_SIGNATORIES') ?? summary.cohort[0]
        const vendors = summary.vendors
        const quality = bucket20(vendors.map((v) => dimensionValue(v, 'CVE_QUALITY')))
        const vdpCounts = all ? Object.entries(all.vdpStatusCounts) : []
        const vdpMax = Math.max(1, ...vdpCounts.map(([, n]) => n))
        const gaps = [...vendors].sort((a, b) => b.coverage.unobserved.length - a.coverage.unobserved.length).slice(0, 5)
        const improved =
          history.status === 'ready'
            ? deltas(history.data, ['cve.complete_records', 'vdp.criteria_met', 'cve.timely_issuance'])
                .filter((d) => d.delta > 0 && vendors.some((v) => v.vendor.id === d.vendorId))
                .sort((a, b) => b.delta - a.delta)
                .slice(0, 5)
            : []
        const recent = vendors
          .flatMap((v) => v.vdpChanges.map((c) => ({ v, c })))
          .sort((a, b) => b.c.toObservedAt.localeCompare(a.c.toObservedAt))
          .slice(0, 5)
        const checksPassed = m.qualityChecks.filter((q) => q.passed).length
        return (
          <>
            <PageHeader
              eyebrow={`Run ${m.runId} · as of ${date(m.asOf)}`}
              title="Overview"
              lede="What public evidence shows across the signatories in this run, where it runs out, and how current it is."
              actions={index.mode === 'DEMO' ? <DemoLabel long /> : undefined}
            />

            <section aria-label="Key figures" className="ts-panel grid grid-cols-2 gap-6 p-6 lg:grid-cols-4">
              <Stat
                label="Signatories"
                value={<CountUp value={summary.signatoryList.declaredCount ?? summary.signatoryList.parsedCount} />}
                sub={`${summary.signatoryList.parsedCount} parsed from the signer list · ${vendors.length} analysed`}
              />
              <Stat label="Observable goals" value={`${OBSERVABLE_GOAL_IDS.length}/7`} sub="G3 partially, G5 and G6 fully" />
              <Stat label="Not externally verifiable" value={`${UNVERIFIABLE_GOAL_IDS.length}/7`} sub="G1, G2, G4, G7 · no score is invented" />
              <FreshnessSummary summary={summary} />
            </section>

            <div className="mt-6 grid gap-6 xl:grid-cols-2">
              <Panel title="Evidence coverage across signatories" eyebrow="Distribution" description="Share of the fourteen evidence slots each vendor’s public sources could answer. Not a measure of security strength.">
                {all ? <Histogram buckets={all.coverageDistribution} unit="vendors" /> : <p className="text-sm text-ink-3">No cohort summary.</p>}
              </Panel>
              <Panel title="CVE record quality" eyebrow="Distribution" description="Complete CNA records (CWE and in-namespace CPE), per vendor. Vendors below the minimum sample are counted as not measured.">
                <Histogram buckets={quality} tone="stone" unit="vendors" />
              </Panel>
              <Panel title="VDP status" eyebrow="Counts" description="Goal 5 status per vendor in this run.">
                <ul className="space-y-3">
                  {vdpCounts.map(([k, n]) => (
                    <li key={k}>
                      <HBar value={(n / vdpMax) * 100} label={k.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase())} valueLabel={num(n)} tone={k === 'VERIFIED' ? 'sage' : k === 'PARTIAL' ? 'marigold' : 'stone'} />
                    </li>
                  ))}
                </ul>
              </Panel>
              <Panel title="Largest increases in observable evidence" eyebrow="From history" description="Change between the last two runs, only where the metric’s formula did not change between their methodology versions.">
                {history.status !== 'ready' ? (
                  <p className="text-sm text-ink-3">{history.status === 'loading' ? 'Loading history…' : 'History unavailable.'}</p>
                ) : improved.length === 0 ? (
                  <p className="text-sm text-ink-3">No comparable increase between the last two runs.</p>
                ) : (
                  <ul className="divide-y divide-line">
                    {improved.map((d) => (
                      <li key={`${d.vendorId}-${d.metricId}`} className="flex items-center justify-between gap-3 py-2.5">
                        <span className="min-w-0">
                          <Link to={`/app/vendors/${d.vendorId}`} className="ts-ident font-semibold text-ink hover:underline">
                            {vendorName(summary, d.vendorId)}
                          </Link>
                          <span className="block text-[0.78rem] text-ink-3">{defOf(summary, d.metricId)?.name ?? d.metricId}</span>
                        </span>
                        <span className="ts-num shrink-0 text-[0.84rem] text-ink-2">
                          {pct(d.from, 0)} → <span className="text-ink">{pct(d.to, 0)}</span> <span className="text-sage-ink">+{d.delta.toFixed(1)}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
              <Panel title="Biggest evidence gaps" eyebrow="Coverage" description="Vendors with the most evidence slots that public sources could not answer.">
                <ul className="divide-y divide-line">
                  {gaps.map((v) => (
                    <li key={v.vendor.id} className="py-2.5">
                      <div className="flex items-center justify-between gap-3">
                        <Link to={`/app/vendors/${v.vendor.id}`} className="ts-ident font-semibold text-ink hover:underline">
                          {v.vendor.canonicalName}
                        </Link>
                        <span className="ts-num shrink-0 text-[0.8rem] text-ink-2">
                          {v.coverage.unobserved.length} of {v.coverage.totalSlots} undetermined
                        </span>
                      </div>
                      <p className="ts-ident mt-0.5 line-clamp-1 text-[0.76rem] text-ink-3">{v.coverage.unobserved.slice(0, 3).map((u) => slotLabel(u.metricId, summary.metricDefinitions)).join(' · ')}</p>
                    </li>
                  ))}
                </ul>
              </Panel>
              <Panel title="Recently updated" eyebrow="Policy changes" description="Disclosure policies whose text or criteria changed between snapshots.">
                {recent.length === 0 ? (
                  <p className="text-sm text-ink-3">No policy changes detected in this run.</p>
                ) : (
                  <ul className="divide-y divide-line">
                    {recent.map(({ v, c }) => (
                      <li key={`${v.vendor.id}-${c.toSnapshotId}`} className="flex items-start justify-between gap-3 py-2.5">
                        <span className="min-w-0">
                          <Link to={`/app/vendors/${v.vendor.id}#vdp`} className="ts-ident font-semibold text-ink hover:underline">
                            {v.vendor.canonicalName}
                          </Link>
                          <span className="block text-[0.78rem] text-ink-3">
                            {c.criteria.filter((x) => x.before !== x.after).map((x) => `${criterionLabel(x.criterion)}: ${x.before.toLowerCase()} → ${x.after.toLowerCase()}`).join(' · ') || 'Text changed; criteria unchanged'}
                          </span>
                        </span>
                        <span className="ts-num shrink-0 text-[0.78rem] text-ink-2">{date(c.toObservedAt)}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
            </div>

            <div className="mt-6 grid gap-6">
              <Panel title="Run and methodology" eyebrow="Provenance">
                <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-5 gap-y-2 text-[0.84rem]">
                  <dt className="ts-eyebrow pt-0.5">Run</dt>
                  <dd className="ts-ident font-mono text-[0.8rem]">{m.runId}</dd>
                  <dt className="ts-eyebrow pt-0.5">Dataset</dt>
                  <dd className="font-mono text-[0.8rem]">
                    {m.datasetVersion} · {m.mode}
                  </dd>
                  <dt className="ts-eyebrow pt-0.5">Methodology</dt>
                  <dd className="font-mono text-[0.8rem]">
                    {m.methodologyVersion} · scoring {m.scoringVersion} · parser {m.parserVersion}
                  </dd>
                  <dt className="ts-eyebrow pt-0.5">Inputs</dt>
                  <dd className="ts-ident font-mono text-[0.8rem]">{shortHash(m.inputsHash, 24)}</dd>
                  <dt className="ts-eyebrow pt-0.5">Outputs</dt>
                  <dd className="ts-ident font-mono text-[0.8rem]">{shortHash(m.outputsHash, 24)}</dd>
                  <dt className="ts-eyebrow pt-0.5">Quality gate</dt>
                  <dd>
                    {checksPassed} of {m.qualityChecks.length} checks passed
                  </dd>
                  <dt className="ts-eyebrow pt-0.5">Exclusions</dt>
                  <dd>{num(summary.exclusionCount)} records excluded from attribution</dd>
                </dl>
                <div className="mt-5 flex flex-wrap gap-3 text-[0.84rem]">
                  <Link to="/app/runs" className="ts-link">
                    All runs and reproduction
                  </Link>
                  <Link to="/app/methodology" className="ts-link inline-flex items-center gap-1">
                    Methodology {m.methodologyVersion} <ArrowUpRight aria-hidden="true" className="size-3.5" />
                  </Link>
                </div>
              </Panel>
              <Panel title="Refresh pipeline" eyebrow="Fetch → normalize → validate → score → publish">
                <RefreshPipeline manifest={m} autoStart={params.get('refresh') === '1'} />
                <div className="mt-5 flex flex-wrap gap-2">
                  {summary.freshness
                    .filter((f) => f.state !== 'CURRENT')
                    .slice(0, 6)
                    .map((f) => (
                      <span key={f.sourceId} className="inline-flex items-center gap-1.5 text-[0.75rem] text-ink-2">
                        <FreshnessBadge state={f.state} />
                        <span className="ts-ident font-mono">{f.sourceId}</span>
                      </span>
                    ))}
                </div>
              </Panel>
            </div>
          </>
        )
      }}
    </Load>
  )
}

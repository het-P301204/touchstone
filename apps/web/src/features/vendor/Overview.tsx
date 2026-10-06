/**
 * Vendor evidence overview: coverage ring, goal status counts, scorecard, and
 * the goal-by-goal cards.
 */
import { Link } from 'react-router'
import { motion } from 'motion/react'
import type { DisplayState, GoalStatus, RunSummary, VendorSummary } from '@touchstone/core/model'
import { CoverageRing, StackBar } from '../../ui/charts.tsx'
import { StatusBadge } from '../../ui/StatusBadge.tsx'
import { Disclosure } from '../../ui/controls.tsx'
import { GOAL_STATUS, POSITION, TONE_CLASSES } from '../../lib/status.ts'
import { DIMENSION_LABEL, defOf, metricOf, metricText, slotLabel } from '../../lib/vocab.ts'
import { pct } from '../../lib/format.ts'
import { cx } from '../../lib/cx.ts'
import { HowCalculated } from '../figures.tsx'
import { usePaths } from '../../lib/paths.ts'

const STATUS_ORDER: GoalStatus[] = ['VERIFIED', 'PARTIAL', 'NOT_VERIFIED', 'DATA_ERROR', 'NOT_EXTERNALLY_VERIFIABLE']

export function EvidenceOverview({ summary, v, runId }: { summary: RunSummary; v: VendorSummary; runId: string }) {
  const c = v.coverage
  const counts = v.statusCounts
  const cwe = metricOf(v, 'cve.cwe_coverage')
  const cpe = metricOf(v, 'cve.cpe_coverage')
  const vdpDim = v.dimensions.find((d) => d.dimension === 'VDP')
  const timely = metricOf(v, 'cve.timely_issuance')
  const timelyBench = v.benchmarks.find((b) => b.metricId === 'cve.timely_issuance' && b.peerGroup === 'ALL_SIGNATORIES')
  const pledge = metricOf(v, 'vdp.pledge_elements_met')

  const scorecard: { label: string; value: string; sub: string; metric?: { goalId: string; metricId: string } }[] = [
    {
      label: 'CWE coverage',
      value: metricText(cwe?.metric, { unit: 'PERCENT' }),
      sub: cwe?.metric.calculation || 'CNA-supplied CWE, eligible records',
      metric: cwe ? { goalId: cwe.goal.goalId, metricId: 'cve.cwe_coverage' } : undefined,
    },
    {
      label: 'CPE coverage',
      value: metricText(cpe?.metric, { unit: 'PERCENT' }),
      sub: cpe?.metric.calculation || 'CNA-supplied CPE 2.3, eligible records',
      metric: cpe ? { goalId: cpe.goal.goalId, metricId: 'cve.cpe_coverage' } : undefined,
    },
    {
      label: 'VDP state',
      value: vdpDim ? GOAL_STATUS[vdpDim.status].label : '—',
      sub: pledge?.metric.value !== null && pledge?.metric.value !== undefined ? `${pledge.metric.value} of 4 pledge elements met` : 'Pledge elements not determined',
      metric: vdpDim ? { goalId: 'G5', metricId: 'vdp.criteria_met' } : undefined,
    },
    {
      label: 'CVE timeliness',
      value: metricText(timely?.metric, { unit: 'PERCENT' }),
      sub: timely?.metric.value !== null && timely?.metric.value !== undefined && timelyBench && timelyBench.position !== 'NOT_COMPARABLE' ? `${POSITION[timelyBench.position].label} (peer median ${pct(timelyBench.peerMedian, 0)})` : 'vs cohort: not comparable',
      metric: timely ? { goalId: timely.goal.goalId, metricId: 'cve.timely_issuance' } : undefined,
    },
  ]

  return (
    <section aria-labelledby="overview-title" className="grid gap-5 xl:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)]">
      <h2 id="overview-title" className="sr-only">
        Evidence overview
      </h2>
      <div className="ts-panel grid gap-6 p-6 md:grid-cols-[auto_minmax(0,1fr)] md:items-center xl:grid-cols-1">
        <CoverageRing percent={c.percent} observed={c.observedSlots} total={c.totalSlots} />
        <div className="min-w-0 space-y-4">
          <div>
            <p className="ts-eyebrow mb-2">Goals by evidence state</p>
            <StackBar
              parts={STATUS_ORDER.filter((s) => (counts[s] ?? 0) > 0).map((s) => ({
                key: s,
                label: GOAL_STATUS[s].label,
                value: counts[s] ?? 0,
                tone: GOAL_STATUS[s].tone,
                hatch: s === 'NOT_EXTERNALLY_VERIFIABLE',
                dashed: s === 'NOT_VERIFIED',
              }))}
            />
          </div>
          <p className="text-[0.82rem] leading-relaxed text-ink-2">
            Coverage counts evidence slots that public sources could answer for this vendor. It is not a measure of security strength.{' '}
            {c.unverifiableGoals} goals are outside the public evidence boundary for every vendor.
          </p>
          {c.unobserved.length > 0 && (
            <Disclosure summary={<span className="text-[0.82rem] font-semibold text-ink">{c.unobserved.length} {c.unobserved.length === 1 ? 'slot' : 'slots'} not determined</span>}>
              <ul className="mt-2 space-y-1.5 text-[0.8rem] text-ink-2">
                {c.unobserved.map((u) => (
                  <li key={u.metricId} className="flex gap-2">
                    <span aria-hidden="true" className="mt-[0.45rem] size-1.5 shrink-0 rounded-full border border-ink-3" />
                    <span className="min-w-0">
                      <span className="font-semibold text-ink">{slotLabel(u.metricId, summary.metricDefinitions)}</span>: {u.reason}
                    </span>
                  </li>
                ))}
              </ul>
            </Disclosure>
          )}
        </div>
      </div>

      <div className="ts-panel p-6">
        <div className="mb-4 flex items-baseline justify-between gap-3">
          <p className="ts-eyebrow">Scorecard</p>
          <p className="text-[0.75rem] text-ink-3">Each figure stands alone. There is no composite.</p>
        </div>
        <dl className="grid gap-px overflow-hidden rounded-card bg-line sm:grid-cols-2">
          {scorecard.map((s) => (
            <div key={s.label} className="min-w-0 bg-surface p-4">
              <div className="flex items-start justify-between gap-2">
                <dt className="ts-eyebrow">{s.label}</dt>
                {s.metric && <HowCalculated vendorId={v.vendor.id} runId={runId} goalId={s.metric.goalId} metricId={s.metric.metricId} iconOnly />}
              </div>
              <dd className="mt-2">
                <span className={cx('block leading-none text-ink', /^\d/.test(s.value) ? 'ts-num text-[1.65rem] font-medium' : s.value.startsWith('Not ') ? 'text-[1rem] font-semibold text-ink-2' : 'text-[1.3rem] font-bold tracking-tight')}>{s.value}</span>
                <span className="ts-ident mt-2 block font-mono text-[0.72rem] leading-snug text-ink-3">{s.sub}</span>
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  )
}

export function GoalCards({ summary, v, runId, disputedGoals }: { summary: RunSummary; v: VendorSummary; runId: string; disputedGoals: Set<string> }) {
  const paths = usePaths()
  const goalsById = new Map(summary.goals.map((g) => [g.id, g]))
  return (
    <section aria-labelledby="goals-title" id="goals" className="scroll-mt-24">
      <div className="mb-4 flex flex-wrap items-baseline justify-between gap-3">
        <h2 id="goals-title" className="text-title-2 text-ink">
          Goal by goal
        </h2>
        <p className="text-[0.8rem] text-ink-3">Status is the original result. A dispute is shown beside it, never instead of it.</p>
      </div>
      <ol className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
        {v.goals.map((g, i) => {
          const goal = goalsById.get(g.goalId)
          const nev = g.status === 'NOT_EXTERNALLY_VERIFIABLE'
          const states: DisplayState[] = [g.status, ...(disputedGoals.has(g.goalId) ? (['DISPUTED'] as const) : [])]
          return (
            <motion.li
              key={g.goalId}
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-40px' }}
              transition={{ duration: 0.45, delay: i * 0.04, ease: [0.16, 1, 0.3, 1] }}
              className={cx('ts-card flex min-w-0 flex-col p-5', nev && 'bg-surface/60')}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="ts-num text-[0.75rem] text-ink-3">{g.goalId}</p>
                  <h3 className="mt-0.5 text-[1.02rem] font-bold leading-snug text-ink">
                    <Link to={paths.goal(g.goalId)} className="hover:underline">
                      {goal?.name ?? g.goalId}
                    </Link>
                  </h3>
                </div>
                {nev && <span aria-hidden="true" className="ts-hatch h-8 w-10 shrink-0 rounded-[8px] ring-1 ring-inset ring-iris/40" />}
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {states.map((s) => (
                  <StatusBadge key={s} status={s} size="sm" />
                ))}
              </div>
              <p className="mt-3 text-[0.84rem] leading-relaxed text-ink-2">{g.statusReason}</p>
              {g.metrics.length > 0 && (
                <Disclosure className="mt-auto pt-4" summary={<span className="text-[0.8rem] font-semibold text-ink">{g.metrics.length} measurements</span>}>
                  <ul className="mt-3 divide-y divide-line rounded-[12px] border border-line">
                    {g.metrics.map((m) => {
                      const def = defOf(summary, m.metricId)
                      return (
                        <li key={m.metricId} className="flex min-w-0 items-center gap-3 px-3 py-2">
                          <span className="min-w-0 flex-1 text-[0.8rem] text-ink-2">{def?.name ?? m.metricId}</span>
                          <span className={cx('max-w-[55%] text-right text-[0.8rem]', m.value === null ? 'text-ink-3' : 'ts-num text-ink')}>{metricText(m, def)}</span>
                          <HowCalculated vendorId={v.vendor.id} runId={runId} goalId={g.goalId} metricId={m.metricId} iconOnly />
                        </li>
                      )
                    })}
                  </ul>
                </Disclosure>
              )}
              {g.claimCount > 0 && <p className="mt-3 text-[0.75rem] text-ink-3">{g.claimCount} self-reported claim{g.claimCount === 1 ? '' : 's'} (not evidence)</p>}
            </motion.li>
          )
        })}
      </ol>
    </section>
  )
}

export function DimensionLine({ v, dim }: { v: VendorSummary; dim: 'VDP' | 'CVE_QUALITY' | 'CVE_TIMELINESS' }) {
  const d = v.dimensions.find((x) => x.dimension === dim)
  const meta = d ? GOAL_STATUS[d.status] : GOAL_STATUS.NOT_VERIFIED
  return (
    <span className="inline-flex items-center gap-2 text-[0.82rem]">
      <span className={cx('size-2 rounded-full', TONE_CLASSES[meta.tone].dot)} aria-hidden="true" />
      {DIMENSION_LABEL[dim]} <span className="ts-num text-ink">{pct(d?.value ?? null)}</span>
    </span>
  )
}

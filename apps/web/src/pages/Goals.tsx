import { Link, useParams } from 'react-router'
import { ArrowLeft, ArrowRight, ArrowUpRight } from 'lucide-react'
import type { GoalStatus } from '@touchstone/core/model'
import { GOALS, PLEDGE_SOURCE_URL, goalById } from '../lib/core.ts'
import { GOAL_STATUS, VERIFICATION_MODE } from '../lib/status.ts'
import { cx } from '../lib/cx.ts'
import { useInApp, usePaths } from '../lib/paths.ts'
import { ModeSwatch } from '../landing/GoalBoundary.tsx'
import { useActiveSummary } from '../data/hooks.ts'
import { StackBar } from '../ui/charts.tsx'
import { StatusBadge } from '../ui/StatusBadge.tsx'
import { Panel } from '../ui/Panel.tsx'
import { DemoLabel } from '../ui/controls.tsx'
import { EmptyState } from '../ui/States.tsx'
import { defOf } from '../lib/vocab.ts'

function Wrap({ children }: { children: React.ReactNode }) {
  const inApp = useInApp()
  return <div className={cx(!inApp && 'mx-auto max-w-page px-4 py-12 sm:px-6 lg:px-10')}>{children}</div>
}

export function GoalsIndex() {
  const paths = usePaths()
  return (
    <Wrap>
      <header className="mb-10 max-w-3xl">
        <p className="ts-eyebrow mb-3">The pledge</p>
        <h1 className="text-display text-ink">Seven goals. Three leave public evidence.</h1>
        <p className="mt-5 text-lede text-ink-2">
          The Secure by Design Pledge asks signatories to make measurable progress on seven goals. Pledge text below is quoted verbatim from{' '}
          <a href={PLEDGE_SOURCE_URL} className="ts-link inline-flex items-center gap-1" target="_blank" rel="noopener noreferrer">
            CISA <ArrowUpRight aria-hidden="true" className="size-3.5" />
          </a>
          .
        </p>
      </header>
      <ol className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {GOALS.map((g) => {
          const mode = VERIFICATION_MODE[g.verificationMode]
          return (
            <li key={g.id} className={cx('ts-panel flex flex-col p-6', g.verificationMode === 'NOT_EXTERNALLY_VERIFIABLE' && 'bg-surface/70')}>
              <div className="flex items-center justify-between gap-3">
                <span className="ts-num text-[0.8rem] text-ink-3">Goal {g.number}</span>
                <ModeSwatch mode={g.verificationMode} className="h-5 w-14" />
              </div>
              <h2 className="mt-3 text-title-3 text-ink">{g.name}</h2>
              <p className="mt-1 text-[0.8rem] font-semibold text-ink-2">{mode.label}</p>
              <p className="mt-3 line-clamp-4 text-[0.86rem] leading-relaxed text-ink-2">“{g.pledgeText}”</p>
              <Link to={paths.goal(g.id)} className="ts-link mt-auto inline-flex items-center gap-1.5 pt-5 text-sm">
                Method and evidence <ArrowRight aria-hidden="true" className="size-4" />
              </Link>
            </li>
          )
        })}
      </ol>
      <p className="mt-8 text-sm text-ink-2">
        Four goals cannot be verified from public evidence.{' '}
        <Link to={paths.cannotSee} className="ts-link">
          Read what verification would need
        </Link>
        .
      </p>
    </Wrap>
  )
}

const ORDER: GoalStatus[] = ['VERIFIED', 'PARTIAL', 'NOT_VERIFIED', 'DATA_ERROR', 'NOT_EXTERNALLY_VERIFIABLE']

function GoalAcrossVendors({ goalId }: { goalId: string }) {
  const value = useActiveSummary()
  const paths = usePaths()
  if (value.status !== 'ready') return null
  const { summary, index } = value.data
  const rows = summary.vendors.map((v) => ({ v, g: v.goals.find((x) => x.goalId === goalId) })).filter((r) => r.g)
  const counts = ORDER.map((s) => ({ s, n: rows.filter((r) => r.g!.status === s).length })).filter((c) => c.n > 0)
  return (
    <Panel
      eyebrow={`Run ${summary.manifest.runId}`}
      title="Across the vendors in this run"
      actions={index.mode === 'DEMO' ? <DemoLabel /> : undefined}
      description="Original results per vendor. For goals outside the evidence boundary, every vendor carries the same state: it describes the goal, not the vendor."
    >
      <StackBar parts={counts.map(({ s, n }) => ({ key: s, label: GOAL_STATUS[s].label, value: n, tone: GOAL_STATUS[s].tone, hatch: s === 'NOT_EXTERNALLY_VERIFIABLE', dashed: s === 'NOT_VERIFIED' }))} />
      <ul className="mt-5 grid gap-x-6 gap-y-2 sm:grid-cols-2">
        {rows.map(({ v, g }) => (
          <li key={v.vendor.id} className="flex min-w-0 items-center justify-between gap-3 border-b border-line py-2">
            <Link to={paths.vendor(v.vendor.id)} className="ts-ident min-w-0 text-[0.86rem] font-semibold text-ink hover:underline">
              {v.vendor.canonicalName}
            </Link>
            <StatusBadge status={g!.status} size="sm" short />
          </li>
        ))}
      </ul>
    </Panel>
  )
}

export function GoalDetail() {
  const { goalId = '' } = useParams()
  const paths = usePaths()
  const goal = goalById(goalId.toUpperCase())
  const summary = useActiveSummary()
  if (!goal)
    return (
      <Wrap>
        <EmptyState title="No such goal">The pledge has goals G1 to G7.</EmptyState>
      </Wrap>
    )
  const mode = VERIFICATION_MODE[goal.verificationMode]
  const i = GOALS.indexOf(goal)
  const prev = GOALS[i - 1]
  const next = GOALS[i + 1]
  return (
    <Wrap>
      <nav aria-label="Breadcrumb" className="mb-5 text-[0.8rem] text-ink-3">
        <Link to={paths.goals} className="hover:text-ink">
          Goals
        </Link>{' '}
        / <span className="text-ink-2">{goal.id}</span>
      </nav>
      <header className="max-w-3xl">
        <p className="inline-flex items-center gap-2 text-[0.84rem] font-semibold text-ink-2">
          <ModeSwatch mode={goal.verificationMode} className="h-3.5 w-7" />
          Goal {goal.number} · {mode.label}
        </p>
        <h1 className="mt-3 text-display text-ink">{goal.name}</h1>
        <blockquote className="mt-6 border-l-2 border-marigold pl-5 text-lede text-ink">“{goal.pledgeText}”</blockquote>
        <p className="mt-2 pl-5 text-[0.78rem] text-ink-3">Pledge text, quoted verbatim from CISA.</p>
      </header>

      <div className="mt-10 grid gap-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-6">
          <Panel title="Method" eyebrow="How TOUCHSTONE treats this goal">
            <p className="text-[0.92rem] leading-relaxed text-ink">{goal.methodology.summary}</p>
            <p className="ts-eyebrow mb-1.5 mt-5">Status rule</p>
            <p className="rounded-[12px] bg-paper-2/70 px-3.5 py-3 font-mono text-[0.78rem] leading-relaxed text-ink">{goal.methodology.statusRule}</p>
            {goal.methodology.metricIds.length > 0 && (
              <>
                <p className="ts-eyebrow mb-2 mt-5">Metrics</p>
                <ul className="divide-y divide-line rounded-[12px] border border-line">
                  {goal.methodology.metricIds.map((id) => {
                    const def = summary.status === 'ready' ? defOf(summary.data.summary, id) : undefined
                    return (
                      <li key={id} className="px-3.5 py-2.5">
                        <span className="text-[0.86rem] font-semibold text-ink">{def?.name ?? id}</span> <span className="font-mono text-[0.72rem] text-ink-3">{id}</span>
                        {def && <p className="mt-1 text-[0.8rem] leading-relaxed text-ink-2">{def.formula}</p>}
                      </li>
                    )
                  })}
                </ul>
              </>
            )}
          </Panel>
          <Panel title="Evidence requirements" eyebrow="What would answer it">
            <ul className="space-y-2">
              {goal.evidenceRequirements.map((r) => (
                <li key={r.id} className="flex items-start gap-3 text-[0.88rem]">
                  <span aria-hidden="true" className={cx('mt-1 inline-block h-3 w-5 shrink-0 rounded-[4px]', r.publiclyAvailable ? 'bg-sage' : 'ts-hatch ring-1 ring-inset ring-iris/60')} />
                  <span className="min-w-0 text-ink">
                    {r.description} <span className="text-ink-3">· {r.publiclyAvailable ? 'publicly available' : 'not publicly available'}</span>
                  </span>
                </li>
              ))}
            </ul>
            {goal.methodology.evidenceNeeded.length > 0 && (
              <>
                <p className="ts-eyebrow mb-2 mt-5">Verification would need</p>
                <ul className="list-disc space-y-1 pl-5 text-[0.88rem] text-ink-2">
                  {goal.methodology.evidenceNeeded.map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              </>
            )}
            <p className="ts-eyebrow mb-2 mt-5">Limitations</p>
            <ul className="list-disc space-y-1 pl-5 text-[0.88rem] text-ink-2">
              {goal.methodology.limitations.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          </Panel>
        </div>
        <div className="min-w-0">
          <GoalAcrossVendors goalId={goal.id} />
        </div>
      </div>

      <nav aria-label="Other goals" className="mt-10 flex flex-wrap justify-between gap-3 border-t border-line pt-6 text-sm">
        {prev ? (
          <Link to={paths.goal(prev.id)} className="ts-link inline-flex items-center gap-1.5">
            <ArrowLeft aria-hidden="true" className="size-4" /> {prev.id} {prev.name}
          </Link>
        ) : (
          <span />
        )}
        {next && (
          <Link to={paths.goal(next.id)} className="ts-link inline-flex items-center gap-1.5">
            {next.id} {next.name} <ArrowRight aria-hidden="true" className="size-4" />
          </Link>
        )}
      </nav>
    </Wrap>
  )
}

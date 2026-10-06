/**
 * Shared figure cells for tables and cards. A null value is shown as "not
 * measured" with its reason, never as 0.
 */
import type { DimensionId, FreshnessState, RunSummary, SourceFreshness, VendorSummary } from '@touchstone/core/model'
import { Ruler } from 'lucide-react'
import { cx } from '../lib/cx.ts'
import { pct } from '../lib/format.ts'
import { GOAL_STATUS, TONE_CLASSES } from '../lib/status.ts'
import { DIMENSION_LABEL, GAP_LABEL, dimensionOf, metricOf } from '../lib/vocab.ts'
import { useUi } from '../state/ui.ts'
import { FreshnessBadge } from '../ui/StatusBadge.tsx'

const FRESH_ORDER: FreshnessState[] = ['CURRENT', 'AGING', 'STALE', 'UNKNOWN']

/** True when a source id is scoped to this vendor ("vendor.<vendorId>.<kind>"). */
export function isVendorSource(sourceId: string, vendorId: string): boolean {
  return sourceId.split('.')[1] === vendorId && sourceId.startsWith('vendor.')
}

/** Sources that belong to a vendor (vendor-scoped source ids). */
export function vendorFreshness(summary: Pick<RunSummary, 'freshness'>, vendorId: string): SourceFreshness[] {
  return summary.freshness.filter((f) => isVendorSource(f.sourceId, vendorId))
}

/** Worst freshness state among the vendor's own sources (UNKNOWN when none). */
export function worstFreshness(summary: Pick<RunSummary, 'freshness'>, vendorId: string): FreshnessState {
  const list = vendorFreshness(summary, vendorId)
  if (list.length === 0) return 'UNKNOWN'
  return list.reduce<FreshnessState>((w, f) => (FRESH_ORDER.indexOf(f.state) > FRESH_ORDER.indexOf(w) ? f.state : w), 'CURRENT')
}

export function dimensionValue(v: VendorSummary, dim: DimensionId): number | null {
  return dimensionOf(v, dim)?.value ?? null
}

/** Why a dimension has no value, from its metric's gap. */
export function dimensionGap(v: VendorSummary, dim: DimensionId): string | null {
  const d = dimensionOf(v, dim)
  if (!d || d.value !== null) return null
  const m = metricOf(v, d.metricId)?.metric
  if (d.status === 'NOT_EXTERNALLY_VERIFIABLE') return GOAL_STATUS.NOT_EXTERNALLY_VERIFIABLE.label
  if (d.status === 'DATA_ERROR') return m?.gap ? `Data error: ${(GAP_LABEL[m.gap] ?? m.gap).toLowerCase()}` : 'Data error'
  return m?.gap ? `Not measured: ${(GAP_LABEL[m.gap] ?? m.gap).toLowerCase()}` : 'Not measured'
}

export function DimensionCell({ v, dim, compact = false }: { v: VendorSummary; dim: DimensionId; compact?: boolean }) {
  const d = dimensionOf(v, dim)
  const value = d?.value ?? null
  const status = d?.status ?? 'NOT_VERIFIED'
  const meta = GOAL_STATUS[status]
  const Icon = meta.icon
  if (value === null) {
    return (
      <span className="inline-flex min-w-0 items-center gap-1.5 text-[0.8rem] text-ink-3" title={meta.description}>
        <Icon aria-hidden="true" className="size-3.5 shrink-0" />
        <span className="truncate">{dimensionGap(v, dim)}</span>
      </span>
    )
  }
  return (
    <span className="flex min-w-0 items-center gap-2.5">
      <span className="ts-num w-[3.6rem] shrink-0 text-right text-[0.88rem] text-ink">{pct(value, compact ? 0 : 1)}</span>
      {!compact && (
        <span className="relative hidden h-1.5 w-16 shrink-0 overflow-hidden rounded-full bg-paper-3 sm:block" aria-hidden="true">
          <span className={cx('absolute inset-y-0 left-0 rounded-full', TONE_CLASSES[meta.tone === 'stone' ? 'stone' : meta.tone].fill)} style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
        </span>
      )}
      <span title={`${DIMENSION_LABEL[dim]}: ${meta.label}`} className={cx('shrink-0', TONE_CLASSES[meta.tone].text)}>
        <Icon aria-hidden="true" className="size-3.5" />
        <span className="sr-only">{meta.label}</span>
      </span>
    </span>
  )
}

export function CoverageCell({ v }: { v: VendorSummary }) {
  const c = v.coverage
  return (
    <span className="flex min-w-0 items-center gap-2.5" title="Coverage of independently observable evidence (not security strength)">
      <span className="ts-num w-[3.2rem] shrink-0 text-right text-[0.88rem] text-ink">{pct(c.percent, 0)}</span>
      <span aria-hidden="true" className="hidden gap-[2px] sm:flex">
        {Array.from({ length: c.totalSlots }, (_, i) => (
          <span key={i} className={cx('h-3 w-[5px] rounded-[1.5px]', i < c.observedSlots ? 'bg-ink-2' : 'bg-paper-3')} />
        ))}
      </span>
      <span className="ts-num text-[0.72rem] text-ink-3 sm:hidden">
        {c.observedSlots}/{c.totalSlots}
      </span>
    </span>
  )
}

export function FreshnessCell({ summary, vendorId }: { summary: RunSummary; vendorId: string }) {
  return <FreshnessBadge state={worstFreshness(summary, vendorId)} />
}

/** "How was this calculated?" trigger for one metric. */
export function HowCalculated({
  vendorId,
  runId,
  goalId,
  metricId,
  label = 'How was this calculated?',
  iconOnly = false,
  className,
}: {
  vendorId: string
  runId: string
  goalId: string
  metricId: string
  label?: string
  iconOnly?: boolean
  className?: string
}) {
  const openMetric = useUi((s) => s.openMetric)
  return (
    <button
      type="button"
      onClick={() => openMetric({ vendorId, runId, goalId, metricId })}
      aria-label={iconOnly ? `${label} (${metricId})` : undefined}
      title={iconOnly ? label : undefined}
      className={cx(
        'inline-flex shrink-0 items-center gap-1.5 rounded-[10px] text-[0.78rem] font-semibold text-ink-2 transition-colors hover:text-ink',
        iconOnly ? 'size-7 justify-center hover:bg-paper-2' : 'px-0 underline decoration-line-strong underline-offset-4 hover:decoration-ink',
        className,
      )}
    >
      <Ruler aria-hidden="true" className="size-3.5" />
      {!iconOnly && label}
    </button>
  )
}

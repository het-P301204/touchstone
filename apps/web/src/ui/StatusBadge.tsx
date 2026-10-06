/**
 * State chips. Every chip is icon + text; colour is reinforcement only.
 * NOT_EXTERNALLY_VERIFIABLE carries the hatch (the evidence boundary),
 * unknown states carry a dashed outline.
 */
import type { ReactNode } from 'react'
import type { CriterionState, DisplayState, FreshnessState } from '@touchstone/core/model'
import { cx } from '../lib/cx.ts'
import { CRITERION_STATE, FRESHNESS_STATE, GOAL_STATUS, TONE_CLASSES } from '../lib/status.ts'
import type { StateMeta, Tone } from '../lib/status.ts'

export function StateChip({ meta, size = 'md', className, label }: { meta: StateMeta; size?: 'sm' | 'md'; className?: string; label?: string }) {
  const Icon = meta.icon
  return (
    <span
      title={meta.description}
      className={cx(
        'inline-flex max-w-full items-center gap-1.5 whitespace-nowrap rounded-chip font-semibold ring-1 ring-inset',
        size === 'sm' ? 'h-6 px-2 text-[0.72rem]' : 'h-7 px-2.5 text-[0.78rem]',
        TONE_CLASSES[meta.tone].chip,
        meta.hatch && 'ts-hatch-soft',
        meta.dashed && 'ring-0 outline-dashed outline-1 -outline-offset-1 outline-ink-3/60',
        className,
      )}
    >
      <Icon aria-hidden="true" className={size === 'sm' ? 'size-3.5 shrink-0' : 'size-4 shrink-0'} strokeWidth={2.2} />
      <span className="truncate">{label ?? meta.label}</span>
    </span>
  )
}

export function StatusBadge({ status, size, className, short }: { status: DisplayState; size?: 'sm' | 'md'; className?: string; short?: boolean }) {
  const meta = GOAL_STATUS[status]
  return <StateChip meta={meta} size={size} className={className} label={short && meta.short ? meta.short : undefined} />
}

export function CriterionBadge({ state, size = 'sm' }: { state: CriterionState; size?: 'sm' | 'md' }) {
  return <StateChip meta={CRITERION_STATE[state]} size={size} />
}

export function FreshnessBadge({ state, size = 'sm' }: { state: FreshnessState; size?: 'sm' | 'md' }) {
  return <StateChip meta={FRESHNESS_STATE[state]} size={size} />
}

export function ToneDot({ tone, className }: { tone: Tone; className?: string }) {
  return <span aria-hidden="true" className={cx('inline-block size-2 shrink-0 rounded-full', TONE_CLASSES[tone].dot, className)} />
}

/** A plain text tag (category, source family). */
export function Tag({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cx('inline-flex h-6 max-w-full items-center rounded-chip border border-line bg-paper-2/70 px-2 font-mono text-[0.68rem] uppercase tracking-[0.08em] text-ink-2', className)}>
      <span className="truncate">{children}</span>
    </span>
  )
}

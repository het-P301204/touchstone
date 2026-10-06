/**
 * Shared construction of MetricValue objects so every measure applies the
 * same null/gap/minimum-sample rules:
 *
 *   denominator 0                     -> value null, gap NO_ELIGIBLE_RECORDS (or the caller's gap)
 *   denominator < minimum sample      -> value null, gap BELOW_MINIMUM_SAMPLE (never 0)
 *   otherwise                         -> numerator / denominator × 100
 */

import type { MetricValue } from '../model/index.ts'
import type { ConfidenceTally } from './context.ts'
import { fmt, percent } from './stats.ts'

export type Gap = NonNullable<MetricValue['gap']>

export function sortedUnique(ids: string[]): string[] {
  return [...new Set(ids)].sort()
}

export function ratioMetric(a: {
  metricId: string
  numerator: number
  denominator: number
  /** Minimum denominator before a value is reported (0 = no minimum). */
  minimum: number
  /** Gap when the denominator is 0. */
  emptyGap?: Gap
  /** Unit word for the calculation string, e.g. "records". */
  noun: string
  evidenceIds: string[]
  query: string
  tally: ConfidenceTally
  breakdown?: Record<string, number>
}): MetricValue {
  const base = {
    metricId: a.metricId,
    evidenceIds: sortedUnique(a.evidenceIds),
    query: a.query,
  }
  const extra = a.breakdown ? { breakdown: a.breakdown } : {}
  if (a.denominator === 0) {
    a.tally.fire('C6.NOT_MEASURED', `No eligible ${a.noun}.`)
    return {
      ...base,
      value: null,
      gap: a.emptyGap ?? 'NO_ELIGIBLE_RECORDS',
      calculation: `No eligible ${a.noun}: not measured.`,
      ...a.tally.result(),
      ...extra,
    }
  }
  if (a.denominator < a.minimum) {
    a.tally.fire('C6.NOT_MEASURED', `${a.denominator} eligible ${a.noun}, below the minimum sample of ${a.minimum}.`)
    return {
      ...base,
      value: null,
      numerator: a.numerator,
      denominator: a.denominator,
      gap: 'BELOW_MINIMUM_SAMPLE',
      calculation: `${a.numerator} / ${a.denominator} ${a.noun}: below the minimum sample of ${a.minimum}; not reported.`,
      ...a.tally.result(),
      ...extra,
    }
  }
  const value = percent(a.numerator, a.denominator)
  return {
    ...base,
    value,
    numerator: a.numerator,
    denominator: a.denominator,
    calculation: `${a.numerator} / ${a.denominator} = ${fmt(value)}%`,
    ...a.tally.result(),
    ...extra,
  }
}

/** A metric that could not be measured at all (no source, source unusable). */
export function absentMetric(a: { metricId: string; gap: Gap; reason: string; query: string; tally: ConfidenceTally; breakdown?: Record<string, number> }): MetricValue {
  a.tally.fire('C6.NOT_MEASURED', a.reason)
  const m: MetricValue = {
    metricId: a.metricId,
    value: null,
    gap: a.gap,
    evidenceIds: [],
    query: a.query,
    calculation: `${a.reason} Not measured.`,
    ...a.tally.result(),
  }
  if (a.breakdown) m.breakdown = a.breakdown
  return m
}

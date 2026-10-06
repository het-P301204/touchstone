/**
 * Goal 3 signal: the share of the vendor's disclosed records (with a
 * CNA-supplied CWE identifier) that fall in a tracked weakness class, in the
 * latest 12 months versus the prior 12 months.
 *
 * This describes disclosed records only. Disclosure volume, product mix and
 * CWE assignment practice all move the share without any change in
 * prevalence, so the goal status derived from it is at most PARTIAL.
 */

import type { CveRecord, MetricValue } from '../model/index.ts'
import { ConfidenceTally, familyFreshness, resolveSource } from './context.ts'
import type { MeasureContext } from './context.ts'
import { TRACKED_CWE_CLASSES } from './definitions.ts'
import { absentMetric, sortedUnique } from './metric.ts'
import { fmt, isoDaysBefore, percent, round2, toMs } from './stats.ts'

const YEAR_DAYS = 365

/** CNA CWE identifiers that name a weakness (placeholders and malformed values excluded). */
export function cnaCweIds(r: CveRecord): string[] {
  return [...new Set(r.cna.cwes.filter((w) => w.id !== null && !w.placeholder).map((w) => w.id!))].sort()
}

/** Tracked class ids the record falls in. */
export function classesOf(cwes: string[]): string[] {
  return TRACKED_CWE_CLASSES.filter((c) => cwes.some((w) => c.cwes.includes(w))).map((c) => c.id)
}

export function measureClassShare(ctx: MeasureContext): MetricValue {
  const params = ctx.methodology.parameters
  const vendorId = ctx.vendor.id
  const min = params.minimumRecordsPerTrendPeriod
  const latestStart = isoDaysBefore(ctx.asOf, YEAR_DAYS)
  const priorStart = isoDaysBefore(ctx.asOf, 2 * YEAR_DAYS)
  const query = `cve_records WHERE attributed_to = '${vendorId}' AND state = 'PUBLISHED' AND cna CWE identifier present; prior = (${priorStart}, ${latestStart}], latest = (${latestStart}, ${ctx.asOf}] -> share in tracked classes [${TRACKED_CWE_CLASSES.map((c) => c.id).join(', ')}]`
  const latestStartMs = toMs(latestStart)!
  const priorStartMs = toMs(priorStart)!

  type P = { n: number; inAny: number; byClass: Record<string, number> }
  const mk = (): P => ({ n: 0, inAny: 0, byClass: Object.fromEntries(TRACKED_CWE_CLASSES.map((c) => [c.id, 0])) })
  const prior = mk()
  const latest = mk()
  const evidence: string[] = []
  let mediumAttribution = 0

  for (const { record: r, attribution } of ctx.attributed) {
    if (r.state !== 'PUBLISHED' || ctx.duplicateIds.has(r.id)) continue
    const ms = toMs(r.datePublished)
    if (ms === null || ms > ctx.asOfMs || ms <= priorStartMs) continue
    const cwes = cnaCweIds(r)
    if (cwes.length === 0) continue
    const period = ms > latestStartMs ? 'LATEST' : 'PRIOR'
    const p = period === 'LATEST' ? latest : prior
    const classes = classesOf(cwes)
    p.n++
    if (classes.length > 0) p.inAny++
    for (const c of classes) p.byClass[c]!++
    if (attribution.confidence !== 'HIGH') mediumAttribution++
    const src = resolveSource(ctx, r.snapshotId, 'CVE_PROGRAM')
    evidence.push(
      ctx.ledger.add({
        vendorId,
        metricId: 'g3.class_share_trend',
        sourceId: src.sourceId,
        snapshotId: r.snapshotId,
        subject: r.id,
        collectedAt: src.collectedAt,
        extracted: { container: 'CNA', cwe: cwes, period, trackedClasses: classes, datePublished: r.datePublished ?? null },
        interpretation: 'CONTEXT',
        reading:
          classes.length > 0
            ? `${period === 'LATEST' ? 'Latest' : 'Prior'} period: CNA CWE ${cwes.join(', ')} is in tracked class ${classes.join(', ')}.`
            : `${period === 'LATEST' ? 'Latest' : 'Prior'} period: CNA CWE ${cwes.join(', ')} is outside the tracked classes.`,
        confidence: attribution.confidence,
        methodologyVersion: ctx.methodology.version,
      }),
    )
  }

  const t = new ConfidenceTally()
  if (mediumAttribution > 0) t.fire('C1.ATTRIBUTION', `${mediumAttribution} contributing records were attributed by affected-vendor name only.`)
  t.freshness(familyFreshness(ctx, 'CVE_PROGRAM'))
  const breakdown: Record<string, number> = { prior_records: prior.n, latest_records: latest.n, prior_in_tracked: prior.inAny, latest_in_tracked: latest.inAny }
  // A period with no records has no share: the key is omitted (never reported as 0%).
  for (const c of TRACKED_CWE_CLASSES) {
    if (prior.n) breakdown[`prior_share_pct.${c.id}`] = percent(prior.byClass[c.id]!, prior.n)
    if (latest.n) breakdown[`latest_share_pct.${c.id}`] = percent(latest.byClass[c.id]!, latest.n)
  }
  if (prior.n < min || latest.n < min) {
    const m = absentMetric({
      metricId: 'g3.class_share_trend',
      gap: prior.n === 0 && latest.n === 0 ? (ctx.cveSourceFailed ? 'SOURCE_FAILED' : 'NO_ELIGIBLE_RECORDS') : 'BELOW_MINIMUM_SAMPLE',
      reason: `Records with a CNA CWE identifier: prior period ${prior.n}, latest period ${latest.n}; each period needs at least ${min}.`,
      query,
      tally: t,
      breakdown,
    })
    m.evidenceIds = sortedUnique(evidence)
    return m
  }
  const priorShare = percent(prior.inAny, prior.n)
  const latestShare = percent(latest.inAny, latest.n)
  const change = round2(latestShare - priorShare)
  breakdown['prior_share_pct'] = priorShare
  breakdown['latest_share_pct'] = latestShare
  return {
    metricId: 'g3.class_share_trend',
    value: change,
    numerator: latest.inAny,
    denominator: latest.n,
    evidenceIds: sortedUnique(evidence),
    query,
    calculation: `latest ${latest.inAny} / ${latest.n} = ${fmt(latestShare)}% minus prior ${prior.inAny} / ${prior.n} = ${fmt(priorShare)}% → ${change > 0 ? '+' : ''}${fmt(change)} percentage points`,
    breakdown,
    ...t.result(),
  }
}

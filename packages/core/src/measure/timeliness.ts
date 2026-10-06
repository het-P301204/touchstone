/**
 * Goal 6, issuance timeliness, from the vendor's own high-impact advisories.
 *
 *  - No machine-readable advisory feed: the metrics are null with gap
 *    NO_SOURCE, never zero.
 *  - The CVE source could not be read (no usable snapshot): null with gap
 *    SOURCE_FAILED. An unread source says nothing about whether CVEs exist.
 *  - Advisories are de-duplicated by (vendorId, id).
 *  - A listed CVE id that exists more than once with conflicting content is
 *    UNDETERMINED: the advisory is set aside (outside the denominator) and
 *    listed in the breakdown. It is never read as "no CVE record exists".
 *  - A CVE published after asOf did not exist at the analysis date: it is not
 *    credited (not timely, not "with CVE").
 *  - The tolerance comparison is on raw milliseconds; rounding is for display only.
 *  - Fewer than minimumHighImpactAdvisories: the value is shown with LOW
 *    confidence (rule C2.SAMPLE) and cannot make Goal 6 or the figure VERIFIED.
 *
 * The tolerance (timelinessToleranceDays) is a TOUCHSTONE methodology
 * parameter, not a CISA threshold, and every reading says so.
 */

import type { Advisory, CveRecord, MetricValue } from '../model/index.ts'
import { ConfidenceTally, resolveSource } from './context.ts'
import type { MeasureContext } from './context.ts'
import { absentMetric, ratioMetric, sortedUnique } from './metric.ts'
import { DAY_MS, daysBetween, fmt, isoDaysBefore, median, percentileNearestRank, toMs, withinDaysBefore } from './stats.ts'
import { canonicalJson } from '../run/canonical.ts'

export type AdvisoryOutcome = 'TIMELY' | 'LATE' | 'NO_CVE_LISTED' | 'CVE_NOT_IN_SNAPSHOT' | 'CVE_PUBLISHED_AFTER_AS_OF' | 'CVE_UNDETERMINED'

export type AdvisoryTiming = {
  advisory: Advisory
  /** Listed CVE ids that exist as PUBLISHED records with a datePublished on or before asOf. */
  found: CveRecord[]
  /** Listed CVE ids absent from the snapshot, REJECTED, or without a datePublished. */
  missing: string[]
  /** Listed CVE ids published after the analysis date. */
  publishedAfterAsOf: string[]
  /** Listed CVE ids that exist more than once with conflicting content (outcome undetermined). */
  undetermined: string[]
  /** Latest found CVE datePublished minus advisory release, in days (display, 2 decimals); null when nothing was found. */
  latencyDays: number | null
  /** The same latency in raw milliseconds (the tolerance comparison uses this). */
  latencyMs: number | null
  outcome: AdvisoryOutcome
}

export function timeAdvisory(
  a: Advisory,
  cvesById: Map<string, CveRecord>,
  toleranceDays: number,
  opts: { asOfMs?: number; duplicateIds?: Set<string> } = {},
): AdvisoryTiming {
  const listed = [...new Set(a.cveIds)].sort()
  const found: CveRecord[] = []
  const missing: string[] = []
  const publishedAfterAsOf: string[] = []
  const undetermined: string[] = []
  for (const id of listed) {
    if (opts.duplicateIds?.has(id)) {
      undetermined.push(id)
      continue
    }
    const r = cvesById.get(id)
    const ms = r ? toMs(r.datePublished) : null
    if (!r || r.state !== 'PUBLISHED' || ms === null) missing.push(id)
    else if (opts.asOfMs !== undefined && ms > opts.asOfMs) publishedAfterAsOf.push(id)
    else found.push(r)
  }
  const advMs = toMs(a.publishedAt)
  let latencyMs: number | null = null
  if (advMs !== null && found.length > 0) latencyMs = Math.max(...found.map((r) => toMs(r.datePublished)!)) - advMs
  const latencyDays = latencyMs === null ? null : daysBetween(0, latencyMs)
  let outcome: AdvisoryOutcome
  if (listed.length === 0) outcome = 'NO_CVE_LISTED'
  else if (undetermined.length > 0) outcome = 'CVE_UNDETERMINED'
  else if (missing.length > 0 || latencyMs === null) outcome = publishedAfterAsOf.length > 0 && missing.length === 0 ? 'CVE_PUBLISHED_AFTER_AS_OF' : 'CVE_NOT_IN_SNAPSHOT'
  else if (publishedAfterAsOf.length > 0) outcome = 'CVE_PUBLISHED_AFTER_AS_OF'
  else outcome = latencyMs <= toleranceDays * DAY_MS ? 'TIMELY' : 'LATE'
  return { advisory: a, found, missing, publishedAfterAsOf, undetermined, latencyDays, latencyMs, outcome }
}

/** One advisory per (vendorId, id); among copies with different content the canonical-first wins. */
export function dedupeAdvisories(advisories: Advisory[]): { advisories: Advisory[]; duplicates: number } {
  const byKey = new Map<string, { a: Advisory; c: string }>()
  let duplicates = 0
  for (const a of advisories) {
    const key = `${a.vendorId}|${a.id}`
    const c = canonicalJson(a)
    const cur = byKey.get(key)
    if (!cur) byKey.set(key, { a, c })
    else {
      duplicates++
      if (c < cur.c) byKey.set(key, { a, c })
    }
  }
  const out = [...byKey.values()].map((x) => x.a).sort((x, y) => (x.vendorId + '|' + x.id < y.vendorId + '|' + y.id ? -1 : 1))
  return { advisories: out, duplicates }
}

export type TimelinessResult = { metrics: MetricValue[]; timings: AdvisoryTiming[] }

const TIMELINESS_METRICS = ['cve.high_impact_with_cve', 'cve.timely_issuance', 'cve.publication_latency']

export function measureTimeliness(ctx: MeasureContext): TimelinessResult {
  const params = ctx.methodology.parameters
  const version = ctx.methodology.version
  const vendorId = ctx.vendor.id
  const tol = params.timelinessToleranceDays
  const sev = params.highImpactSeverities
  const minAdv = params.minimumHighImpactAdvisories ?? params.minimumEligibleRecords
  const windowStart = isoDaysBefore(ctx.asOf, params.cveWindowDays)
  const advQuery = `advisories WHERE vendorId = '${vendorId}' AND severity IN (${sev.join(', ')}) AND publishedAt IN (${windowStart}, ${ctx.asOf}] (one per advisory id)`

  const { advisories, duplicates } = dedupeAdvisories(ctx.advisories)
  if (advisories.length === 0) {
    const reason = ctx.vendor.csafProviderUrl
      ? 'The vendor’s advisory feed yielded no advisories in this dataset.'
      : 'No machine-readable advisory feed (CSAF) is known for the vendor.'
    return {
      timings: [],
      metrics: TIMELINESS_METRICS.map((metricId) => absentMetric({ metricId, gap: 'NO_SOURCE', reason, query: advQuery, tally: new ConfidenceTally() })),
    }
  }
  if (ctx.cveSourceFailed) {
    const reason = 'The CVE record source could not be read and no earlier snapshot exists, so whether the listed CVEs exist cannot be determined.'
    return {
      timings: [],
      metrics: TIMELINESS_METRICS.map((metricId) => absentMetric({ metricId, gap: 'SOURCE_FAILED', reason, query: advQuery, tally: new ConfidenceTally() })),
    }
  }

  const highImpact = advisories.filter((a) => sev.includes(a.severity) && withinDaysBefore(a.publishedAt, ctx.asOfMs, params.cveWindowDays))
  const all = highImpact.map((a) => timeAdvisory(a, ctx.cvesById, tol, { asOfMs: ctx.asOfMs, duplicateIds: ctx.duplicateIds }))
  // Undetermined advisories are set aside: outside every denominator, listed in the breakdown.
  const timings = all.filter((t) => t.outcome !== 'CVE_UNDETERMINED')
  const undetermined = all.filter((t) => t.outcome === 'CVE_UNDETERMINED')

  const ids = { withCve: [] as string[], timely: [] as string[], latency: [] as string[] }
  const freshness = new Map<string, ReturnType<typeof resolveSource>['freshness']>()
  for (const t of all) {
    const a = t.advisory
    const src = resolveSource(ctx, a.snapshotId, 'VENDOR_ADVISORY')
    if (src.freshness) freshness.set(src.freshness.sourceId, src.freshness)
    const common = {
      vendorId,
      sourceId: src.sourceId,
      snapshotId: a.snapshotId,
      subject: a.id,
      collectedAt: src.collectedAt,
      confidence: 'HIGH' as const,
      methodologyVersion: version,
    }
    const extracted = {
      advisoryUrl: a.url,
      severity: a.severity,
      advisoryPublishedAt: a.publishedAt,
      listedCves: [...new Set(a.cveIds)].sort(),
      foundCves: t.found.map((r) => r.id).sort(),
      missingCves: t.missing,
      publishedAfterAsOfCves: t.publishedAfterAsOf,
      undeterminedCves: t.undetermined,
      latestCvePublishedAt: t.found.length ? t.found.map((r) => r.datePublished!).sort().at(-1)! : null,
      latencyDays: t.latencyDays,
      toleranceDays: tol,
    }
    if (t.outcome === 'CVE_UNDETERMINED') {
      const reading = `Listed CVE(s) ${t.undetermined.join(', ')} exist more than once in the snapshot with conflicting content; the advisory is set aside (outcome undetermined) and is outside the denominator.`
      ids.withCve.push(ctx.ledger.add({ ...common, metricId: 'cve.high_impact_with_cve', extracted, interpretation: 'EXCLUDED', reading }))
      ids.timely.push(ctx.ledger.add({ ...common, metricId: 'cve.timely_issuance', extracted: { ...extracted, outcome: t.outcome }, interpretation: 'EXCLUDED', reading }))
      continue
    }
    const notCredited = [
      t.missing.length ? `${t.missing.join(', ')} not present as a published record in the snapshot` : '',
      t.publishedAfterAsOf.length ? `${t.publishedAfterAsOf.join(', ')} published after the analysis date` : '',
    ]
      .filter(Boolean)
      .join('; ')
    ids.withCve.push(
      ctx.ledger.add({
        ...common,
        metricId: 'cve.high_impact_with_cve',
        extracted,
        interpretation: t.found.length > 0 ? 'SUPPORTS' : 'DOES_NOT_SUPPORT',
        reading:
          t.found.length > 0
            ? `${a.severity} advisory lists ${t.found.map((r) => r.id).join(', ')}, present in the snapshot.`
            : t.outcome === 'NO_CVE_LISTED'
              ? `${a.severity} advisory lists no CVE id.`
              : `${a.severity} advisory lists ${notCredited}.`,
      }),
    )
    const lat = fmt(t.latencyDays ?? 0)
    const timelyReading: Record<Exclude<AdvisoryOutcome, 'CVE_UNDETERMINED'>, string> = {
      TIMELY: `Latest listed CVE published ${lat} day(s) after the advisory, within the ${tol}-day methodology tolerance (a TOUCHSTONE parameter, not a CISA threshold).`,
      LATE: `Latest listed CVE published ${lat} day(s) after the advisory, beyond the ${tol}-day methodology tolerance (a TOUCHSTONE parameter, not a CISA threshold).`,
      NO_CVE_LISTED: 'Advisory lists no CVE id, so no timely CVE issuance is observed.',
      CVE_NOT_IN_SNAPSHOT: `Listed CVE(s): ${notCredited}; not counted as timely.`,
      CVE_PUBLISHED_AFTER_AS_OF: `Listed CVE(s): ${notCredited}; no CVE existed at the analysis date, so not counted as timely.`,
    }
    ids.timely.push(
      ctx.ledger.add({
        ...common,
        metricId: 'cve.timely_issuance',
        extracted: { ...extracted, outcome: t.outcome },
        interpretation: t.outcome === 'TIMELY' ? 'SUPPORTS' : 'DOES_NOT_SUPPORT',
        reading: timelyReading[t.outcome],
      }),
    )
    if (t.latencyDays !== null) {
      ids.latency.push(
        ctx.ledger.add({
          ...common,
          metricId: 'cve.publication_latency',
          extracted,
          interpretation: 'CONTEXT',
          reading:
            (t.latencyMs ?? 0) < 0
              ? `CVE record public ${fmt(-t.latencyDays)} day(s) before the advisory.`
              : `CVE record published ${lat} day(s) after the advisory.`,
        }),
      )
    }
  }

  const n = timings.length
  const tally = (count: number): ConfidenceTally => {
    const t = new ConfidenceTally()
    t.freshness([...freshness.values()])
    if (count > 0 && count < minAdv)
      t.fire('C2.SAMPLE', `${count} high-impact advisories, fewer than the methodology minimum of ${minAdv}; shown, but cannot make the goal VERIFIED.`)
    return t
  }
  const outcomes: Record<string, number> = { TIMELY: 0, LATE: 0, NO_CVE_LISTED: 0, CVE_NOT_IN_SNAPSHOT: 0, CVE_PUBLISHED_AFTER_AS_OF: 0 }
  for (const t of timings) outcomes[t.outcome] = (outcomes[t.outcome] ?? 0) + 1
  const common = { undetermined_set_aside: undetermined.length, duplicate_advisories_collapsed: duplicates }

  const metrics: MetricValue[] = []
  metrics.push(
    ratioMetric({
      metricId: 'cve.high_impact_with_cve',
      numerator: timings.filter((t) => t.found.length > 0).length,
      denominator: n,
      minimum: 0,
      noun: 'high-impact advisories',
      evidenceIds: ids.withCve,
      query: `${advQuery} -> cveIds[] EXISTS IN cve_records (state PUBLISHED, datePublished <= asOf)`,
      tally: tally(n),
      breakdown: { no_cve_listed: outcomes['NO_CVE_LISTED']!, advisories_total: advisories.length, ...common },
    }),
  )
  metrics.push(
    ratioMetric({
      metricId: 'cve.timely_issuance',
      numerator: outcomes['TIMELY']!,
      denominator: n,
      minimum: 0,
      noun: 'high-impact advisories',
      evidenceIds: ids.timely,
      query: `${advQuery} -> max(cve.datePublished) - advisory.publishedAt <= ${tol} days, compared in milliseconds (methodology parameter timelinessToleranceDays)`,
      tally: tally(n),
      breakdown: {
        timely: outcomes['TIMELY']!,
        late: outcomes['LATE']!,
        no_cve_listed: outcomes['NO_CVE_LISTED']!,
        cve_not_in_snapshot: outcomes['CVE_NOT_IN_SNAPSHOT']!,
        cve_published_after_as_of: outcomes['CVE_PUBLISHED_AFTER_AS_OF']!,
        tolerance_days: tol,
        minimum_high_impact_advisories: minAdv,
        ...common,
      },
    }),
  )
  const latMs = timings.flatMap((t) => (t.latencyMs === null ? [] : [t.latencyMs]))
  const lat = latMs.map((ms) => daysBetween(0, ms))
  const latQuery = `${advQuery} -> max(cve.datePublished) - advisory.publishedAt, in days (sign kept)`
  if (lat.length === 0) {
    metrics.push(
      absentMetric({
        metricId: 'cve.publication_latency',
        gap: 'NO_ELIGIBLE_RECORDS',
        reason: n === 0 ? 'No high-impact advisories in the window.' : 'No high-impact advisory lists a CVE present in the snapshot.',
        query: latQuery,
        tally: tally(0),
      }),
    )
  } else {
    const med = median(lat)!
    const p75 = percentileNearestRank(lat, 75)!
    const p95 = percentileNearestRank(lat, 95)!
    metrics.push({
      metricId: 'cve.publication_latency',
      value: med,
      denominator: lat.length,
      distribution: { median: med, p75, p95, n: lat.length },
      evidenceIds: sortedUnique(ids.latency),
      query: latQuery,
      calculation: `median of ${lat.length} advisory latencies = ${fmt(med)} days (p75 ${fmt(p75)}, p95 ${fmt(p95)}; negative = CVE public before the advisory)`,
      breakdown: { cve_before_advisory: latMs.filter((x) => x < 0).length, within_tolerance: latMs.filter((x) => x <= tol * DAY_MS).length },
      ...tally(lat.length).result(),
    })
  }
  return { metrics, timings: all }
}

/**
 * Goal 6, issuance timeliness, from the vendor's own high-impact advisories.
 *
 * Without a machine-readable advisory feed there is nothing to measure
 * against: the metrics are null with gap NO_SOURCE, never zero. The
 * tolerance (timelinessToleranceDays) is a TOUCHSTONE methodology parameter,
 * not a CISA threshold, and every reading says so.
 */

import type { Advisory, CveRecord, MetricValue } from '../model/index.ts'
import { ConfidenceTally, resolveSource } from './context.ts'
import type { MeasureContext } from './context.ts'
import { absentMetric, ratioMetric, sortedUnique } from './metric.ts'
import { daysBetween, fmt, isoDaysBefore, median, percentileNearestRank, toMs, withinDaysBefore } from './stats.ts'

export type AdvisoryTiming = {
  advisory: Advisory
  /** CVE ids listed by the advisory that exist as PUBLISHED records with a datePublished. */
  found: CveRecord[]
  /** Listed CVE ids absent from the snapshot (or without a datePublished). */
  missing: string[]
  /** Latest found CVE datePublished minus advisory release, in days; null when nothing was found. */
  latencyDays: number | null
  outcome: 'TIMELY' | 'LATE' | 'NO_CVE_LISTED' | 'CVE_NOT_IN_SNAPSHOT'
}

export function timeAdvisory(a: Advisory, cvesById: Map<string, CveRecord>, toleranceDays: number): AdvisoryTiming {
  const listed = [...new Set(a.cveIds)].sort()
  const found: CveRecord[] = []
  const missing: string[] = []
  for (const id of listed) {
    const r = cvesById.get(id)
    if (r && r.state === 'PUBLISHED' && toMs(r.datePublished) !== null) found.push(r)
    else missing.push(id)
  }
  const advMs = toMs(a.publishedAt)
  let latencyDays: number | null = null
  if (advMs !== null && found.length > 0) {
    const latest = Math.max(...found.map((r) => toMs(r.datePublished)!))
    latencyDays = daysBetween(advMs, latest)
  }
  let outcome: AdvisoryTiming['outcome']
  if (listed.length === 0) outcome = 'NO_CVE_LISTED'
  else if (missing.length > 0 || latencyDays === null) outcome = 'CVE_NOT_IN_SNAPSHOT'
  else outcome = latencyDays <= toleranceDays ? 'TIMELY' : 'LATE'
  return { advisory: a, found, missing, latencyDays, outcome }
}

export type TimelinessResult = { metrics: MetricValue[]; timings: AdvisoryTiming[] }

export function measureTimeliness(ctx: MeasureContext): TimelinessResult {
  const params = ctx.methodology.parameters
  const version = ctx.methodology.version
  const vendorId = ctx.vendor.id
  const tol = params.timelinessToleranceDays
  const sev = params.highImpactSeverities
  const windowStart = isoDaysBefore(ctx.asOf, params.cveWindowDays)
  const advQuery = `advisories WHERE vendorId = '${vendorId}' AND severity IN (${sev.join(', ')}) AND publishedAt IN (${windowStart}, ${ctx.asOf}]`

  if (ctx.advisories.length === 0) {
    const reason = ctx.vendor.csafProviderUrl
      ? 'The vendor’s advisory feed yielded no advisories in this dataset.'
      : 'No machine-readable advisory feed (CSAF) is known for the vendor.'
    return {
      timings: [],
      metrics: ['cve.high_impact_with_cve', 'cve.timely_issuance', 'cve.publication_latency'].map((metricId) =>
        absentMetric({ metricId, gap: 'NO_SOURCE', reason, query: advQuery, tally: new ConfidenceTally() }),
      ),
    }
  }

  const highImpact = ctx.advisories
    .filter((a) => sev.includes(a.severity) && withinDaysBefore(a.publishedAt, ctx.asOfMs, params.cveWindowDays))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  const timings = highImpact.map((a) => timeAdvisory(a, ctx.cvesById, tol))

  const ids = { withCve: [] as string[], timely: [] as string[], latency: [] as string[] }
  const freshness = new Map<string, ReturnType<typeof resolveSource>['freshness']>()
  for (const t of timings) {
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
      latestCvePublishedAt: t.found.length ? t.found.map((r) => r.datePublished!).sort().at(-1)! : null,
      latencyDays: t.latencyDays,
      toleranceDays: tol,
    }
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
              : `${a.severity} advisory lists ${t.missing.join(', ')}, not present as a published record in the snapshot.`,
      }),
    )
    const timelyReading: Record<AdvisoryTiming['outcome'], string> = {
      TIMELY: `Latest listed CVE published ${fmt(t.latencyDays ?? 0)} day(s) after the advisory, within the ${tol}-day methodology tolerance (a TOUCHSTONE parameter, not a CISA threshold).`,
      LATE: `Latest listed CVE published ${fmt(t.latencyDays ?? 0)} day(s) after the advisory, beyond the ${tol}-day methodology tolerance (a TOUCHSTONE parameter, not a CISA threshold).`,
      NO_CVE_LISTED: 'Advisory lists no CVE id, so no timely CVE issuance is observed.',
      CVE_NOT_IN_SNAPSHOT: `Listed CVE(s) ${t.missing.join(', ')} not present as published records in the snapshot; not counted as timely.`,
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
            t.latencyDays < 0
              ? `CVE record public ${fmt(-t.latencyDays)} day(s) before the advisory.`
              : `CVE record published ${fmt(t.latencyDays)} day(s) after the advisory.`,
        }),
      )
    }
  }

  const n = timings.length
  const tally = (count: number): ConfidenceTally => {
    const t = new ConfidenceTally()
    t.freshness([...freshness.values()])
    if (count > 0 && count < params.minimumEligibleRecords)
      t.fire('C2.SAMPLE', `${count} advisories, fewer than the methodology minimum of ${params.minimumEligibleRecords}.`)
    return t
  }
  const outcomes: Record<string, number> = { TIMELY: 0, LATE: 0, NO_CVE_LISTED: 0, CVE_NOT_IN_SNAPSHOT: 0 }
  for (const t of timings) outcomes[t.outcome]!++

  const metrics: MetricValue[] = []
  metrics.push(
    ratioMetric({
      metricId: 'cve.high_impact_with_cve',
      numerator: timings.filter((t) => t.found.length > 0).length,
      denominator: n,
      minimum: 0,
      noun: 'high-impact advisories',
      evidenceIds: ids.withCve,
      query: `${advQuery} -> cveIds[] EXISTS IN cve_records (state PUBLISHED)`,
      tally: tally(n),
      breakdown: { no_cve_listed: outcomes['NO_CVE_LISTED']!, advisories_total: ctx.advisories.length },
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
      query: `${advQuery} -> max(cve.datePublished) - advisory.publishedAt <= ${tol} days (methodology parameter timelinessToleranceDays)`,
      tally: tally(n),
      breakdown: {
        timely: outcomes['TIMELY']!,
        late: outcomes['LATE']!,
        no_cve_listed: outcomes['NO_CVE_LISTED']!,
        cve_not_in_snapshot: outcomes['CVE_NOT_IN_SNAPSHOT']!,
        tolerance_days: tol,
      },
    }),
  )
  const lat = timings.flatMap((t) => (t.latencyDays === null ? [] : [t.latencyDays]))
  const latQuery = `${advQuery} -> max(cve.datePublished) - advisory.publishedAt, in days (sign kept)`
  if (lat.length === 0) {
    const tl = tally(0)
    metrics.push(
      absentMetric({
        metricId: 'cve.publication_latency',
        gap: 'NO_ELIGIBLE_RECORDS',
        reason: n === 0 ? 'No high-impact advisories in the window.' : 'No high-impact advisory lists a CVE present in the snapshot.',
        query: latQuery,
        tally: tl,
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
      breakdown: { cve_before_advisory: lat.filter((x) => x < 0).length, within_tolerance: lat.filter((x) => x <= tol).length },
      ...tally(lat.length).result(),
    })
  }
  return { metrics, timings }
}

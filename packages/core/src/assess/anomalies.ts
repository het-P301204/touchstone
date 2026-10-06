/**
 * Anomalies: observed deviations, stated with the rule and threshold that
 * fired. They are prompts for review, never judgements about a vendor.
 *
 *   UNUSUAL          a higher-is-stronger metric is strictly below the cohort's
 *                    unusualBelowPercentile (nearest-rank) across ALL_SIGNATORIES,
 *                    evaluated only with at least MIN_PEERS_FOR_PERCENTILE values
 *   LATENCY_OUTLIER  current median latency > historical median × latencyOutlierFactor
 *                    AND exceeds it by at least latencyOutlierMinDays (historical median
 *                    floored at 1 day for the factor test)
 *   DATA_QUALITY     exclusions, duplicate conflicts, identity conflicts, carried-forward
 *                    or unreadable sources affecting the vendor
 *   CHANGE_DETECTED  the VDP text or a criterion state changed since the previous dataset
 */

import type {
  Anomaly,
  AttributionExclusion,
  HistoricalPoint,
  IdentityConflict,
  MethodologyParameters,
  MetricValue,
  SourceFreshness,
  VdpChange,
  VdpObservation,
  Vendor,
} from '../model/index.ts'
import { BENCHMARK_METRIC_IDS, MIN_PEERS_FOR_PERCENTILE, VDP_CRITERION_LABELS, metricDefinition } from '../measure/definitions.ts'
import { fmt, percentileNearestRank, round2 } from '../measure/stats.ts'
import { sha256Text } from '../util/sha256.ts'
import { canonicalJson } from '../run/canonical.ts'
import type { CohortRow } from './cohort.ts'
import { historicalMedian, signatoryRows } from './cohort.ts'

function withId(a: Omit<Anomaly, 'id'>): Anomaly {
  return { id: `AN-${sha256Text(canonicalJson(a)).slice(0, 10)}`, ...a }
}

export type AnomalyInputs = {
  vendor: Vendor
  metrics: Map<string, MetricValue>
  rows: CohortRow[]
  history: HistoricalPoint[]
  params: MethodologyParameters
  asOf: string
  methodologyVersion: string
  exclusions: AttributionExclusion[]
  identityConflicts: IdentityConflict[]
  vdp?: VdpObservation
  vdpChanges: VdpChange[]
  /** Freshness of sources the vendor's evidence was read from. */
  vendorSourceFreshness: SourceFreshness[]
  /** Number of VDP observations supplied for the vendor (more than one is a data quality note). */
  vdpObservationCount?: number
}

export function detectAnomalies(inp: AnomalyInputs): Anomaly[] {
  const out: Anomaly[] = []
  const vendorId = inp.vendor.id
  const p = inp.params

  // UNUSUAL
  for (const metricId of BENCHMARK_METRIC_IDS) {
    const def = metricDefinition(metricId)!
    if (def.direction !== 'HIGHER_IS_STRONGER_EVIDENCE') continue
    const m = inp.metrics.get(metricId)
    if (!m || m.value === null) continue
    const vals = signatoryRows(inp.rows).flatMap((r) => {
      const v = r.metrics.get(metricId)?.value
      return v === null || v === undefined ? [] : [v]
    })
    if (vals.length < MIN_PEERS_FOR_PERCENTILE) continue
    const threshold = percentileNearestRank(vals, p.unusualBelowPercentile)!
    if (m.value < threshold) {
      out.push(
        withId({
          vendorId,
          kind: 'UNUSUAL',
          metricId,
          headline: `Observed deviation: ${def.name} is below the cohort's ${p.unusualBelowPercentile}th percentile.`,
          detail: `${fmt(m.value)}% against a ${p.unusualBelowPercentile}th-percentile value of ${fmt(threshold)}% across ${vals.length} vendors with a value. This is a position on an observable metric, not an assessment of the vendor.`,
          rule: `UNUSUAL: value < nearest-rank P${p.unusualBelowPercentile} of ALL_SIGNATORIES values (methodology unusualBelowPercentile = ${p.unusualBelowPercentile}; evaluated with >= ${MIN_PEERS_FOR_PERCENTILE} vendors).`,
          evidenceIds: m.evidenceIds.slice(0, 50),
        }),
      )
    }
  }

  // LATENCY_OUTLIER
  const lat = inp.metrics.get('cve.publication_latency')
  if (lat && lat.value !== null) {
    const hist = historicalMedian(inp.history, vendorId, 'cve.publication_latency', inp.asOf, inp.methodologyVersion)
    if (hist !== null) {
      const base = Math.max(hist, 1)
      if (lat.value > base * p.latencyOutlierFactor && lat.value - hist >= p.latencyOutlierMinDays) {
        out.push(
          withId({
            vendorId,
            kind: 'LATENCY_OUTLIER',
            metricId: 'cve.publication_latency',
            headline: 'Observed deviation: median CVE publication latency is well above the vendor’s own historical median.',
            detail: `Current median ${fmt(lat.value)} days against a historical median of ${fmt(hist)} days (+${fmt(round2(lat.value - hist))} days).`,
            rule: `LATENCY_OUTLIER: current > max(historical, 1 day) × ${p.latencyOutlierFactor} AND current − historical >= ${p.latencyOutlierMinDays} days (methodology latencyOutlierFactor, latencyOutlierMinDays).`,
            evidenceIds: lat.evidenceIds.slice(0, 50),
          }),
        )
      }
    }
  }

  // DATA_QUALITY
  const byReason = new Map<string, string[]>()
  for (const x of inp.exclusions) byReason.set(x.reason, [...(byReason.get(x.reason) ?? []), x.cveId])
  const excludedMetric = inp.metrics.get('cve.excluded_records')
  for (const [reason, ids] of [...byReason.entries()].sort()) {
    const uniq = [...new Set(ids)].sort()
    out.push(
      withId({
        vendorId,
        kind: 'DATA_QUALITY',
        metricId: reason === 'DUPLICATE_CONFLICT' ? 'cve.duplicate_conflicts' : 'cve.excluded_records',
        headline: `Data quality: ${uniq.length} record(s) naming this vendor were excluded (${reason}).`,
        detail: `Excluded from every metric: ${uniq.slice(0, 20).join(', ')}${uniq.length > 20 ? ', …' : ''}.`,
        rule: `Attribution exclusion rule ${reason}.`,
        evidenceIds: (excludedMetric?.evidenceIds ?? []).slice(0, 50),
      }),
    )
  }
  for (const c of inp.identityConflicts.filter((c) => c.vendorIds.includes(vendorId))) {
    out.push(
      withId({
        vendorId,
        kind: 'DATA_QUALITY',
        headline: `Data quality: identity conflict on ${c.aliasKind} "${c.value}" shared with ${c.vendorIds.filter((v) => v !== vendorId).join(', ')}.`,
        detail: `${c.note} ${new Set([...c.affectedRecordIds, ...inp.exclusions.filter((x) => x.reason === 'IDENTITY_CONFLICT').map((x) => x.cveId)]).size} record(s) naming this vendor are excluded until the registry resolves it.`,
        rule: `Identity conflict ${c.kind} (${c.id}).`,
        evidenceIds: [],
      }),
    )
  }
  if ((inp.vdpObservationCount ?? 0) > 1) {
    out.push(
      withId({
        vendorId,
        kind: 'DATA_QUALITY',
        metricId: 'vdp.criteria_met',
        headline: `Data quality: ${inp.vdpObservationCount} VDP observations were supplied for this vendor; one was used.`,
        detail: `The observation with the latest observedAt (then the lowest snapshot id) is used${inp.vdp ? `: observed ${inp.vdp.observedAt}` : ''}. The others are set aside.`,
        rule: 'One VDP observation per vendor; deterministic choice by observedAt, then snapshot id.',
        evidenceIds: [],
      }),
    )
  }
  if (inp.vdp?.carriedFromSnapshotId) {
    out.push(
      withId({
        vendorId,
        kind: 'DATA_QUALITY',
        metricId: 'vdp.criteria_met',
        headline: 'Data quality: the VDP observation is carried forward from an earlier snapshot.',
        detail: `The latest refresh did not succeed; figures use snapshot ${inp.vdp.carriedFromSnapshotId}.`,
        rule: 'Carried-forward observation (confidence rule C4.CARRIED).',
        evidenceIds: inp.metrics.get('vdp.criteria_met')?.evidenceIds ?? [],
      }),
    )
  }
  for (const f of inp.vendorSourceFreshness) {
    if (f.state !== 'STALE' && f.state !== 'UNKNOWN') continue
    out.push(
      withId({
        vendorId,
        kind: 'DATA_QUALITY',
        headline: `Data quality: source ${f.sourceId} is ${f.state}.`,
        detail:
          f.lastStatus && f.lastStatus !== 'OK'
            ? `The latest refresh attempt (${f.lastAttemptAt ?? 'unknown time'}) did not succeed; ${f.usedSnapshotId ? `figures use snapshot ${f.usedSnapshotId}, ${fmt(f.ageHours ?? 0)} hours old at the analysis date` : 'no earlier snapshot exists'}.`
            : f.ageHours !== undefined
              ? `Snapshot used is ${fmt(f.ageHours)} hours old at the analysis date.`
              : 'No successful snapshot.',
        rule: `Freshness bands for ${f.family} (methodology freshnessHours).`,
        evidenceIds: [],
      }),
    )
  }

  // CHANGE_DETECTED
  for (const ch of inp.vdpChanges) {
    const parts = ch.criteria.map((c) => `${VDP_CRITERION_LABELS[c.criterion as keyof typeof VDP_CRITERION_LABELS] ?? c.criterion}: ${c.before} → ${c.after}`)
    out.push(
      withId({
        vendorId,
        kind: 'CHANGE_DETECTED',
        metricId: 'vdp.criteria_met',
        headline: `Observed change in the VDP since ${ch.fromObservedAt.slice(0, 10)}${ch.reviewRecommended ? ': review recommended' : ''}.`,
        detail: `${ch.textChanged ? 'Policy text changed. ' : ''}${parts.length ? `Criteria: ${parts.join('; ')}.` : 'No criterion changed state.'}`,
        rule: 'VDP change detection: text hash or criterion state differs from the previous dataset; review recommended when a pledge criterion changed.',
        evidenceIds: inp.metrics.get('vdp.criteria_met')?.evidenceIds ?? [],
      }),
    )
  }
  return out.sort((a, b) => (a.kind + a.id < b.kind + b.id ? -1 : 1))
}

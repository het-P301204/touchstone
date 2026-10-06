/**
 * Evidence coverage over the 14 slots (definitions.ts COVERAGE_SLOTS): the
 * 8 VDP criteria plus six CVE/G3 measurements. A slot is observed when it
 * has an evidence-backed determination: a VDP criterion MET, NOT_MET,
 * PARTIAL or CONTRADICTED, or a numeric value with a denominator above 0.
 * Coverage says how much could be looked at, not how good the result was.
 */

import type { EvidenceCoverage, EvidenceItem, MetricValue, VdpObservation } from '../model/index.ts'
import { UNVERIFIABLE_GOAL_IDS } from '../methodology/goals.ts'
import { COVERAGE_SLOTS, VDP_CRITERIA, vdpSlotId } from '../measure/definitions.ts'
import { criteriaStates, DETERMINED } from '../measure/vdp.ts'
import { round1 } from '../measure/stats.ts'

const GAP_TEXT: Record<string, string> = {
  NO_SOURCE: 'no source available',
  SOURCE_FAILED: 'source could not be retrieved',
  NO_ELIGIBLE_RECORDS: 'no eligible records',
  BELOW_MINIMUM_SAMPLE: 'below the minimum sample',
  NOT_APPLICABLE: 'not applicable under the methodology',
  NOT_PROVIDED: 'field not provided',
}

export function computeCoverage(metrics: Map<string, MetricValue>, vdp: VdpObservation | undefined, evidence: EvidenceItem[]): EvidenceCoverage {
  const unobserved: { metricId: string; reason: string }[] = []
  let observed = 0
  const states = vdp ? criteriaStates(vdp) : undefined
  for (const c of VDP_CRITERIA) {
    const slot = vdpSlotId(c)
    const s = states?.get(c)
    if (s && DETERMINED.includes(s.state)) observed++
    else unobserved.push({ metricId: slot, reason: !vdp ? 'No VDP observation for the vendor.' : `UNKNOWN${s?.note ? `: ${s.note}` : ''}` })
  }
  for (const slot of COVERAGE_SLOTS.slice(VDP_CRITERIA.length)) {
    const m = metrics.get(slot)
    const ok = !!m && m.value !== null && (m.denominator ?? m.distribution?.n ?? 0) > 0
    if (ok) observed++
    else unobserved.push({ metricId: slot, reason: m?.gap ? (GAP_TEXT[m.gap] ?? m.gap) : 'not measured' })
  }
  const total = COVERAGE_SLOTS.length
  const measurements = [...metrics.values()].filter((m) => m.value !== null && m.evidenceIds.length > 0).length
  return {
    percent: round1((observed / total) * 100),
    observedSlots: observed,
    totalSlots: total,
    sourcesEvaluated: new Set(evidence.map((e) => e.sourceId)).size,
    evidenceBackedMeasurements: measurements,
    unverifiableGoals: UNVERIFIABLE_GOAL_IDS.length,
    unobserved,
  }
}

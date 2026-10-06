/**
 * Goal 5, VDP figures from a VdpObservation (produced by the pipeline's
 * assessVdp). One evidence item per criterion, quoting the sentence(s) that
 * support the determination. UNKNOWN counts 0 and is listed; it never
 * counts as MET.
 */

import type { CriterionResult, CriterionState, MetricValue, VdpCriterionId, VdpObservation } from '../model/index.ts'
import { ConfidenceTally, resolveSource } from './context.ts'
import type { MeasureContext } from './context.ts'
import { PLEDGE_VDP_CRITERIA, VDP_CRITERIA, VDP_CRITERION_LABELS } from './definitions.ts'
import { absentMetric, sortedUnique } from './metric.ts'
import { fmt, round2 } from './stats.ts'

/** The observation's result for each of the 8 criteria; a criterion the observation omits is UNKNOWN. */
export function criteriaStates(obs: VdpObservation): Map<VdpCriterionId, CriterionResult> {
  const m = new Map<VdpCriterionId, CriterionResult>()
  for (const c of VDP_CRITERIA) {
    const found = obs.criteria.find((x) => x.criterion === c)
    m.set(c, found ?? { criterion: c, state: 'UNKNOWN', ruleId: 'VDP.NOT_ASSESSED', quotes: [], note: 'Criterion absent from the observation.' })
  }
  return m
}

export const DETERMINED: CriterionState[] = ['MET', 'NOT_MET', 'PARTIAL', 'CONTRADICTED']

/** Credit for one criterion state: MET 1, PARTIAL 0.5, everything else 0. */
export function criterionCredit(s: CriterionState): number {
  return s === 'MET' ? 1 : s === 'PARTIAL' ? 0.5 : 0
}

/**
 * The policy fetch did not succeed and no earlier snapshot was carried: every
 * pledge criterion is UNKNOWN and the observation is not a carried copy.
 */
export function vdpRetrievalFailed(obs: VdpObservation): boolean {
  if (obs.carriedFromSnapshotId) return false
  // Per the pipeline contract (assessVdp), pledge criteria are UNKNOWN only
  // when the policy could not be read; a policy that does not exist yields NOT_MET.
  const states = criteriaStates(obs)
  return PLEDGE_VDP_CRITERIA.every((c) => states.get(c)!.state === 'UNKNOWN')
}

export type VdpResult = { metrics: MetricValue[]; criterionEvidence: Map<VdpCriterionId, string> }

export function measureVdp(ctx: MeasureContext): VdpResult {
  const vendorId = ctx.vendor.id
  const version = ctx.methodology.version
  const obs = ctx.vdp
  const query = `vdp_observations WHERE vendorId = '${vendorId}' -> criteria[8].state`
  const criterionEvidence = new Map<VdpCriterionId, string>()
  if (!obs) {
    return {
      criterionEvidence,
      metrics: ['vdp.criteria_met', 'vdp.pledge_elements_met'].map((metricId) =>
        absentMetric({ metricId, gap: 'NO_SOURCE', reason: 'No VDP observation for the vendor in this dataset.', query, tally: new ConfidenceTally() }),
      ),
    }
  }
  const states = criteriaStates(obs)
  const snapshotId = obs.policy.snapshotId ?? obs.securityTxt.snapshotId ?? obs.carriedFromSnapshotId ?? 'unknown'
  const src = resolveSource(ctx, snapshotId, obs.policy.snapshotId ? 'VENDOR_VDP' : 'SECURITY_TXT')
  const txtSrc = obs.securityTxt.snapshotId ? resolveSource(ctx, obs.securityTxt.snapshotId, 'SECURITY_TXT') : undefined
  const carried = !!obs.carriedFromSnapshotId
  const subject = obs.policy.url ?? obs.securityTxt.url ?? `vdp:${vendorId}`

  for (const c of VDP_CRITERIA) {
    const r = states.get(c)!
    const determined = DETERMINED.includes(r.state)
    const prohib = obs.prohibitive.filter((p) => p.againstCriterion === c)
    const interpretation = r.state === 'MET' || r.state === 'PARTIAL' ? 'SUPPORTS' : r.state === 'UNKNOWN' ? 'CONTEXT' : 'DOES_NOT_SUPPORT'
    const label = VDP_CRITERION_LABELS[c]
    const reading =
      r.state === 'MET'
        ? `${label}: MET${r.quotes[0] ? ` — "${r.quotes[0]}"` : ''}`
        : r.state === 'PARTIAL'
          ? `${label}: PARTIAL${r.quotes[0] ? ` — "${r.quotes[0]}"` : ''}`
          : r.state === 'CONTRADICTED'
            ? `${label}: CONTRADICTED by prohibitive language (observed deviation)${prohib[0] ? ` — "${prohib[0].quote}"` : r.quotes[0] ? ` — "${r.quotes[0]}"` : ''}`
            : r.state === 'NOT_MET'
              ? `${label}: NOT_MET — not found in the policy text read.`
              : `${label}: UNKNOWN — could not be determined${r.note ? ` (${r.note})` : ''}; counted as 0.`
    const id = ctx.ledger.add({
      vendorId,
      metricId: 'vdp.criteria_met',
      sourceId: src.sourceId,
      snapshotId,
      subject,
      collectedAt: src.collectedAt,
      extracted: {
        criterion: c,
        state: r.state,
        ruleId: r.ruleId,
        quotes: r.quotes,
        prohibitiveRuleIds: prohib.map((p) => p.ruleId),
        carriedFromSnapshotId: obs.carriedFromSnapshotId ?? null,
        policyTextHash: obs.policy.textHash ?? null,
      },
      interpretation,
      reading,
      confidence: !determined ? 'LOW' : carried ? 'MEDIUM' : 'HIGH',
      methodologyVersion: version,
    })
    criterionEvidence.set(c, id)
  }

  const tally = (): ConfidenceTally => {
    const t = new ConfidenceTally()
    if (carried) t.fire('C4.CARRIED', `VDP observation carried forward from snapshot ${obs.carriedFromSnapshotId}.`)
    t.freshness([src.freshness, txtSrc?.freshness])
    return t
  }
  const counts: Record<CriterionState, number> = { MET: 0, PARTIAL: 0, NOT_MET: 0, CONTRADICTED: 0, UNKNOWN: 0 }
  for (const c of VDP_CRITERIA) counts[states.get(c)!.state]++
  const unknown = VDP_CRITERIA.filter((c) => states.get(c)!.state === 'UNKNOWN')
  const metrics: MetricValue[] = []
  const failed = vdpRetrievalFailed(obs)

  if (unknown.length === VDP_CRITERIA.length) {
    metrics.push(
      absentMetric({
        metricId: 'vdp.criteria_met',
        gap: failed ? 'SOURCE_FAILED' : 'NO_SOURCE',
        reason: 'No VDP criterion could be determined.',
        query,
        tally: tally(),
        breakdown: { ...counts },
      }),
    )
  } else {
    const t = tally()
    if (unknown.length > 0) t.fire('C5.UNDETERMINED', `${unknown.length} of 8 criteria UNKNOWN (${unknown.join(', ')}), counted as 0.`)
    const num = counts.MET + 0.5 * counts.PARTIAL
    const value = round2((num / VDP_CRITERIA.length) * 100)
    metrics.push({
      metricId: 'vdp.criteria_met',
      value,
      numerator: num,
      denominator: VDP_CRITERIA.length,
      evidenceIds: sortedUnique([...criterionEvidence.values()]),
      query,
      calculation: `(${counts.MET} MET + 0.5 × ${counts.PARTIAL} PARTIAL) / 8 = ${fmt(value)}%${unknown.length ? `; UNKNOWN (counted 0): ${unknown.join(', ')}` : ''}`,
      breakdown: { ...counts },
      ...t.result(),
    })
  }

  const pledgeUnknown = PLEDGE_VDP_CRITERIA.filter((c) => states.get(c)!.state === 'UNKNOWN')
  const pledgeIds = PLEDGE_VDP_CRITERIA.map((c) => criterionEvidence.get(c)!)
  if (pledgeUnknown.length === PLEDGE_VDP_CRITERIA.length) {
    metrics.push(
      absentMetric({
        metricId: 'vdp.pledge_elements_met',
        gap: failed ? 'SOURCE_FAILED' : 'NO_SOURCE',
        reason: 'None of the four pledge elements could be determined.',
        query,
        tally: tally(),
      }),
    )
  } else {
    const t = tally()
    if (pledgeUnknown.length > 0) t.fire('C5.UNDETERMINED', `${pledgeUnknown.length} of 4 pledge elements UNKNOWN (${pledgeUnknown.join(', ')}), not counted.`)
    const met = PLEDGE_VDP_CRITERIA.filter((c) => states.get(c)!.state === 'MET').length
    const b: Record<string, number> = {}
    for (const c of PLEDGE_VDP_CRITERIA) b[`state.${c}.${states.get(c)!.state}`] = 1
    metrics.push({
      metricId: 'vdp.pledge_elements_met',
      value: met,
      numerator: met,
      denominator: PLEDGE_VDP_CRITERIA.length,
      evidenceIds: sortedUnique(pledgeIds),
      query: `${query} WHERE criterion IN (${PLEDGE_VDP_CRITERIA.join(', ')}) AND state = 'MET'`,
      calculation: `${met} of 4 pledge elements MET${pledgeUnknown.length ? `; UNKNOWN: ${pledgeUnknown.join(', ')}` : ''}`,
      breakdown: b,
      ...t.result(),
    })
  }
  return { metrics, criterionEvidence }
}

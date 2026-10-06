/**
 * VDP change detection: compares the current observation with the previous
 * dataset's observation for the same vendor. Reports text and per-criterion
 * state changes; recommends review when a pledge-required criterion changed.
 * A change is an observation, not a judgement.
 *
 * A retrieval problem is not a change: no change is reported when the newer
 * observation could not read the policy (FETCH_FAILED / UNREADABLE), criteria
 * that are UNKNOWN on either side are skipped, and the text is compared only
 * when both observations carry a text hash.
 */

import type { VdpChange, VdpObservation } from '../model/index.ts'
import { PLEDGE_VDP_CRITERIA, VDP_CRITERIA } from '../measure/definitions.ts'
import { criteriaStates } from '../measure/vdp.ts'

function snapshotOf(o: VdpObservation): string {
  return o.policy.snapshotId ?? o.securityTxt.snapshotId ?? o.carriedFromSnapshotId ?? 'unknown'
}

export function detectVdpChange(previous: VdpObservation | undefined, current: VdpObservation | undefined): VdpChange[] {
  if (!previous || !current) return []
  const retrieval = (current.policy as { retrieval?: string }).retrieval
  if (retrieval === 'FETCH_FAILED' || retrieval === 'UNREADABLE') return []
  const before = criteriaStates(previous)
  const after = criteriaStates(current)
  const criteria: VdpChange['criteria'] = []
  for (const c of VDP_CRITERIA) {
    const b = before.get(c)!.state
    const a = after.get(c)!.state
    if (a === 'UNKNOWN' || b === 'UNKNOWN') continue
    if (a !== b) criteria.push({ criterion: c, before: b, after: a })
  }
  const textChanged = !!previous.policy.textHash && !!current.policy.textHash && previous.policy.textHash !== current.policy.textHash
  if (!textChanged && criteria.length === 0) return []
  return [
    {
      vendorId: current.vendorId,
      fromSnapshotId: snapshotOf(previous),
      toSnapshotId: snapshotOf(current),
      fromObservedAt: previous.observedAt,
      toObservedAt: current.observedAt,
      textChanged,
      criteria,
      reviewRecommended: criteria.some((x) => (PLEDGE_VDP_CRITERIA as string[]).includes(x.criterion)),
    },
  ]
}

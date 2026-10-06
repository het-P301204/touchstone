/**
 * Goal-level status, exactly per each goal's `methodology.statusRule`
 * (methodology/goals.ts), and the three dimension figures. Status reasons are
 * written in measurement language: what evidence was found, what was not,
 * what could not be determined.
 *
 * There is no composite score. Each DimensionFigure stands alone.
 */

import type { DimensionFigure, GoalAssessment, GoalStatus, MetricValue, VdpObservation, Vendor } from '../model/index.ts'
import { GOALS } from '../methodology/goals.ts'
import { METRIC_DEFINITIONS, PLEDGE_VDP_CRITERIA, VDP_CRITERION_LABELS } from '../measure/definitions.ts'
import { criteriaStates, vdpRetrievalFailed } from '../measure/vdp.ts'
import { fmt } from '../measure/stats.ts'

export type GoalInputs = {
  vendor: Vendor
  metrics: Map<string, MetricValue>
  vdp?: VdpObservation
  cveSourceFailed: boolean
  minimumEligibleRecords: number
  minimumRecordsPerTrendPeriod: number
}

const metricsForGoal = (goalId: string): string[] => METRIC_DEFINITIONS.filter((m) => m.goalId === goalId).map((m) => m.id)

function collect(goalId: string, metrics: Map<string, MetricValue>): MetricValue[] {
  return metricsForGoal(goalId).flatMap((id) => {
    const m = metrics.get(id)
    return m ? [m] : []
  })
}

function evidenceOf(ms: MetricValue[]): string[] {
  return [...new Set(ms.flatMap((m) => m.evidenceIds))].sort()
}

const label = (c: string): string => VDP_CRITERION_LABELS[c as keyof typeof VDP_CRITERION_LABELS] ?? c

export function assessG5(inp: GoalInputs): { status: GoalStatus; reason: string } {
  const obs = inp.vdp
  if (!obs) return { status: 'NOT_VERIFIED', reason: 'No vulnerability disclosure policy observation exists for this vendor in the dataset; no policy evidence was found.' }
  if (vdpRetrievalFailed(obs))
    return {
      status: 'DATA_ERROR',
      reason: 'The policy could not be retrieved and no earlier snapshot exists, so none of the four pledge elements could be determined.',
    }
  const states = criteriaStates(obs)
  const st = (c: string) => states.get(c as never)!.state
  const met = PLEDGE_VDP_CRITERIA.filter((c) => st(c) === 'MET')
  const contradicted = PLEDGE_VDP_CRITERIA.filter((c) => st(c) === 'CONTRADICTED')
  const notMet = PLEDGE_VDP_CRITERIA.filter((c) => st(c) === 'NOT_MET' || st(c) === 'PARTIAL')
  const unknown = PLEDGE_VDP_CRITERIA.filter((c) => st(c) === 'UNKNOWN')
  const carried = obs.carriedFromSnapshotId ? ` Observation carried forward from snapshot ${obs.carriedFromSnapshotId} after a refresh did not succeed.` : ''
  const detail = [
    contradicted.length ? `Prohibitive language observed against: ${contradicted.map(label).join(', ')} (observed deviation).` : '',
    notMet.length ? `Not found or only partly found: ${notMet.map(label).join(', ')}.` : '',
    unknown.length ? `Could not be determined: ${unknown.map(label).join(', ')}.` : '',
  ]
    .filter(Boolean)
    .join(' ')
  if (met.length === 4 && contradicted.length === 0)
    return { status: 'VERIFIED', reason: `Evidence supports all four pledge elements; each is quoted from the published policy.${carried}` }
  if (obs.policy.found && met.length >= 1)
    return { status: 'PARTIAL', reason: `Evidence supports ${met.length} of 4 pledge elements (${met.map(label).join(', ')}). ${detail}${carried}`.trim() }
  if (!obs.policy.found)
    return {
      status: 'NOT_VERIFIED',
      reason: `No vulnerability disclosure policy was found at the locations checked (security.txt Policy field, registry URL, vendor domain).${obs.securityTxt.present ? ' A security.txt file exists but is not counted as a policy.' : ''}${carried}`,
    }
  return { status: 'NOT_VERIFIED', reason: `A policy was found, but none of the four pledge elements is supported by it. ${detail}${carried}`.trim() }
}

export function assessG6(inp: GoalInputs): { status: GoalStatus; reason: string } {
  const complete = inp.metrics.get('cve.complete_records')
  const timely = inp.metrics.get('cve.timely_issuance')
  if (inp.cveSourceFailed)
    return { status: 'DATA_ERROR', reason: 'The CVE record source could not be retrieved and no earlier snapshot exists; record quality could not be measured.' }
  const q = complete?.value ?? null
  const t = timely?.value ?? null
  const qText =
    q === null
      ? `Record quality not measured (${complete?.gap ?? 'no data'}${complete?.denominator !== undefined ? `, ${complete.denominator} eligible records` : ''}).`
      : `${complete!.numerator} of ${complete!.denominator} eligible records (${fmt(q)}%) carry a usable CWE and an in-namespace CPE in the CNA container.`
  const tText =
    t === null
      ? `Issuance timeliness not measured: ${timely ? timely.calculation.replace(/ Not measured\.$/, '') : 'no data.'}`
      : `${timely!.numerator} of ${timely!.denominator} high-impact advisories (${fmt(t)}%) have every listed CVE published within the methodology tolerance.`
  if (q === 100 && t === 100) return { status: 'VERIFIED', reason: `Evidence supports both parts: ${qText} ${tText}` }
  if (q === null && t === null) {
    const few = complete?.gap === 'BELOW_MINIMUM_SAMPLE' || complete?.gap === 'NO_ELIGIBLE_RECORDS'
    return {
      status: 'NOT_VERIFIED',
      reason: `Evidence incomplete: ${few ? `fewer eligible records than the minimum sample of ${inp.minimumEligibleRecords}` : 'record quality not measurable'} and no high-impact advisories to measure timeliness. ${qText} ${tText}`,
    }
  }
  return { status: 'PARTIAL', reason: `Evidence supports part of the goal. ${qText} ${tText}` }
}

export function assessG3(inp: GoalInputs): { status: GoalStatus; reason: string } {
  const m = inp.metrics.get('g3.class_share_trend')
  const lim = 'This describes disclosed records only and cannot establish a reduction in prevalence.'
  if (inp.cveSourceFailed && (!m || m.value === null))
    return { status: 'DATA_ERROR', reason: 'The CVE record source could not be retrieved and no earlier snapshot exists.' }
  if (!m || m.value === null) {
    const b = m?.breakdown ?? {}
    return {
      status: 'NOT_VERIFIED',
      reason: `Evidence incomplete: records with a CNA-supplied CWE identifier were prior ${b['prior_records'] ?? 0} and latest ${b['latest_records'] ?? 0}; each 12-month period needs at least ${inp.minimumRecordsPerTrendPeriod}. ${lim}`,
    }
  }
  const b = m.breakdown ?? {}
  return {
    status: 'PARTIAL',
    reason: `Class-share signal measured: tracked classes were ${fmt(b['prior_share_pct'] ?? 0)}% of ${b['prior_records']} prior-period records and ${fmt(b['latest_share_pct'] ?? 0)}% of ${b['latest_records']} latest-period records (${m.value > 0 ? '+' : ''}${fmt(m.value)} points). ${lim}`,
  }
}

export function assessGoals(inp: GoalInputs): GoalAssessment[] {
  const out: GoalAssessment[] = []
  for (const g of GOALS) {
    const claimCount = inp.vendor.claims.filter((c) => c.goalId === g.id).length
    if (g.verificationMode === 'NOT_EXTERNALLY_VERIFIABLE') {
      out.push({
        vendorId: inp.vendor.id,
        goalId: g.id,
        status: 'NOT_EXTERNALLY_VERIFIABLE',
        statusReason: `Not externally verifiable: public sources cannot meaningfully answer this goal. This is a property of the goal, not a finding about the vendor.${claimCount ? ` ${claimCount} vendor statement(s) are shown as unverified claims.` : ''}`,
        metrics: [],
        evidenceIds: [],
        claimCount,
      })
      continue
    }
    const metrics = collect(g.id, inp.metrics)
    const r = g.id === 'G5' ? assessG5(inp) : g.id === 'G6' ? assessG6(inp) : assessG3(inp)
    out.push({
      vendorId: inp.vendor.id,
      goalId: g.id,
      status: r.status,
      statusReason: r.reason.replace(/\s+/g, ' ').trim(),
      metrics,
      evidenceIds: evidenceOf(metrics),
      claimCount,
    })
  }
  return out
}

/** The three dimension figures. Each stands alone; they are never combined. */
export function dimensionFigures(goals: GoalAssessment[], metrics: Map<string, MetricValue>): DimensionFigure[] {
  const g = (id: string) => goals.find((x) => x.goalId === id)!.status
  const fig = (dimension: DimensionFigure['dimension'], metricId: string, goalStatus: GoalStatus): DimensionFigure => {
    const v = metrics.get(metricId)?.value ?? null
    let status: GoalStatus
    if (goalStatus === 'DATA_ERROR') status = 'DATA_ERROR'
    else if (v === null) status = 'NOT_VERIFIED'
    else if (v === 100) status = 'VERIFIED'
    else status = 'PARTIAL'
    return { dimension, value: v, metricId, status }
  }
  return [
    // The VDP figure's status is the Goal 5 status (it depends on the pledge elements, not only the share).
    { ...fig('VDP', 'vdp.criteria_met', g('G5')), status: g('G5') },
    fig('CVE_QUALITY', 'cve.complete_records', g('G6')),
    fig('CVE_TIMELINESS', 'cve.timely_issuance', g('G6')),
  ]
}

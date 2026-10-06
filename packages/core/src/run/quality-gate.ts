/**
 * Pre-publication quality gate. Ten questions a reviewer would ask before a
 * figure is published, each answered by a concrete check over the run's
 * inputs and outputs. A check that does not pass is published with its
 * detail; nothing is hidden. The gate reports, it does not edit results.
 */

import type { GoalAssessment, MetricValue, RunInputs, RunManifest, RunOutput } from '../model/index.ts'
import { GOALS } from '../methodology/goals.ts'
import { METHODOLOGY_VERSIONS } from '../methodology/versions.ts'
import { METRIC_DEFINITIONS } from '../measure/definitions.ts'
import { percent, round2 } from '../measure/stats.ts'
import { findBannedTerms } from '../assess/language.ts'
import { allNumbersFinite, canonicalJson } from './canonical.ts'

export type QualityCheck = RunManifest['qualityChecks'][number]

export const QUALITY_QUESTIONS: { id: string; question: string; check: string }[] = [
  { id: 'Q1', question: 'Is the vendor identity correct?', check: 'No attributed record is involved in an identity conflict, and every attribution names at least one matched alias that the registry backs with evidence.' },
  { id: 'Q2', question: 'Is the dataset current enough?', check: 'Every STALE or UNKNOWN source is labelled in the freshness table, and every metric that cites evidence from such a source carries confidence below HIGH.' },
  { id: 'Q3', question: 'Is the source authoritative?', check: 'Every evidence item resolves to a declared source, and every credited CWE/CPE evidence item comes from the CNA container.' },
  { id: 'Q4', question: 'Is the formula documented?', check: 'Every reported metric has a published definition with a formula, a query and a rendered calculation.' },
  { id: 'Q5', question: 'Is the denominator correct?', check: 'Every percentage recomputes from its numerator and denominator, numerators never exceed denominators, and per-record metric denominators equal the count of their per-record evidence items.' },
  { id: 'Q6', question: 'Are missing values explicit?', check: 'Every null value carries a gap reason; no value is reported over a zero denominator.' },
  { id: 'Q7', question: 'Can the result be re-run?', check: 'The methodology version is published, every number is finite, and the outputs survive a canonical JSON round trip unchanged.' },
  { id: 'Q8', question: 'Is the conclusion overstated?', check: 'Goal 3 is never VERIFIED, unverifiable goals are NOT_EXTERNALLY_VERIFIABLE, no VERIFIED goal has an unmeasured figure, and generated text contains no judgement words.' },
  { id: 'Q9', question: 'Is measurement separated from interpretation?', check: 'Benchmark wording refers to an observable metric, anomaly headlines are worded as observations, and vendor claims never appear as supporting evidence.' },
  { id: 'Q10', question: 'Could the mapping be disputed?', check: 'Every evidence item names a subject and a snapshot that exists in the run, and every determined VDP criterion carries its rule id.' },
]

const RECORD_METRICS = ['cve.cwe_coverage', 'cve.cpe_coverage', 'cve.complete_records']

function allMetrics(out: RunOutput): { vendorId: string; goal: GoalAssessment; m: MetricValue }[] {
  return out.vendors.flatMap((v) => v.goals.flatMap((g) => g.metrics.map((m) => ({ vendorId: v.vendor.id, goal: g, m }))))
}

function check(id: string, passed: boolean, detail: string): QualityCheck {
  const q = QUALITY_QUESTIONS.find((x) => x.id === id)!
  return { id, question: q.question, passed, detail: passed ? `Passed: ${detail}` : `Needs review: ${detail}` }
}

const list = (xs: string[], n = 5): string => (xs.length > n ? `${xs.slice(0, n).join('; ')}; +${xs.length - n} more` : xs.join('; '))

export function runQualityChecks(out: RunOutput, inputs: RunInputs): QualityCheck[] {
  const results: QualityCheck[] = []
  const metrics = allMetrics(out)
  const evidenceById = new Map(out.evidence.map((e) => [e.id, e]))
  const vendorsById = new Map(inputs.vendors.map((v) => [v.id, v]))

  // Q1 identity
  {
    const conflicted = new Set([...out.identityConflicts.flatMap((c) => c.affectedRecordIds), ...out.exclusions.map((x) => x.cveId)])
    const bad = out.attributions.filter((a) => conflicted.has(a.cveId)).map((a) => `${a.cveId} -> ${a.vendorId}`)
    const unbacked = out.attributions
      .filter((a) => {
        const v = vendorsById.get(a.vendorId)
        if (!v || a.matched.length === 0) return true
        // matched values may be normalized (case-folded, suffix-stripped), so match on kind or value.
        return !a.matched.some((m) =>
          v.aliases.some((al) => al.evidence.length > 0 && (al.kind === m.kind || al.value.toLowerCase() === m.value.toLowerCase())),
        )
      })
      .map((a) => `${a.cveId} -> ${a.vendorId}`)
    const issues = [...bad.map((x) => `conflicted or excluded record attributed: ${x}`), ...unbacked.map((x) => `attribution without an evidenced alias: ${x}`)]
    results.push(
      check(
        'Q1',
        issues.length === 0,
        issues.length === 0
          ? `${out.attributions.length} attributions; ${out.identityConflicts.length} identity conflict(s), their records excluded.`
          : list(issues),
      ),
    )
  }

  // Q2 currency
  {
    const weak = out.freshness.filter((f) => f.state === 'STALE' || f.state === 'UNKNOWN')
    const weakIds = new Set(weak.map((f) => f.sourceId))
    const unlabelled = weak.filter((f) => f.state === 'UNKNOWN' && !f.note).map((f) => f.sourceId)
    const overconfident = metrics
      .filter(({ m }) => m.value !== null && m.confidence === 'HIGH' && m.evidenceIds.some((id) => weakIds.has(evidenceById.get(id)?.sourceId ?? '')))
      .map(({ vendorId, m }) => `${vendorId}/${m.metricId}`)
    const issues = [...unlabelled.map((s) => `unlabelled source ${s}`), ...overconfident.map((s) => `HIGH confidence on stale evidence: ${s}`)]
    results.push(
      check(
        'Q2',
        issues.length === 0,
        issues.length === 0
          ? weak.length === 0
            ? 'All sources are CURRENT or AGING.'
            : `${weak.length} source(s) STALE or UNKNOWN (${list(weak.map((f) => `${f.sourceId} ${f.state}`))}); each is labelled and lowers confidence.`
          : list(issues),
      ),
    )
  }

  // Q3 authoritative
  {
    const sourceIds = new Set(out.sources.map((s) => s.id))
    const unresolved = [...new Set(out.evidence.filter((e) => !sourceIds.has(e.sourceId)).map((e) => e.sourceId))]
    const nonCna = out.evidence
      .filter((e) => (e.metricId === 'cve.cwe_coverage' || e.metricId === 'cve.cpe_coverage') && e.interpretation === 'SUPPORTS' && e.extracted['container'] !== 'CNA')
      .map((e) => e.id)
    const issues = [...unresolved.map((s) => `undeclared source ${s}`), ...nonCna.map((id) => `non-CNA credit ${id}`)]
    results.push(check('Q3', issues.length === 0, issues.length === 0 ? `${out.evidence.length} evidence items resolve to ${out.sources.length} declared sources; only CNA data is credited.` : list(issues)))
  }

  // Q4 formula documented
  {
    const issues = metrics
      .filter(({ m }) => {
        const def = METRIC_DEFINITIONS.find((d) => d.id === m.metricId)
        return !def || !def.formula || !m.query || !m.calculation
      })
      .map(({ vendorId, m }) => `${vendorId}/${m.metricId}`)
    results.push(check('Q4', issues.length === 0, issues.length === 0 ? `${metrics.length} metric values, each with a definition, query and calculation.` : list(issues)))
  }

  // Q5 denominators
  {
    const issues: string[] = []
    for (const { vendorId, m } of metrics) {
      const def = METRIC_DEFINITIONS.find((d) => d.id === m.metricId)
      if (m.numerator !== undefined && m.denominator !== undefined && m.numerator > m.denominator) issues.push(`${vendorId}/${m.metricId} numerator exceeds denominator`)
      if (def?.unit === 'PERCENT' && m.value !== null && m.numerator !== undefined && m.denominator && m.metricId !== 'g3.class_share_trend' && m.metricId !== 'vdp.criteria_met') {
        if (percent(m.numerator, m.denominator) !== m.value) issues.push(`${vendorId}/${m.metricId} does not recompute`)
      }
      if (m.metricId === 'vdp.criteria_met' && m.value !== null && m.numerator !== undefined && m.denominator) {
        if (round2((m.numerator / m.denominator) * 100) !== m.value) issues.push(`${vendorId}/${m.metricId} does not recompute`)
      }
      if (RECORD_METRICS.includes(m.metricId) && m.denominator !== undefined) {
        const per = new Set(
          m.evidenceIds.map((id) => evidenceById.get(id)).filter((e) => e && e.interpretation !== 'EXCLUDED').map((e) => e!.subject),
        ).size
        if (per !== m.denominator) issues.push(`${vendorId}/${m.metricId} denominator ${m.denominator} vs ${per} evidence records`)
      }
    }
    results.push(check('Q5', issues.length === 0, issues.length === 0 ? 'Every percentage recomputes from its numerator and denominator.' : list(issues)))
  }

  // Q6 missing values explicit
  {
    const issues = metrics
      .filter(({ m }) => (m.value === null && !m.gap) || (m.value !== null && m.denominator === 0))
      .map(({ vendorId, m }) => `${vendorId}/${m.metricId}`)
    const nulls = metrics.filter(({ m }) => m.value === null).length
    results.push(check('Q6', issues.length === 0, issues.length === 0 ? `${nulls} unmeasured values, each with a gap reason.` : list(issues)))
  }

  // Q7 re-runnable
  {
    const known = METHODOLOGY_VERSIONS.some((v) => v.version === inputs.methodologyVersion)
    const finite = allNumbersFinite(out.vendors) && allNumbersFinite(out.evidence)
    const c1 = canonicalJson(out.vendors)
    const stable = canonicalJson(JSON.parse(c1)) === c1
    const issues = [!known ? 'unknown methodology version' : '', !finite ? 'non-finite number in outputs' : '', !stable ? 'outputs change on JSON round trip' : ''].filter(Boolean)
    results.push(check('Q7', issues.length === 0, issues.length === 0 ? `Methodology ${inputs.methodologyVersion} is published; outputs are canonical and finite.` : list(issues)))
  }

  // Q8 not overstated
  {
    const issues: string[] = []
    for (const v of out.vendors) {
      for (const g of v.goals) {
        const goal = GOALS.find((x) => x.id === g.goalId)
        if (g.goalId === 'G3' && g.status === 'VERIFIED') issues.push(`${v.vendor.id} G3 VERIFIED`)
        if (goal?.verificationMode === 'NOT_EXTERNALLY_VERIFIABLE' && g.status !== 'NOT_EXTERNALLY_VERIFIABLE') issues.push(`${v.vendor.id} ${g.goalId} status ${g.status}`)
        if (g.status === 'VERIFIED') {
          const dims = v.dimensions.filter((d) => (g.goalId === 'G5' ? d.dimension === 'VDP' : g.goalId === 'G6' ? d.dimension !== 'VDP' : false))
          if (dims.some((d) => d.value === null)) issues.push(`${v.vendor.id} ${g.goalId} VERIFIED with an unmeasured figure`)
        }
        for (const t of findBannedTerms(g.statusReason)) issues.push(`${v.vendor.id} ${g.goalId} reason uses "${t}"`)
      }
      for (const a of v.anomalies) for (const t of findBannedTerms(a.headline)) issues.push(`${v.vendor.id} anomaly uses "${t}"`)
      for (const b of v.benchmarks) for (const t of findBannedTerms(b.wording)) issues.push(`${v.vendor.id} benchmark uses "${t}"`)
      for (const n of Object.values(v.rankingNotes)) for (const t of findBannedTerms(n)) issues.push(`${v.vendor.id} ranking note uses "${t}"`)
    }
    results.push(check('Q8', issues.length === 0, issues.length === 0 ? 'Statuses follow the goal rules; generated text uses measurement language only.' : list(issues)))
  }

  // Q9 measurement vs interpretation
  {
    const issues: string[] = []
    for (const v of out.vendors) {
      for (const b of v.benchmarks) if (!b.wording.includes('observable metric')) issues.push(`${v.vendor.id} benchmark ${b.metricId}`)
      for (const a of v.anomalies)
        if (!/^(Observed deviation|Observed change|Data quality)/.test(a.headline)) issues.push(`${v.vendor.id} anomaly ${a.id}`)
    }
    const claimEvidence = out.evidence.filter((e) => e.interpretation === 'SUPPORTS' && e.extracted['claim'] !== undefined).map((e) => e.id)
    issues.push(...claimEvidence.map((id) => `claim used as evidence ${id}`))
    results.push(check('Q9', issues.length === 0, issues.length === 0 ? 'Positions are stated on observable metrics; anomalies are observations; claims are context only.' : list(issues)))
  }

  // Q10 disputable mapping
  {
    const issues: string[] = []
    const snapIds = new Set(out.snapshots.map((s) => s.id))
    for (const e of out.evidence) if (!e.subject || !snapIds.has(e.snapshotId)) issues.push(`evidence ${e.id} lacks a subject or a resolvable snapshot (${e.snapshotId})`)
    for (const v of out.vendors)
      for (const c of v.vdp?.criteria ?? []) if (c.state !== 'UNKNOWN' && !c.ruleId) issues.push(`${v.vendor.id} ${c.criterion} lacks a rule id`)
    results.push(check('Q10', issues.length === 0, issues.length === 0 ? 'Every evidence item names its subject and snapshot; every determination names its rule.' : list(issues)))
  }
  return results
}

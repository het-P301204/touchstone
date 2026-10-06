import { describe, expect, it } from 'vitest'
import { executeRun, reproduceRun, STAGES } from '../../src/run/run.ts'
import { canonicalJson } from '../../src/run/canonical.ts'
import { QUALITY_QUESTIONS } from '../../src/run/quality-gate.ts'
import { findBannedTerms } from '../../src/assess/language.ts'
import { cohortInputs } from '../fixtures/run-fixture.ts'
import type { RunOutput } from '../../src/model/index.ts'

const vendor = (out: RunOutput, id: string) => out.vendors.find((v) => v.vendor.id === id)!
const metric = (out: RunOutput, id: string, metricId: string) =>
  vendor(out, id)
    .goals.flatMap((g) => g.metrics)
    .find((m) => m.metricId === metricId)!
const goal = (out: RunOutput, id: string, goalId: string) => vendor(out, id).goals.find((g) => g.goalId === goalId)!

describe('executeRun end to end', () => {
  const out = executeRun(cohortInputs())

  it('produces a manifest with run id, hashes, stage log and the 10 quality checks', () => {
    const m = out.manifest
    expect(m.runId).toMatch(/^TS-2026-10-06-[0-9A-F]{4}$/)
    expect(m.inputsHash).toMatch(/^[0-9a-f]{64}$/)
    expect(m.outputsHash).toMatch(/^[0-9a-f]{64}$/)
    expect(m.stages.map((s) => s.stage)).toEqual([...STAGES])
    expect(m.qualityChecks.map((q) => q.id)).toEqual(QUALITY_QUESTIONS.map((q) => q.id))
    for (const q of m.qualityChecks) expect(q.passed, `${q.id}: ${q.detail}`).toBe(true)
  })

  it('measures the complete vendor', () => {
    expect(metric(out, 'northwind', 'cve.complete_records')).toMatchObject({ value: 100, numerator: 10, denominator: 10 })
    expect(metric(out, 'northwind', 'cve.timely_issuance')).toMatchObject({ value: 100, denominator: 5 })
    expect(goal(out, 'northwind', 'G6').status).toBe('VERIFIED')
    expect(goal(out, 'northwind', 'G5').status).toBe('VERIFIED')
    expect(goal(out, 'northwind', 'G1')).toMatchObject({ status: 'NOT_EXTERNALLY_VERIFIABLE', claimCount: 1 })
  })

  it('applies 1.1.0 to the placeholder vendor and records VDP change', () => {
    expect(metric(out, 'halcyon', 'cve.cwe_coverage')).toMatchObject({ value: 33.33 })
    expect(goal(out, 'halcyon', 'G6').status).toBe('PARTIAL')
    const ch = vendor(out, 'halcyon').vdpChanges
    expect(ch).toHaveLength(1)
    expect(ch[0]).toMatchObject({ textChanged: true, reviewRecommended: false })
    expect(ch[0]!.criteria).toEqual([{ criterion: 'SCOPE_DEFINED', before: 'MET', after: 'PARTIAL' }])
    expect(vendor(out, 'halcyon').anomalies.some((a) => a.kind === 'CHANGE_DETECTED')).toBe(true)
  })

  it('no advisory feed: timeliness NOT measured (NO_SOURCE), never zero', () => {
    expect(metric(out, 'brightwater', 'cve.timely_issuance')).toMatchObject({ value: null, gap: 'NO_SOURCE' })
    expect(vendor(out, 'brightwater').dimensions.find((d) => d.dimension === 'CVE_TIMELINESS')).toMatchObject({ value: null, status: 'NOT_VERIFIED' })
    // CISA-ADP supplies the missing CWE for 3 of 6: reported, not credited
    expect(metric(out, 'brightwater', 'cve.enriched_only')).toMatchObject({ value: 50, numerator: 3, denominator: 6 })
    expect(metric(out, 'brightwater', 'cve.cwe_coverage')).toMatchObject({ value: 50 })
  })

  it('below minimum sample and missing VDP observation', () => {
    expect(metric(out, 'sparrow', 'cve.complete_records')).toMatchObject({ value: null, gap: 'BELOW_MINIMUM_SAMPLE' })
    expect(goal(out, 'sparrow', 'G6').status).toBe('NOT_VERIFIED')
    expect(goal(out, 'sparrow', 'G5').status).toBe('NOT_VERIFIED')
    expect(vendor(out, 'sparrow').coverage.observedSlots).toBe(0)
  })

  it('excludes ambiguous and duplicate records and reports them as data quality', () => {
    const ex = out.exclusions.map((x) => `${x.cveId}:${x.reason}`)
    expect(ex).toContain('DEMO-2026-0700:AMBIGUOUS_VENDOR')
    expect(ex).toContain('DEMO-2026-0999:DUPLICATE_CONFLICT')
    expect(vendor(out, 'northwind').attributedCveIds).not.toContain('DEMO-2026-0999')
    expect(metric(out, 'northwind', 'cve.duplicate_conflicts').value).toBe(1)
    expect(metric(out, 'quill', 'cve.excluded_records').value).toBe(1)
    expect(vendor(out, 'quill').anomalies.some((a) => a.kind === 'DATA_QUALITY' && a.headline.includes('AMBIGUOUS_VENDOR'))).toBe(true)
  })

  it('G3 is never VERIFIED and unverifiable goals never carry metrics', () => {
    for (const v of out.vendors) {
      expect(v.goals.find((g) => g.goalId === 'G3')!.status).not.toBe('VERIFIED')
      for (const id of ['G1', 'G2', 'G4', 'G7']) {
        const g = v.goals.find((x) => x.goalId === id)!
        expect(g.status).toBe('NOT_EXTERNALLY_VERIFIABLE')
        expect(g.metrics).toEqual([])
      }
    }
  })

  it('has no composite score and uses measurement language only', () => {
    for (const v of out.vendors) {
      expect(Object.keys(v)).not.toContain('score')
      expect(v.dimensions.map((d) => d.dimension)).toEqual(['VDP', 'CVE_QUALITY', 'CVE_TIMELINESS'])
      const text = [...v.goals.map((g) => g.statusReason), ...v.anomalies.map((a) => a.headline), ...v.benchmarks.map((b) => b.wording), ...Object.values(v.rankingNotes)].join('\n')
      expect(findBannedTerms(text)).toEqual([])
    }
  })

  it('evidence ids are unique and every metric evidence id resolves', () => {
    const ids = new Set(out.evidence.map((e) => e.id))
    expect(ids.size).toBe(out.evidence.length)
    for (const v of out.vendors) for (const g of v.goals) for (const m of g.metrics) for (const id of m.evidenceIds) expect(ids.has(id)).toBe(true)
    for (const e of out.evidence) expect(e.id).toMatch(/^EV-[0-9a-f]{10}$/)
  })
})

describe('reproducibility', () => {
  it('same inputs + same methodology -> identical outputsHash and byte-identical output', () => {
    const a = executeRun(cohortInputs())
    const b = executeRun(cohortInputs())
    expect(b.manifest.outputsHash).toBe(a.manifest.outputsHash)
    expect(canonicalJson(b)).toBe(canonicalJson(a))
  })

  it('input order does not change the result', () => {
    const inp = cohortInputs()
    const shuffled = { ...inp, vendors: [...inp.vendors].reverse(), cves: [...inp.cves].reverse(), advisories: [...inp.advisories].reverse() }
    const a = executeRun(inp)
    const b = executeRun(shuffled)
    expect(b.manifest.outputsHash).toBe(a.manifest.outputsHash)
  })

  it('different methodology version -> different outputsHash, both recorded', () => {
    const v10 = executeRun(cohortInputs('1.0.0'))
    const v11 = executeRun(cohortInputs('1.1.0'))
    expect(v10.manifest.methodologyVersion).toBe('1.0.0')
    expect(v11.manifest.methodologyVersion).toBe('1.1.0')
    expect(v10.manifest.scoringVersion).toBe('1.0.0')
    expect(v11.manifest.scoringVersion).toBe('1.1.0')
    expect(v10.manifest.outputsHash).not.toBe(v11.manifest.outputsHash)
    expect(v10.manifest.inputsHash).not.toBe(v11.manifest.inputsHash)
    // the methodology change moves the placeholder vendor only
    expect(metric(v10, 'halcyon', 'cve.cwe_coverage').value).toBe(66.67)
    expect(metric(v11, 'halcyon', 'cve.cwe_coverage').value).toBe(33.33)
    expect(metric(v10, 'northwind', 'cve.cwe_coverage').value).toBe(metric(v11, 'northwind', 'cve.cwe_coverage').value)
  })

  it('reproduceRun confirms a manifest and lists mismatches for a tampered one', () => {
    const inp = cohortInputs()
    const out = executeRun(inp)
    expect(reproduceRun(inp, out.manifest)).toMatchObject({ reproduced: true, mismatches: [] })
    const tampered = { ...out.manifest, outputsHash: '0'.repeat(64), methodologyVersion: '1.0.0' }
    const r = reproduceRun(inp, tampered)
    expect(r.reproduced).toBe(false)
    expect(r.mismatches.map((m) => m.split(':')[0])).toEqual(['methodologyVersion', 'outputsHash'])
    expect(r.outputsHash).toBe(out.manifest.outputsHash)
  })

  it('rejects an unknown methodology version', () => {
    expect(() => executeRun(cohortInputs('9.9.9'))).toThrow(/Unknown methodology version/)
  })
})

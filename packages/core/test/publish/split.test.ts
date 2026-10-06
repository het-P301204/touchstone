import { describe, expect, it } from 'vitest'
import { executeRun } from '../../src/run/run.ts'
import { historySeries, splitForPublication } from '../../src/publish/split.ts'
import { methodologyVersion } from '../../src/methodology/versions.ts'
import { cohortInputs } from '../fixtures/run-fixture.ts'
import { daysAgo } from '../fixtures/builders.ts'

describe('splitForPublication', () => {
  const out = executeRun(cohortInputs())
  const { summary, vendors } = splitForPublication(out, methodologyVersion('1.1.0'))

  it('summary carries the manifest, methodology, goals and one VendorSummary per vendor', () => {
    expect(summary.manifest.runId).toBe(out.manifest.runId)
    expect(summary.methodology.version).toBe('1.1.0')
    expect(summary.goals).toHaveLength(7)
    expect(summary.vendors.map((v) => v.vendor.id)).toEqual(out.vendors.map((v) => v.vendor.id))
    const nw = summary.vendors.find((v) => v.vendor.id === 'northwind')!
    expect(nw.cveCount).toBe(10)
    expect(nw.advisoryCount).toBe(5)
    expect(nw.statusCounts).toEqual({ VERIFIED: 2, PARTIAL: 0, NOT_VERIFIED: 1, NOT_EXTERNALLY_VERIFIABLE: 4, DATA_ERROR: 0 })
    expect(nw.goals[0]).not.toHaveProperty('evidenceIds')
    expect(nw.goals.find((g) => g.goalId === 'G6')!.evidenceCount).toBeGreaterThan(0)
    expect(summary.exclusionCount).toBe(out.exclusions.length)
    expect(summary.signatoryList.parsedCount).toBe(6)
  })

  it('vendor detail holds that vendor’s evidence, records, exclusions and advisories only', () => {
    const d = vendors['quill']!
    expect(d.runId).toBe(out.manifest.runId)
    expect(d.evidence.every((e) => e.vendorId === 'quill')).toBe(true)
    expect(d.evidence.length).toBeGreaterThan(0)
    expect(d.exclusions.map((x) => x.cveId)).toEqual(['DEMO-2026-0700'])
    expect(d.cves.map((c) => c.id)).toContain('DEMO-2026-0700')
    expect(d.advisories.map((a) => a.id)).toEqual(['QL-2026-01'])
    const total = Object.values(vendors).reduce((n, v) => n + v.evidence.length, 0)
    expect(total).toBe(out.evidence.length)
  })

  it('keeps per-record CVE snapshots out of the summary and in the vendor details', () => {
    expect(summary.snapshots.some((s) => s.sourceId === 'cve.record')).toBe(false)
    expect(summary.snapshots.length).toBe(out.snapshots.length - 1)
    expect(summary.snapshotCounts?.['cve.record']).toBe(1)
    expect(vendors['northwind']!.snapshots?.map((s) => s.id)).toEqual(['SN-cve000000001'])
    // every evidence snapshot resolves via the summary or the vendor detail
    for (const d of Object.values(vendors)) {
      const known = new Set([...summary.snapshots, ...(d.snapshots ?? [])].map((s) => s.id))
      for (const e of d.evidence) expect(known.has(e.snapshotId), e.snapshotId).toBe(true)
    }
  })

  it('refuses a methodology that does not match the run', () => {
    expect(() => splitForPublication(out, methodologyVersion('1.0.0'))).toThrow(/does not match/)
  })
})

describe('historySeries', () => {
  it('orders points by asOf and keeps each point’s methodology version', () => {
    const earlier = { ...cohortInputs('1.0.0'), asOf: daysAgo(91), datasetVersion: '2026-07-06' }
    const a = executeRun(earlier)
    const b = executeRun(cohortInputs('1.1.0'))
    const series = historySeries([b, a])
    const s = series.find((x) => x.vendorId === 'halcyon' && x.metricId === 'cve.cwe_coverage')!
    expect(s.points.map((p) => [p.datasetVersion, p.methodologyVersion])).toEqual([
      ['2026-07-06', '1.0.0'],
      ['2026-10-06', '1.1.0'],
    ])
    expect(series.map((x) => `${x.vendorId}|${x.metricId}`)).toEqual([...series.map((x) => `${x.vendorId}|${x.metricId}`)].sort())
  })
})

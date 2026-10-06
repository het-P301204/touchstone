import { describe, expect, it } from 'vitest'
import { EvidenceLedger, evidenceId, makeEvidence } from '../../src/evidence/ledger.ts'
import type { EvidenceDraft } from '../../src/evidence/ledger.ts'

const draft = (over: Partial<EvidenceDraft> = {}): EvidenceDraft => ({
  vendorId: 'northwind',
  metricId: 'cve.cwe_coverage',
  sourceId: 'cve.record',
  snapshotId: 'SN-1',
  subject: 'DEMO-2026-0001',
  collectedAt: '2026-10-05T12:00:00.000Z',
  extracted: { container: 'CNA', cwe: ['CWE-79'] },
  interpretation: 'SUPPORTS',
  reading: 'CNA container lists CWE-79.',
  confidence: 'HIGH',
  methodologyVersion: '1.1.0',
  ...over,
})

describe('evidence ledger', () => {
  it('ids are EV- + 10 hex, content-derived and independent of key order', () => {
    const a = makeEvidence(draft())
    expect(a.id).toMatch(/^EV-[0-9a-f]{10}$/)
    const reordered = draft({ extracted: { cwe: ['CWE-79'], container: 'CNA' } })
    expect(evidenceId(reordered)).toBe(a.id)
  })

  it('different content or methodology gives a different id', () => {
    const a = evidenceId(draft())
    expect(evidenceId(draft({ subject: 'DEMO-2026-0002' }))).not.toBe(a)
    expect(evidenceId(draft({ methodologyVersion: '1.0.0' }))).not.toBe(a)
  })

  it('identical items collapse to one entry', () => {
    const l = new EvidenceLedger()
    const x = l.add(draft())
    const y = l.add(draft())
    expect(x).toBe(y)
    expect(l.size).toBe(1)
  })

  it('strips bidi and invisible characters before hashing and storing', () => {
    const rlo = String.fromCodePoint(0x202e)
    const zw = String.fromCodePoint(0x200b)
    const e = makeEvidence(draft({ reading: `CNA lists ${rlo}97-EWC${zw}.`, extracted: { quote: `a${rlo}b` } }))
    expect(e.reading).toBe('CNA lists 97-EWC.')
    expect(e.extracted['quote']).toBe('ab')
    expect(e.id).toBe(evidenceId(draft({ reading: 'CNA lists 97-EWC.', extracted: { quote: 'ab' } })))
  })

  it('lists items sorted by id', () => {
    const l = new EvidenceLedger()
    for (let i = 0; i < 20; i++) l.add(draft({ subject: `DEMO-2026-${1000 + i}` }))
    const ids = l.list().map((e) => e.id)
    expect(ids).toEqual([...ids].sort())
  })
})

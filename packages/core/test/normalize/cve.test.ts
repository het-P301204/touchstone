import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { cpeFieldGap, cweFieldGap, normalizeCveRecord, parseCpe23, parseCwe } from '../../src/normalize/cve.ts'

const real = (name: string) => JSON.parse(readFileSync(new URL(`../../../../fixtures/real/${name}`, import.meta.url), 'utf8')) as unknown
const ctx = { snapshotId: 'SN-000000000000', synthetic: false }

function record(over: { cna?: Record<string, unknown>; adp?: unknown[]; meta?: Record<string, unknown>; dataVersion?: string } = {}) {
  return {
    dataType: 'CVE_RECORD',
    dataVersion: over.dataVersion ?? '5.1',
    cveMetadata: { cveId: 'CVE-2025-12345', assignerOrgId: 'AAAA-1', assignerShortName: 'acme', state: 'PUBLISHED', datePublished: '2025-03-01T10:00:00.000Z', ...over.meta },
    containers: { cna: { affected: [{ vendor: 'Acme', product: 'Widget' }], ...over.cna }, ...(over.adp ? { adp: over.adp } : {}) },
  }
}

describe('parseCwe', () => {
  it('normalizes ids and accepts a description suffix', () => {
    expect(parseCwe('CWE-79')).toEqual({ raw: 'CWE-79', id: 'CWE-79', placeholder: false })
    expect(parseCwe('cwe-0079: Improper Neutralization').id).toBe('CWE-79')
    expect(parseCwe('  CWE-787 Out-of-bounds Write ').id).toBe('CWE-787')
  })
  it('flags placeholders, including the CISA-ADP "CWE-noinfo ..." form', () => {
    for (const p of ['NVD-CWE-noinfo', 'NVD-CWE-Other', 'nvd-cwe-NOINFO', 'CWE-noinfo Not enough information']) {
      const r = parseCwe(p)
      expect(r.placeholder).toBe(true)
      expect(r.id).toBeNull()
    }
  })
  it('marks anything else as not a CWE id', () => {
    for (const bad of ['CWE-', 'CWE-abc', 'CWE-79abc', 'XSS', '', 'CWE-0']) expect(parseCwe(bad)).toMatchObject({ id: null, placeholder: false })
  })
  it('strips invisible characters from the raw value', () => {
    expect(parseCwe(`CWE-79${String.fromCodePoint(0x202e)}`).raw).toBe('CWE-79')
  })
})

describe('cweFieldGap', () => {
  it('distinguishes NOT_PROVIDED, PLACEHOLDER (by methodology) and MALFORMED', () => {
    expect(cweFieldGap([], true)).toBe('NOT_PROVIDED')
    expect(cweFieldGap([parseCwe('NVD-CWE-noinfo')], true)).toBeNull()
    expect(cweFieldGap([parseCwe('NVD-CWE-noinfo')], false)).toBe('PLACEHOLDER')
    expect(cweFieldGap([parseCwe('CWE-xyz')], false)).toBe('MALFORMED')
    expect(cweFieldGap([parseCwe('CWE-xyz'), parseCwe('CWE-20')], false)).toBeNull()
  })
})

describe('parseCpe23', () => {
  it('parses a well-formed CPE 2.3 name', () => {
    expect(parseCpe23('cpe:2.3:a:northwind:ledger_suite:4.2.1:*:*:*:*:*:*:*')).toEqual({
      raw: 'cpe:2.3:a:northwind:ledger_suite:4.2.1:*:*:*:*:*:*:*',
      part: 'a',
      vendor: 'northwind',
      product: 'ledger_suite',
      wellFormed: true,
    })
  })
  it('honours backslash escapes and lower-cases vendor/product', () => {
    const r = parseCpe23('cpe:2.3:o:Ember\\&Oak:hub\\:pro:1.0:*:*:*:*:*:*:*')
    expect(r).toMatchObject({ wellFormed: true, vendor: 'ember&oak', product: 'hub:pro' })
  })
  it('rejects 2.2 URIs, wrong component counts, bad parts and wildcard vendors as MALFORMED', () => {
    for (const bad of [
      'cpe:/o:redhat:enterprise_linux:9',
      'cpe:2.3:a:vendor:product:1.0',
      'cpe:2.3:x:vendor:product:1.0:*:*:*:*:*:*:*',
      'cpe:2.3:a:*:product:1.0:*:*:*:*:*:*:*',
      'cpe:2.3:a:vendor:-:1.0:*:*:*:*:*:*:*',
      'cpe:2.3:a:ven dor:product:1.0:*:*:*:*:*:*:*',
      'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*\\',
      '',
    ]) {
      expect(parseCpe23(bad).wellFormed, bad).toBe(false)
    }
    expect(cpeFieldGap([parseCpe23('cpe:/a:x:y:1')])).toBe('MALFORMED')
    expect(cpeFieldGap([])).toBe('NOT_PROVIDED')
    expect(cpeFieldGap([parseCpe23('cpe:/a:x:y:1'), parseCpe23('cpe:2.3:a:x:y:1:*:*:*:*:*:*:*')])).toBeNull()
  })
})

describe('normalizeCveRecord: real records', () => {
  it('CVE-2024-21412 (5.2): CNA CPEs from cpeApplicability, CNA CWE, ADP containers kept separate', () => {
    const r = normalizeCveRecord(real('CVE-2024-21412.json'), ctx)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.record.id).toBe('CVE-2024-21412')
    expect(r.record.dataVersion).toBe('5.2')
    expect(r.record.assigner).toEqual({ orgId: 'f38d906d-7342-40ea-92c1-6c4a2c6478c8', shortName: 'microsoft' })
    expect(r.record.cna.cwes.map((c) => c.id)).toEqual(['CWE-693'])
    expect(r.record.cna.cpes.length).toBeGreaterThan(5)
    expect(r.record.cna.cpes.every((c) => c.wellFormed && c.vendor === 'microsoft')).toBe(true)
    // duplicate criteria in the source are listed once
    expect(new Set(r.record.cna.cpes.map((c) => c.raw)).size).toBe(r.record.cna.cpes.length)
    expect(r.record.cna.cvss[0]).toMatchObject({ version: '3.1', baseScore: 8.1, severity: 'HIGH', provider: 'CNA' })
    expect(r.record.adp.map((a) => a.provider)).toEqual(['CISA-ADP', 'CVE'])
    expect(r.record.adp.every((a) => a.cwes.length === 0)).toBe(true)
    expect(r.record.affected.every((a) => a.vendor === 'Microsoft')).toBe(true)
    expect(r.record.sourceHash).toMatch(/^[0-9a-f]{64}$/)
    expect(r.record.datePublished).toBe('2024-02-13T18:02:49.184Z')
  })

  it('CVE-2024-3094: CNA affected[].cpes in CPE 2.2 URI form are present but MALFORMED', () => {
    const r = normalizeCveRecord(real('CVE-2024-3094.json'), ctx)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.record.cna.cpes.length).toBeGreaterThan(0)
    expect(r.record.cna.cpes.every((c) => !c.wellFormed)).toBe(true)
    expect(cpeFieldGap(r.record.cna.cpes)).toBe('MALFORMED')
    expect(r.record.cna.cwes.map((c) => c.id)).toEqual(['CWE-506'])
  })

  it('CVE-2024-23897: no CNA CWE or CPE, CISA-ADP supplies both (enrichment, not CNA data)', () => {
    const r = normalizeCveRecord(real('CVE-2024-23897.json'), ctx)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.record.cna.cwes).toEqual([])
    expect(r.record.cna.cpes).toEqual([])
    const cisa = r.record.adp.find((a) => a.provider === 'CISA-ADP')!
    expect(cisa.cwes.map((c) => c.id)).toEqual(['CWE-27'])
    expect(cisa.cpes.some((c) => c.wellFormed && c.vendor === 'jenkins')).toBe(true)
  })

  it('CVE-2022-0001: a free-text CNA problem type is not a CWE; the ADP "CWE-noinfo" is a placeholder', () => {
    const r = normalizeCveRecord(real('CVE-2022-0001.json'), ctx)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(cweFieldGap(r.record.cna.cwes, true)).toBe('NOT_PROVIDED')
    const cisa = r.record.adp.find((a) => a.provider === 'CISA-ADP')!
    expect(cisa.cwes[0]).toMatchObject({ placeholder: true, id: null })
  })

  it('CVE-2022-0003: REJECTED record', () => {
    const r = normalizeCveRecord(real('CVE-2022-0003.json'), ctx)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.record.state).toBe('REJECTED')
    expect(r.record.affected).toEqual([])
    expect(r.record.datePublished).toBeUndefined()
  })
})

describe('normalizeCveRecord: synthetic shapes', () => {
  it('reads affected[].cpes (5.0) and ADP containers per provider', () => {
    const r = normalizeCveRecord(
      record({
        dataVersion: '5.0',
        cna: {
          affected: [{ vendor: 'Acme', product: 'Widget', cpes: ['cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*', 'cpe:/a:acme:widget:1.0'] }],
          problemTypes: [{ descriptions: [{ lang: 'en', type: 'CWE', description: 'NVD-CWE-noinfo' }] }],
        },
        adp: [{ providerMetadata: { shortName: 'CISA-ADP' }, problemTypes: [{ descriptions: [{ lang: 'en', type: 'CWE', cweId: 'CWE-79', description: 'CWE-79 XSS' }] }] }],
      }),
      ctx,
    )
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.record.cna.cpes.map((c) => c.wellFormed)).toEqual([true, false])
    expect(r.record.cna.cwes[0]!.placeholder).toBe(true)
    expect(r.record.adp[0]).toMatchObject({ provider: 'CISA-ADP', cwes: [{ id: 'CWE-79' }] })
  })

  it('accepts DEMO ids only for synthetic input', () => {
    const demo = record({ meta: { cveId: 'DEMO-2026-1001' } })
    expect(normalizeCveRecord(demo, ctx)).toMatchObject({ ok: false, cveId: 'DEMO-2026-1001' })
    expect(normalizeCveRecord(demo, { ...ctx, synthetic: true }).ok).toBe(true)
  })

  it('rejects malformed records with a reason instead of guessing', () => {
    expect(normalizeCveRecord(null, ctx).ok).toBe(false)
    expect(normalizeCveRecord([], ctx).ok).toBe(false)
    expect(normalizeCveRecord(record({ dataVersion: '6.0' }), ctx)).toMatchObject({ ok: false })
    expect(normalizeCveRecord(record({ meta: { cveId: 'CVE-24-1' } }), ctx)).toMatchObject({ ok: false })
    expect(normalizeCveRecord(record({ meta: { state: 'RESERVED' } }), ctx)).toMatchObject({ ok: false })
    expect(normalizeCveRecord({ ...record(), containers: {} }, ctx)).toMatchObject({ ok: false, error: 'containers.cna missing' })
    const legacy = normalizeCveRecord({ data_type: 'CVE', data_version: '4.0', CVE_data_meta: { ID: 'CVE-2019-0001' } }, ctx)
    expect(legacy).toMatchObject({ ok: false, cveId: 'CVE-2019-0001' })
    if (!legacy.ok) expect(legacy.error).toMatch(/legacy CVE JSON/)
  })

  it('ignores inherited properties (prototype keys in hostile JSON)', () => {
    const hostile = JSON.parse('{"__proto__":{"dataVersion":"5.1"},"dataType":"CVE_RECORD","cveMetadata":{"cveId":"CVE-2025-1111","state":"PUBLISHED"},"containers":{"cna":{}}}')
    expect(normalizeCveRecord(hostile, ctx)).toMatchObject({ ok: false })
  })

  it('sourceHash is independent of key order', () => {
    const a = record()
    const b = JSON.parse(JSON.stringify({ containers: a.containers, cveMetadata: a.cveMetadata, dataVersion: a.dataVersion, dataType: a.dataType }))
    const ra = normalizeCveRecord(a, ctx)
    const rb = normalizeCveRecord(b, ctx)
    expect(ra.ok && rb.ok && ra.record.sourceHash === rb.record.sourceHash).toBe(true)
  })
})

describe('dates and depth', () => {
  it('rejects impossible calendar dates instead of rolling them over', () => {
    const r = normalizeCveRecord(record({ meta: { datePublished: '2026-02-30T00:00:00Z', dateUpdated: '2026-04-31', dateReserved: '2024-02-29T23:59:59Z' } }), ctx)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.record.datePublished).toBeUndefined()
    expect(r.record.dateUpdated).toBeUndefined()
    expect(r.record.dateReserved).toBe('2024-02-29T23:59:59.000Z')
  })
  it('a deeply nested record is an error, not a stack overflow', () => {
    let deep: unknown = 1
    for (let i = 0; i < 5_000; i++) deep = [deep]
    const r = normalizeCveRecord(record({ cna: { x_deep: deep } }), ctx)
    expect(r).toMatchObject({ ok: false, error: 'record nested too deeply' })
  })
})

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { normalizeCsafAdvisory } from '../../src/normalize/csaf.ts'
import { parseSecurityTxt, securityTxtExpired } from '../../src/normalize/security-txt.ts'
import { parseSignerList } from '../../src/normalize/signers.ts'
import { failedSnapshotId, snapshotId } from '../../src/normalize/snapshot-id.ts'

const realText = (name: string) => readFileSync(new URL(`../../../../fixtures/real/${name}`, import.meta.url), 'utf8')

describe('parseSignerList', () => {
  it('parses the real CISA page: declared 387, 387 names, entities decoded and trimmed', () => {
    const r = parseSignerList(realText('cisa-signers-2026-10-06.html'))
    expect(r.declaredCount).toBe(387)
    expect(r.names).toHaveLength(387)
    expect(r.warnings).toEqual([])
    expect(r.names[0]).toBe('11trees')
    expect(r.names).toContain('Keeper Security') // "Keeper Security&nbsp;" in the source
    expect(r.names).toContain("Let's Go Learn")
    expect(r.names).toContain('CMD+CTRL Security')
    expect(r.names.every((n) => n === n.trim() && n.length > 0)).toBe(true)
  })

  it('warns when the parsed count differs from the declared count, and on duplicates', () => {
    const html = '<h4>4 Companies</h4><table><tr><td>A &amp; B</td><td>C</td><td>c</td><td>&nbsp;</td></tr></table>'
    const r = parseSignerList(html)
    expect(r.names).toEqual(['A & B', 'C'])
    expect(r.warnings.some((w) => w.startsWith('DUPLICATE_NAME'))).toBe(true)
    expect(r.warnings.some((w) => w.startsWith('COUNT_MISMATCH'))).toBe(true)
  })

  it('handles a missing heading and a missing table', () => {
    expect(parseSignerList('<p>nothing</p>')).toMatchObject({ declaredCount: null, names: [] })
    const r = parseSignerList('<table><tr><td>X</td></tr></table>')
    expect(r.declaredCount).toBeNull()
    expect(r.names).toEqual(['X'])
    expect(r.warnings[0]).toMatch(/^NO_DECLARED_COUNT/)
  })

  it('drops markup inside cells and ignores <thead>/<th> confusion', () => {
    const r = parseSignerList('<h2>2 Companies</h2><table><thead><tr><th>Name</th></tr></thead><tbody><tr><td><a href="x"><b>Acme</b></a></td><td><script>evil()</script>Beta</td></tr></tbody></table>')
    expect(r.names).toEqual(['Name', 'Acme', 'Beta'])
  })
})

describe('parseSecurityTxt', () => {
  const ctx = { url: 'https://www.cisa.gov/.well-known/security.txt', snapshotId: 'SN-aaaaaaaaaaaa', asOf: '2026-10-06T12:00:00Z' }

  it('parses the real CISA file', () => {
    const s = parseSecurityTxt(realText('cisa-security-2026-10-06.txt'), ctx)
    expect(s.present).toBe(true)
    expect(s.contacts).toEqual(['mailto:IRT@cisa.dhs.gov', 'mailto:TOC@cisa.dhs.gov'])
    expect(s.expires).toBe('2027-10-01T00:00:00.000Z')
    expect(s.policyUrls).toEqual([])
    expect(s.signed).toBe(false)
    expect(s.warnings.filter((w) => w.startsWith('EXPIRED'))).toEqual([])
  })

  it('reports an expired file, a missing Contact, duplicate Expires and unknown fields', () => {
    const s = parseSecurityTxt('Expires: 2025-01-01T00:00:00Z\nExpires: 2025-01-01T00:00:00.000Z\nFoo: bar\nPolicy: http://x.example/p\n', ctx)
    expect(s.expires).toBe('2025-01-01T00:00:00.000Z')
    const codes = s.warnings.map((w) => w.split(':')[0])
    expect(codes).toEqual(expect.arrayContaining(['NO_CONTACT', 'MULTIPLE_EXPIRES', 'EXPIRED', 'UNKNOWN_FIELD', 'INSECURE_URI']))
    expect(codes).not.toContain('CONTRADICTORY_EXPIRES')
    expect(securityTxtExpired(s, ctx.asOf)).toBe(true)
  })

  it('contradictory Expires values: none is used, and the file says so', () => {
    const s = parseSecurityTxt('Contact: mailto:a@b.example\nExpires: 2027-01-01T00:00:00Z\nExpires: 2025-01-01T00:00:00Z\n', ctx)
    expect(s.expires).toBeUndefined()
    expect(s.warnings.some((w) => w.startsWith('CONTRADICTORY_EXPIRES'))).toBe(true)
  })

  it('a placeholder Contact is warned about and not stored', () => {
    const s = parseSecurityTxt('Contact: none\nContact: n/a\nContact: mailto:security@v.example\nExpires: 2027-01-01T00:00:00Z\n', ctx)
    expect(s.contacts).toEqual(['mailto:security@v.example'])
    expect(s.warnings.filter((w) => w.startsWith('BAD_CONTACT_URI'))).toHaveLength(2)
  })

  it('handles CRLF, comments, PGP cleartext framing and dash-escaping', () => {
    const text = [
      '-----BEGIN PGP SIGNED MESSAGE-----',
      'Hash: SHA256',
      '',
      '# comment',
      'Contact: mailto:security@vendor.example',
      '- -Contact: https://vendor.example/report',
      'Expires: 2027-01-01T00:00:00Z',
      'Canonical: https://vendor.example/.well-known/security.txt',
      'Policy: https://vendor.example/vdp',
      '-----BEGIN PGP SIGNATURE-----',
      'Contact: mailto:attacker@evil.example',
      '-----END PGP SIGNATURE-----',
    ].join('\r\n')
    const s = parseSecurityTxt(text, { ...ctx, url: 'https://vendor.example/.well-known/security.txt' })
    expect(s.signed).toBe(true)
    expect(s.contacts).toEqual(['mailto:security@vendor.example'])
    expect(s.policyUrls).toEqual(['https://vendor.example/vdp'])
    expect(s.warnings.some((w) => w.startsWith('CANONICAL_MISMATCH'))).toBe(false)
  })

  it('an empty or field-less file is not present', () => {
    expect(parseSecurityTxt('', ctx).present).toBe(false)
    expect(parseSecurityTxt('<html>404</html>', ctx).present).toBe(false)
  })

  it('rejects a non-RFC 3339 Expires', () => {
    const s = parseSecurityTxt('Contact: mailto:a@b.example\nExpires: next year\n', ctx)
    expect(s.expires).toBeUndefined()
    expect(s.warnings.some((w) => w.startsWith('INVALID_EXPIRES'))).toBe(true)
  })
})

describe('normalizeCsafAdvisory', () => {
  const ctx = { vendorId: 'siemens', snapshotId: 'SN-bbbbbbbbbbbb', url: 'https://cert-portal.siemens.com/productcert/csaf/ssa-823812.json', synthetic: false }

  it('reads a real Siemens CSAF 2.0 advisory; severity from CVSS when no aggregate_severity', () => {
    const r = normalizeCsafAdvisory(JSON.parse(realText('siemens-csaf-ssa-823812.json')), ctx)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.advisory).toMatchObject({ id: 'SSA-823812', publishedAt: '2026-09-16T00:00:00.000Z', severity: 'MEDIUM', cveIds: ['CVE-2026-89207'] })
  })

  it('prefers aggregate_severity text and maps vendor vocabulary', () => {
    const doc = (text: string | null, sev = 'LOW') => ({
      document: { csaf_version: '2.0', title: 't', tracking: { id: 'X-1', initial_release_date: '2026-01-02T00:00:00Z' }, ...(text ? { aggregate_severity: { text } } : {}) },
      vulnerabilities: [{ cve: 'CVE-2026-0001', scores: [{ cvss_v3: { baseScore: 3.1, baseSeverity: sev } }] }, { cve: 'not-a-cve' }],
    })
    const sev = (d: unknown) => {
      const r = normalizeCsafAdvisory(d, ctx)
      return r.ok ? r.advisory.severity : 'ERR'
    }
    expect(sev(doc('Important'))).toBe('HIGH')
    expect(sev(doc('Moderate'))).toBe('MEDIUM')
    expect(sev(doc('Severe-ish'))).toBe('LOW') // unknown word: falls back to CVSS
    expect(sev(doc(null, 'CRITICAL'))).toBe('CRITICAL')
    const r = normalizeCsafAdvisory(doc(null), ctx)
    expect(r.ok && r.advisory.cveIds).toEqual(['CVE-2026-0001'])
  })

  it('rejects other CSAF versions and missing tracking data', () => {
    expect(normalizeCsafAdvisory({ document: { csaf_version: '2.1' } }, ctx).ok).toBe(false)
    expect(normalizeCsafAdvisory({ document: { csaf_version: '2.0', tracking: { id: 'x' } } }, ctx).ok).toBe(false)
    expect(normalizeCsafAdvisory('nope', ctx).ok).toBe(false)
  })
})

describe('snapshot ids', () => {
  it('are stable, content-addressed, and distinct per failed attempt', () => {
    const a = snapshotId('cve.record', 'https://x.example/a', 'f'.repeat(64))
    expect(a).toMatch(/^SN-[0-9a-f]{12}$/)
    expect(snapshotId('cve.record', 'https://x.example/a', 'f'.repeat(64))).toBe(a)
    expect(snapshotId('cve.record', 'https://x.example/b', 'f'.repeat(64))).not.toBe(a)
    expect(failedSnapshotId('s', 'u', '2026-01-01T00:00:00Z')).not.toBe(failedSnapshotId('s', 'u', '2026-01-02T00:00:00Z'))
  })
})

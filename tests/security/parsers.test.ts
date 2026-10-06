/**
 * Security review: parsers of untrusted documents (packages/core normalize/, text/, vdp/).
 *
 * Timing tests use generous thresholds (roughly 10x the linear-time cost on
 * this machine) so they only fail on super-linear behaviour.
 * Tests named "FINDING ..." demonstrate a confirmed issue and fail while it exists.
 */
import { describe, expect, it } from 'vitest'
import { methodologyVersion, CURRENT_METHODOLOGY_VERSION } from '../../packages/core/src/methodology/versions.ts'
import { normalizeCveRecord } from '../../packages/core/src/normalize/cve.ts'
import { normalizeCsafAdvisory } from '../../packages/core/src/normalize/csaf.ts'
import { isoDate } from '../../packages/core/src/normalize/json.ts'
import { parseSecurityTxt } from '../../packages/core/src/normalize/security-txt.ts'
import { parseSignerList } from '../../packages/core/src/normalize/signers.ts'
import { htmlToText } from '../../packages/core/src/text/html.ts'
import { cleanText } from '../../packages/core/src/util/sanitize.ts'
import { assessVdp } from '../../packages/core/src/vdp/assess.ts'
import { csvCell, mdInline } from '../../packages/core/src/report/escape.ts'
import { advisoryPathsFromChangesCsv } from '../../packages/collect/src/collectors/csaf.ts'

const cp = (n: number) => String.fromCodePoint(n)
const timed = (fn: () => unknown): number => {
  const t0 = performance.now()
  fn()
  return performance.now() - t0
}
const params = methodologyVersion(CURRENT_METHODOLOGY_VERSION).parameters
const noStxt = { present: false, url: '', contacts: [], policyUrls: [], canonical: [], warnings: [], signed: false }
const assessText = (text: string) => assessVdp({ vendorId: 'v', observedAt: '2026-10-06T00:00:00Z', asOf: '2026-10-06T00:00:00Z', securityTxt: noStxt, policy: { found: true, url: 'https://v.example/vdp', text }, params })
const state = (text: string, criterion: string) => assessText(text).criteria.find((c) => c.criterion === criterion)!.state

/* ------------------------------------------------------------------ pinned defences */

describe('prototype pollution via JSON keys', () => {
  it('__proto__ / constructor keys in a CVE record neither pollute nor inject data', () => {
    const raw = JSON.parse(
      '{"dataType":"CVE_RECORD","dataVersion":"5.1","__proto__":{"polluted":1},"cveMetadata":{"cveId":"CVE-2024-0001","state":"PUBLISHED","__proto__":{"assignerShortName":"evil"}},' +
        '"containers":{"cna":{"__proto__":{"affected":[{"vendor":"evil","product":"p"}]},"constructor":{"prototype":{"polluted2":1}}}}}',
    )
    const r = normalizeCveRecord(raw, { snapshotId: 'SN-000000000000', synthetic: false })
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.record.affected).toEqual([])
      expect(r.record.assigner.shortName).toBe('')
    }
    expect(({} as Record<string, unknown>).polluted).toBeUndefined()
    expect(({} as Record<string, unknown>).polluted2).toBeUndefined()
  })

  it('a CSAF severity word of "constructor" or "__proto__" is not a severity', () => {
    for (const text of ['constructor', '__proto__', 'toString']) {
      const r = normalizeCsafAdvisory(
        { document: { csaf_version: '2.0', tracking: { id: 'A-1', initial_release_date: '2026-01-01T00:00:00Z' }, aggregate_severity: { text } } },
        { vendorId: 'v', snapshotId: 'SN-000000000000', url: 'https://v.example/a.json', synthetic: false },
      )
      expect(r.ok && r.advisory.severity).toBe('UNKNOWN')
    }
  })
})

describe('linear time on adversarial input (each case is ~1 MB or within the source byte cap)', () => {
  it.each([
    ['htmlToText 1 MB of "<"', () => htmlToText('<'.repeat(1_000_000))],
    ['htmlToText unclosed <script> + 140k "</scrip"', () => htmlToText('<script>' + '</scrip'.repeat(140_000))],
    ['htmlToText 500k "&#"', () => htmlToText('&#'.repeat(500_000))],
    ['htmlToText 250k unterminated quoted attributes', () => htmlToText('<a "'.repeat(250_000))],
    ['assessVdp one 500k-char sentence of near-matches', () => assessText('xdisclos'.repeat(62_500))],
    ['assessVdp 125k sentences', () => assessText('Ab. '.repeat(125_000))],
    ['assessVdp 40k "last updated" markers', () => assessText('last updated '.repeat(40_000))],
    ['security.txt 64 KB', () => parseSecurityTxt(('Contact: ' + 'a'.repeat(60) + '\n').repeat(900), { url: 'x', snapshotId: 'SN', asOf: '2026-10-06T00:00:00Z' })],
    ['CSAF changes.csv 10 MB', () => advisoryPathsFromChangesCsv(('"' + 'a'.repeat(998) + '\n').repeat(10_000))],
    ['isoDate long fraction', () => isoDate('2026-01-01T00:00:00.' + '1'.repeat(30))],
    ['signer list 100k "<td"', () => parseSignerList('<h1>1 Companies</h1><table>' + '<td'.repeat(33_000))],
  ])('%s', (_label, fn) => {
    expect(timed(fn)).toBeLessThan(1500)
  })
})

describe('evidence text cannot become markup or reorder itself', () => {
  it('decoded entities stay text; exports escape them', () => {
    const t = htmlToText('<p>&lt;img src=x onerror=alert(1)&gt; &#x3c;script&#x3e;</p>').text
    expect(t).toBe('<img src=x onerror=alert(1)> <script>')
    expect(mdInline(t)).not.toMatch(/(^|[^\\])</)
  })
  it('bidi overrides and zero-width characters, including entity-encoded ones, are removed', () => {
    const t = htmlToText(`<p>we will${cp(0x202e)} not &#8238;sue &#x200B;you&rlm;</p>`).text
    for (const c of [0x202e, 0x200b, 0x200f]) expect(t.includes(cp(c))).toBe(false)
  })
  it('CSV formula guard survives leading whitespace, invisible prefixes and full-width triggers', () => {
    for (const v of ['=HYPERLINK("x")', ' =1+1', '\n=1', `${cp(0x200b)}=1`, `${cp(0xff1d)}1`, '@SUM(A1)', '\t=1', `${cp(0x00a0)}=1`]) {
      expect([v, csvCell(v).replace(/^"/, '').startsWith("'")]).toEqual([v, true])
    }
  })
})

/* ------------------------------------------------------------------ findings */

describe('FINDING: signer-list heading regex is quadratic', () => {
  it('FINDING parseSignerList on 100k chars of "<h1" (no ">") completes in linear time', () => {
    // HEADING = /<h([1-6])\b[^>]*>.../i rescans to the end of input from every "<h1"; 3 MB (the fetch cap) takes minutes.
    expect(timed(() => parseSignerList('<h1'.repeat(33_333)))).toBeLessThan(250)
  })
})

describe('FINDING: deep JSON nesting crashes CVE normalisation', () => {
  it('FINDING normalizeCveRecord returns a result (not a RangeError) for a record nested 20k deep in an x_ field', () => {
    let deep = '1'
    for (let i = 0; i < 20_000; i++) deep = `[${deep}]`
    const raw = JSON.parse(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2024-0001","state":"PUBLISHED"},"containers":{"cna":{"x_deep":${deep}}}}`)
    expect(() => normalizeCveRecord(raw, { snapshotId: 'SN-000000000000', synthetic: false })).not.toThrow()
  })
})

describe('FINDING: invisible characters not stripped hide prohibitive language from the phrase rules', () => {
  it('pin: the plain sentence is CONTRADICTED', () => {
    expect(state(htmlToText('<p>You must not test our production systems.</p>').text, 'TESTING_AUTHORIZED')).toBe('CONTRADICTED')
  })
  it.each([
    ['soft hyphen &#173;', 'must n&#173;ot test'],
    ['soft hyphen &shy; as raw char', `must n${cp(0x00ad)}ot test`],
    ['word joiner &#8288;', 'must not&#8288; test'],
    ['invisible times &#8290;', 'must no&#8290;t test'],
  ])('FINDING %s: renders as "must not test" in a browser but is not detected', (_label, phrase) => {
    const text = htmlToText(`<p>You ${phrase} our production systems.</p>`).text
    expect(state(text, 'TESTING_AUTHORIZED')).toBe('CONTRADICTED')
  })
  it('FINDING cleanText removes U+00AD and U+2060..U+2064', () => {
    for (const c of [0x00ad, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064]) expect([c.toString(16), cleanText(`a${cp(c)}b`)]).toEqual([c.toString(16), 'ab'])
  })
})

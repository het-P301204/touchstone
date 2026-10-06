import { describe, expect, it } from 'vitest'
import type { SecurityTxt, VdpCriterionId } from '../../src/model/index.ts'
import { methodologyVersion } from '../../src/methodology/versions.ts'
import { VDP_RULES, assessVdp, findPhrase, parseStatedLastUpdated, pledgeElementsMet, splitSentences } from '../../src/vdp/assess.ts'
import { parseSecurityTxt } from '../../src/normalize/security-txt.ts'

const params = methodologyVersion('1.1.0').parameters
const asOf = '2026-10-06T12:00:00Z'
const noStxt: SecurityTxt = { present: false, contacts: [], policyUrls: [], canonical: [], warnings: ['NOT_FOUND: HTTP 404.'], signed: false }
const stxt = (expires = '2027-03-01T00:00:00Z') =>
  parseSecurityTxt(`Contact: mailto:security@vendor.example\nExpires: ${expires}\nPolicy: https://vendor.example/vdp\n`, { url: 'https://vendor.example/.well-known/security.txt', snapshotId: 'SN-111111111111', asOf })

function assess(text: string | undefined, over: { securityTxt?: SecurityTxt; fetchFailed?: boolean; found?: boolean } = {}) {
  return assessVdp({
    vendorId: 'v',
    observedAt: asOf,
    asOf,
    securityTxt: over.securityTxt ?? stxt(),
    policy: { found: over.found ?? true, url: 'https://vendor.example/vdp', snapshotId: 'SN-222222222222', ...(text !== undefined ? { text } : {}), ...(over.fetchFailed ? { fetchFailed: true } : {}) },
    params,
  })
}
const state = (o: ReturnType<typeof assess>, c: VdpCriterionId) => o.criteria.find((x) => x.criterion === c)!

const STRONG = [
  'Vulnerability Disclosure Policy',
  'Last updated: March 14, 2026',
  'This policy applies to all Vendor products and services.',
  'We authorize security testing by members of the public of any system in scope.',
  'Report vulnerabilities by email to security@vendor.example or through our web form.',
  'If you make a good faith effort to comply with this policy, we will not pursue legal action against you.',
  'Please do not disclose a vulnerability publicly until we have released a fix or 90 days have passed.',
].join('\n')

describe('assessVdp: positive policy', () => {
  it('meets all eight criteria and quotes the supporting sentence for each', () => {
    const o = assess(STRONG)
    expect(o.criteria.map((c) => c.state)).toEqual(['MET', 'MET', 'MET', 'MET', 'MET', 'MET', 'MET', 'MET'])
    expect(pledgeElementsMet(o)).toBe(4)
    expect(state(o, 'GOOD_FAITH_SAFE_HARBOR')).toMatchObject({ ruleId: 'VDP.SAFE_HARBOR.R1', quotes: ['If you make a good faith effort to comply with this policy, we will not pursue legal action against you.'] })
    expect(state(o, 'PUBLIC_DISCLOSURE_ALLOWED').ruleId).toBe('VDP.DISCLOSURE.R2') // "do not disclose ... until" is coordination, not prohibition
    expect(state(o, 'POLICY_DISCOVERABLE').ruleId).toBe('VDP.DISCOVERABLE.STXT')
    expect(o.prohibitive).toEqual([])
    expect(o.policy.statedLastUpdated).toBe('2026-03-14')
    expect(o.policy.textHash).toMatch(/^[0-9a-f]{64}$/)
    for (const c of o.criteria) for (const q of c.quotes) expect(q.length).toBeLessThanOrEqual(300)
  })

  it('safe harbor via "safe harbor" wording requires context; a bare heading does not count', () => {
    expect(state(assess('Safe harbor\nWe read every report.'), 'GOOD_FAITH_SAFE_HARBOR').state).toBe('NOT_MET')
    expect(state(assess('Research conducted in good faith under this policy is covered by our safe harbor.'), 'GOOD_FAITH_SAFE_HARBOR')).toMatchObject({ state: 'MET', ruleId: 'VDP.SAFE_HARBOR.R2' })
  })
})

describe('assessVdp: negative and weak policies', () => {
  it('a policy without a legal-action commitment: safe harbor NOT_MET, others still MET', () => {
    const o = assess(STRONG.split('\n').filter((l) => !l.includes('legal action')).join('\n'))
    expect(state(o, 'GOOD_FAITH_SAFE_HARBOR')).toMatchObject({ state: 'NOT_MET', ruleId: 'VDP.NO_MATCH', quotes: [] })
    expect(pledgeElementsMet(o)).toBe(3)
  })

  it('a negated authorization is not read as authorization', () => {
    expect(state(assess('Security testing is not authorized.'), 'TESTING_AUTHORIZED').state).not.toBe('MET')
  })

  it('testing limited to some assets is PARTIAL, and wins over a general MET sentence', () => {
    const o = assess('This policy applies only to the web properties listed below.\nYou are authorized to test only the web properties listed in this policy.')
    expect(state(o, 'TESTING_AUTHORIZED')).toMatchObject({ state: 'PARTIAL', ruleId: 'VDP.TESTING.P1' })
    expect(state(o, 'SCOPE_DEFINED')).toMatchObject({ state: 'PARTIAL', ruleId: 'VDP.SCOPE.P1' })
  })

  it('"including but not limited to" does not narrow scope', () => {
    expect(state(assess('This policy applies to all products, including but not limited to our cloud services.'), 'SCOPE_DEFINED').state).toBe('MET')
  })
})

describe('assessVdp: prohibitive language', () => {
  const PROHIBITIVE = [
    'This policy applies to Vendor products.',
    'Researchers must obtain prior written permission before testing any system.',
    'Report vulnerabilities by email to security@vendor.example.',
    'Vendor reserves the right to pursue legal action against anyone who accesses its systems without authorization.',
    'You must not disclose any vulnerability information to third parties without our written consent.',
  ].join('\n')

  it('marks the three criteria CONTRADICTED and lists quoted findings', () => {
    const o = assess(PROHIBITIVE)
    expect(state(o, 'TESTING_AUTHORIZED')).toMatchObject({ state: 'CONTRADICTED', ruleId: 'VDP.TESTING.C1' })
    expect(state(o, 'GOOD_FAITH_SAFE_HARBOR')).toMatchObject({ state: 'CONTRADICTED', ruleId: 'VDP.SAFE_HARBOR.C1' })
    expect(state(o, 'PUBLIC_DISCLOSURE_ALLOWED')).toMatchObject({ state: 'CONTRADICTED', ruleId: 'VDP.DISCLOSURE.C1' })
    expect(state(o, 'REPORTING_CHANNEL').state).toBe('MET')
    expect(o.prohibitive.map((p) => p.againstCriterion).sort()).toEqual(['GOOD_FAITH_SAFE_HARBOR', 'PUBLIC_DISCLOSURE_ALLOWED', 'TESTING_AUTHORIZED'])
    expect(o.prohibitive.find((p) => p.againstCriterion === 'GOOD_FAITH_SAFE_HARBOR')!.quote).toContain('reserves the right to pursue legal action')
    expect(pledgeElementsMet(o)).toBe(1)
  })

  it('prohibitive language wins over supporting language in the same policy, with a note', () => {
    const o = assess(`${STRONG}\nWe reserve the right to take legal action against researchers.`)
    const c = state(o, 'GOOD_FAITH_SAFE_HARBOR')
    expect(c.state).toBe('CONTRADICTED')
    expect(c.note).toMatch(/supporting language/)
  })

  it('"will not pursue legal action" is never read as a threat', () => {
    expect(assess('We will not pursue legal action against good-faith researchers.').prohibitive).toEqual([])
  })
})

describe('assessVdp: UNKNOWN is distinct from NOT_MET', () => {
  it('policy fetch failed: pledge criteria UNKNOWN, never NOT_MET or MET', () => {
    const o = assess(undefined, { fetchFailed: true, securityTxt: noStxt })
    for (const c of ['POLICY_DISCOVERABLE', 'TESTING_AUTHORIZED', 'GOOD_FAITH_SAFE_HARBOR', 'PUBLIC_DISCLOSURE_ALLOWED', 'SCOPE_DEFINED', 'SECURITY_CONTACT', 'REPORTING_CHANNEL'] as const) {
      expect(state(o, c).state, c).toBe('UNKNOWN')
    }
    expect(o.policy.textHash).toBeUndefined()
  })

  it('no policy exists: pledge criteria NOT_MET; a security.txt contact gives a PARTIAL reporting channel', () => {
    const o = assess(undefined, { found: false })
    expect(state(o, 'POLICY_DISCOVERABLE').state).toBe('NOT_MET')
    expect(state(o, 'TESTING_AUTHORIZED')).toMatchObject({ state: 'NOT_MET', ruleId: 'VDP.NO_POLICY' })
    expect(state(o, 'REPORTING_CHANNEL')).toMatchObject({ state: 'PARTIAL', ruleId: 'VDP.REPORTING.STXT_ONLY' })
    expect(state(o, 'SECURITY_CONTACT').state).toBe('MET')
  })

  it('nothing at all: every criterion NOT_MET', () => {
    const o = assess(undefined, { found: false, securityTxt: noStxt })
    expect(o.criteria.every((c) => c.state === 'NOT_MET')).toBe(true)
  })

  it('found but empty page: UNKNOWN', () => {
    expect(state(assess('   '), 'TESTING_AUTHORIZED').state).toBe('UNKNOWN')
  })
})

describe('assessVdp: CURRENT', () => {
  it('expired security.txt and no recent policy date: NOT_MET', () => {
    const o = assess('This policy applies to all products.', { securityTxt: stxt('2026-02-01T00:00:00Z') })
    expect(state(o, 'CURRENT')).toMatchObject({ state: 'NOT_MET', ruleId: 'VDP.CURRENT.EXPIRED' })
  })
  it('expired security.txt but a recent policy date: PARTIAL', () => {
    expect(state(assess('Last updated: 2026-05-01', { securityTxt: stxt('2026-02-01T00:00:00Z') }), 'CURRENT').state).toBe('PARTIAL')
  })
  it('no security.txt, old policy date: NOT_MET; no date at all: UNKNOWN', () => {
    expect(state(assess('Last updated: May 2, 2023', { securityTxt: noStxt }), 'CURRENT')).toMatchObject({ state: 'NOT_MET', ruleId: 'VDP.CURRENT.POLICY_OLD' })
    expect(state(assess('No date here.', { securityTxt: noStxt }), 'CURRENT')).toMatchObject({ state: 'UNKNOWN', ruleId: 'VDP.CURRENT.UNDATED' })
  })
})

describe('helpers', () => {
  it('parses stated update dates in several formats', () => {
    expect(parseStatedLastUpdated('Last updated: 2026-01-15')).toBe('2026-01-15')
    expect(parseStatedLastUpdated('Last revised on March 3, 2025.')).toBe('2025-03-03')
    expect(parseStatedLastUpdated('Effective date: 7 August 2024')).toBe('2024-08-07')
    expect(parseStatedLastUpdated('Last updated: February 30, 2025')).toBeUndefined()
    expect(parseStatedLastUpdated('no date')).toBeUndefined()
  })
  it('phrases match at word starts only', () => {
    expect(findPhrase('we authorize testing', 'test')).toBeGreaterThan(0)
    expect(findPhrase('the contest rules', 'test')).toBe(-1)
    expect(findPhrase('mail security@x.example', '@')).toBeGreaterThan(0)
  })
  it('splits sentences on line breaks and terminal punctuation, not on e.g.', () => {
    expect(splitSentences('One. Two!\nThree, e.g. four? Five')).toEqual(['One.', 'Two!', 'Three, e.g. four?', 'Five'])
  })
  it('rules are documented data with unique ids', () => {
    const ids = VDP_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
    for (const r of VDP_RULES) {
      expect(r.description.length).toBeGreaterThan(10)
      expect(r.allOf.length).toBeGreaterThan(0)
      for (const g of r.allOf) for (const p of g) expect(p).toBe(p.toLowerCase())
    }
  })
  it('a long sentence is quoted in at most 300 characters around the match', () => {
    const long = `${'Background words. '.repeat(1).trim()} ${'x'.repeat(400)} we will not pursue legal action against researchers ${'y'.repeat(400)}`
    const q = state(assess(long), 'GOOD_FAITH_SAFE_HARBOR').quotes[0]!
    expect(q.length).toBeLessThanOrEqual(300)
    expect(q).toContain('will not pursue legal action')
  })
})

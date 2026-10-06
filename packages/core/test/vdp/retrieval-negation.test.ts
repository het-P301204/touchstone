import { describe, expect, it } from 'vitest'
import type { SecurityTxt, VdpCriterionId } from '../../src/model/index.ts'
import { methodologyVersion } from '../../src/methodology/versions.ts'
import { assessVdp, clauseAround, isCreditableContact } from '../../src/vdp/assess.ts'

const params = methodologyVersion('1.1.0').parameters
const asOf = '2026-10-06T12:00:00Z'
const stxt: SecurityTxt = { present: true, contacts: ['mailto:security@v.example'], policyUrls: [], canonical: [], warnings: [], signed: false, expires: '2027-03-01T00:00:00.000Z' }
const noStxt: SecurityTxt = { present: false, contacts: [], policyUrls: [], canonical: [], warnings: [], signed: false }
const LONG_FILLER = Array.from({ length: 20 }, () => 'Thank you for helping us protect our customers.').join(' ')

function assess(text: string | undefined, over: { securityTxt?: SecurityTxt; fetchFailed?: boolean; found?: boolean } = {}) {
  return assessVdp({
    vendorId: 'v',
    observedAt: asOf,
    asOf,
    securityTxt: over.securityTxt ?? stxt,
    policy: { found: over.found ?? true, url: 'https://v.example/vdp', ...(text !== undefined ? { text } : {}), ...(over.fetchFailed ? { fetchFailed: true } : {}) },
    params,
  })
}
const st = (o: ReturnType<typeof assess>, c: VdpCriterionId) => o.criteria.find((x) => x.criterion === c)!

describe('retrieval', () => {
  it('distinguishes READ, TOO_SHORT, UNREADABLE, FETCH_FAILED and NOT_FOUND', () => {
    expect(assess(`We authorize security testing. ${LONG_FILLER}`).policy.retrieval).toBe('READ')
    expect(assess('We authorize security testing of our products.').policy.retrieval).toBe('TOO_SHORT')
    expect(assess('Please enable JavaScript to view this page.').policy.retrieval).toBe('UNREADABLE')
    expect(assess('Loading...').policy.retrieval).toBe('UNREADABLE')
    expect(assess(undefined, { fetchFailed: true }).policy.retrieval).toBe('FETCH_FAILED')
    expect(assess(undefined, { found: false }).policy.retrieval).toBe('NOT_FOUND')
  })
  it('TOO_SHORT is still assessed; UNREADABLE and FETCH_FAILED make every text criterion UNKNOWN', () => {
    expect(st(assess('We authorize security testing of our products.'), 'TESTING_AUTHORIZED').state).toBe('MET')
    for (const o of [assess('Loading...'), assess(undefined, { fetchFailed: true })]) {
      for (const c of ['REPORTING_CHANNEL', 'TESTING_AUTHORIZED', 'GOOD_FAITH_SAFE_HARBOR', 'PUBLIC_DISCLOSURE_ALLOWED', 'SCOPE_DEFINED'] as const) expect(st(o, c).state, c).toBe('UNKNOWN')
      expect(st(o, 'SECURITY_CONTACT').state).toBe('MET') // the security.txt Contact still stands
    }
  })
  it('placeholder contacts are not credited', () => {
    expect(isCreditableContact('none')).toBe(false)
    expect(isCreditableContact('mailto:')).toBe(false)
    expect(isCreditableContact('mailto:security@v.example')).toBe(true)
    expect(isCreditableContact('https://v.example/report')).toBe(true)
    const o = assess(undefined, { found: false, securityTxt: { ...stxt, contacts: ['n/a'] } })
    expect(st(o, 'SECURITY_CONTACT').state).toBe('NOT_MET')
    expect(st(o, 'REPORTING_CHANNEL').state).toBe('NOT_MET')
  })
})

describe('negation', () => {
  it('a negated permissive sentence is CONTRADICTED with a finding', () => {
    const o = assess("Security testing isn't permitted on our products.", { securityTxt: noStxt })
    expect(st(o, 'TESTING_AUTHORIZED')).toMatchObject({ state: 'CONTRADICTED', ruleId: 'VDP.TESTING.R1.NEGATED' })
    expect(o.prohibitive.some((p) => p.againstCriterion === 'TESTING_AUTHORIZED')).toBe(true)
  })
  it('a negated clause that only limits scope is neither credit nor contradiction', () => {
    const o = assess('We authorize security testing of our products. Testing of systems outside this scope is not authorized.')
    expect(st(o, 'TESTING_AUTHORIZED')).toMatchObject({ state: 'MET', ruleId: 'VDP.TESTING.R1' })
    expect(o.prohibitive).toEqual([])
  })
  it('negation is scoped to the clause of the matched phrase', () => {
    expect(st(assess('We welcome security research, and we will not pursue legal action against researchers.'), 'TESTING_AUTHORIZED').state).toBe('MET')
    expect(clauseAround('we welcome research, but testing is not allowed', 3)).toBe('we welcome research')
  })
  it('"do not disclose until a fix" is coordinated disclosure, not a ban', () => {
    expect(st(assess('Please do not make a public disclosure before we release a fix.'), 'PUBLIC_DISCLOSURE_ALLOWED').state).toBe('MET')
  })
  it('legal action conditioned on not following the policy is not a contradiction', () => {
    const o = assess('If you do not follow this policy, we may take legal action.')
    expect(st(o, 'GOOD_FAITH_SAFE_HARBOR').state).toBe('NOT_MET')
    expect(o.prohibitive).toEqual([])
    expect(st(assess('We will not hesitate to pursue legal action against anyone who tests our systems.'), 'GOOD_FAITH_SAFE_HARBOR').state).toBe('CONTRADICTED')
  })
})

describe('CURRENT edge cases', () => {
  it('a future last-updated date is implausible and not counted', () => {
    const o = assess('Last updated: 2030-01-01\nWe authorize security testing.', { securityTxt: noStxt })
    expect(st(o, 'CURRENT')).toMatchObject({ state: 'UNKNOWN', ruleId: 'VDP.CURRENT.FUTURE_DATE' })
  })
  it('contradictory security.txt Expires lines make CURRENT UNKNOWN', () => {
    const o = assess(undefined, { found: false, securityTxt: { ...stxt, expires: undefined, warnings: ['CONTRADICTORY_EXPIRES: 2 different Expires values'] } })
    expect(st(o, 'CURRENT')).toMatchObject({ state: 'UNKNOWN', ruleId: 'VDP.CURRENT.STXT_CONTRADICTORY' })
  })
})

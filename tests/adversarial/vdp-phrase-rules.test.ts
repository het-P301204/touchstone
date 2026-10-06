/**
 * Adversarial: VDP phrase rules (packages/core/src/vdp/assess.ts).
 *
 * The pledge elements are read from policy text with phrase rules. A rule that
 * credits MET or PARTIAL on a sentence that says the opposite overstates the
 * vendor's evidence (and can carry a vendor to Goal 5 VERIFIED). Each failing
 * test below is a single real-looking sentence that currently earns credit.
 *
 * Correct answer for every negated sentence: not MET and not PARTIAL. Ideally
 * CONTRADICTED (prohibitive language) but NOT_MET is acceptable; what is never
 * acceptable is crediting the element.
 */

import { describe, expect, it } from 'vitest'
import { STRONG_POLICY, NO_STXT, stateOf, vdpFromText } from './helpers.ts'

const NOT_CREDITED = ['NOT_MET', 'CONTRADICTED']
const only = (text: string) => vdpFromText('acme', text, { securityTxt: NO_STXT })

describe('VDP negation handling: TESTING_AUTHORIZED', () => {
  // Defect: R1 noneOf lists "not ", "don't", "do not" ... but not the contractions
  // "isn't"/"aren't", nor "forbid", nor "without". The sentence forbids testing and
  // the engine reports TESTING_AUTHORIZED MET (rule VDP.TESTING.R1).
  it("DEFECT vdp-testing-contraction: \"isn't permitted\" must not authorize testing", () => {
    const o = only("Security testing isn't permitted on our products.")
    expect(NOT_CREDITED).toContain(stateOf(o, 'TESTING_AUTHORIZED').state)
  })

  it("DEFECT vdp-testing-contraction: \"aren't authorized to test\" must not authorize testing", () => {
    const o = only("Researchers aren't authorized to test our products.")
    expect(NOT_CREDITED).toContain(stateOf(o, 'TESTING_AUTHORIZED').state)
  })

  // "authorization" + "testing" match R1; "forbidden" is not in the negation list.
  it('DEFECT vdp-testing-forbidden: "Testing without our authorization is forbidden" must not authorize testing', () => {
    const o = only('Testing without our authorization is forbidden.')
    expect(NOT_CREDITED).toContain(stateOf(o, 'TESTING_AUTHORIZED').state)
  })

  // VDP.TESTING.P1 (PARTIAL, "limited authorization") has a shorter noneOf list than R1:
  // "never" is absent, and "not permit" cannot match inside "cannot permit" because the
  // phrase must start at a word boundary. A sentence forbidding testing earns 0.5 credit.
  it('DEFECT vdp-testing-partial-negation: "never permitted ... only" must not be PARTIAL', () => {
    const o = only('Security testing is never permitted, and reports are only accepted by email.')
    expect(NOT_CREDITED).toContain(stateOf(o, 'TESTING_AUTHORIZED').state)
  })

  it('DEFECT vdp-testing-partial-negation: "cannot permit testing ... only" must not be PARTIAL', () => {
    const o = only('We cannot permit testing of any kind; reports are only accepted by email.')
    expect(NOT_CREDITED).toContain(stateOf(o, 'TESTING_AUTHORIZED').state)
  })

  // Pinned protections (pass today).
  it('handled: "We do not authorize testing" is not MET', () => {
    expect(NOT_CREDITED).toContain(stateOf(only('We do not authorize testing of production systems.'), 'TESTING_AUTHORIZED').state)
  })
  it('handled: prior written permission is CONTRADICTED even next to an authorization', () => {
    const o = only('We authorize testing, but you must obtain prior written permission before testing any product.')
    expect(stateOf(o, 'TESTING_AUTHORIZED').state).toBe('CONTRADICTED')
    expect(o.prohibitive.map((p) => p.ruleId)).toContain('VDP.TESTING.C1')
  })
  it('handled: testing limited to web properties is PARTIAL, not MET', () => {
    expect(stateOf(only('We authorize testing only on our public websites.'), 'TESTING_AUTHORIZED').state).toBe('PARTIAL')
  })
})

describe('VDP negation handling: GOOD_FAITH_SAFE_HARBOR', () => {
  // R1 lists the bare phrase "considered authorized" with an empty noneOf, so the
  // negated form matches.
  it('DEFECT vdp-safe-harbor-not-considered-authorized: "is not considered authorized" must not be safe harbor', () => {
    const o = only('Any testing outside this policy is not considered authorized.')
    expect(NOT_CREDITED).toContain(stateOf(o, 'GOOD_FAITH_SAFE_HARBOR').state)
  })

  // R2: "safe harbor" + "research"; noneOf has "no safe harbor", "does not provide",
  // "not offer" only.
  it('DEFECT vdp-safe-harbor-negated: "Safe harbor does not apply to security research" must not be MET', () => {
    const o = only('Safe harbor does not apply to security research on our products.')
    expect(NOT_CREDITED).toContain(stateOf(o, 'GOOD_FAITH_SAFE_HARBOR').state)
  })
  it("DEFECT vdp-safe-harbor-negated: \"We don't offer safe harbor to researchers\" must not be MET", () => {
    const o = only("We don't offer safe harbor to researchers.")
    expect(NOT_CREDITED).toContain(stateOf(o, 'GOOD_FAITH_SAFE_HARBOR').state)
  })
  it('DEFECT vdp-safe-harbor-negated: "We cannot offer safe harbor" must not be MET (word-boundary defeats noneOf "not offer")', () => {
    const o = only('We cannot offer safe harbor to researchers.')
    expect(NOT_CREDITED).toContain(stateOf(o, 'GOOD_FAITH_SAFE_HARBOR').state)
  })
  it('DEFECT vdp-safe-harbor-negated: "There is no legal safe harbor for research" must not be MET', () => {
    const o = only('There is no legal safe harbor for research on our products.')
    expect(NOT_CREDITED).toContain(stateOf(o, 'GOOD_FAITH_SAFE_HARBOR').state)
  })

  it('handled: "we will not pursue legal action" in good faith is MET', () => {
    expect(stateOf(only('We will not pursue legal action against researchers acting in good faith.'), 'GOOD_FAITH_SAFE_HARBOR').state).toBe('MET')
  })
  it('handled: "we reserve the right to pursue legal action" is CONTRADICTED with a ProhibitiveFinding', () => {
    const o = only('We reserve the right to pursue legal action against anyone who tests our systems.')
    expect(stateOf(o, 'GOOD_FAITH_SAFE_HARBOR').state).toBe('CONTRADICTED')
    expect(o.prohibitive.some((p) => p.againstCriterion === 'GOOD_FAITH_SAFE_HARBOR')).toBe(true)
  })
  it('handled: "we will not hesitate to pursue legal action" is never credited as safe harbor', () => {
    expect(NOT_CREDITED).toContain(stateOf(only('We will not hesitate to pursue legal action against anyone who tests our systems.'), 'GOOD_FAITH_SAFE_HARBOR').state)
  })
  it('handled: "does not provide safe harbor" is not MET', () => {
    expect(NOT_CREDITED).toContain(stateOf(only('This policy does not provide safe harbor for research.'), 'GOOD_FAITH_SAFE_HARBOR').state)
  })
})

describe('VDP negation handling: PUBLIC_DISCLOSURE_ALLOWED', () => {
  // R1 matches "public disclosure"; NEGATIONS does not contain "forbid".
  it('DEFECT vdp-disclosure-forbidden: "Public disclosure of vulnerabilities is forbidden" must not be MET', () => {
    const o = only('Public disclosure of vulnerabilities is forbidden.')
    expect(NOT_CREDITED).toContain(stateOf(o, 'PUBLIC_DISCLOSURE_ALLOWED').state)
  })
  it("DEFECT vdp-disclosure-contraction: \"You aren't permitted to publicly disclose findings\" must not be MET", () => {
    const o = only("You aren't permitted to publicly disclose findings.")
    expect(NOT_CREDITED).toContain(stateOf(o, 'PUBLIC_DISCLOSURE_ALLOWED').state)
  })

  it('handled: "You must not disclose vulnerabilities publicly" is CONTRADICTED', () => {
    expect(stateOf(only('You must not disclose the vulnerability publicly.'), 'PUBLIC_DISCLOSURE_ALLOWED').state).toBe('CONTRADICTED')
  })
  it('handled: "Public disclosure is not permitted" is CONTRADICTED', () => {
    expect(stateOf(only('Public disclosure is not permitted.'), 'PUBLIC_DISCLOSURE_ALLOWED').state).toBe('CONTRADICTED')
  })
})

describe('VDP aggregation', () => {
  it('handled: the strong reference policy meets all eight criteria (fixture sanity)', () => {
    const o = vdpFromText('acme', STRONG_POLICY)
    expect(o.criteria.map((c) => c.state)).toEqual(['MET', 'MET', 'MET', 'MET', 'MET', 'MET', 'MET', 'MET'])
  })

  it('handled: one prohibitive sentence anywhere in an otherwise strong policy makes the element CONTRADICTED', () => {
    const o = vdpFromText('acme', `${STRONG_POLICY}\nYou must not disclose any vulnerability to third parties or the public.`)
    expect(stateOf(o, 'PUBLIC_DISCLOSURE_ALLOWED').state).toBe('CONTRADICTED')
  })

  it('handled: a policy that exists only as security.txt comments is not a policy', () => {
    const o = vdpFromText('acme', undefined, { found: false, securityTxt: { ...NO_STXT, present: true, contacts: ['mailto:security@acme.example'], warnings: [] } })
    expect(stateOf(o, 'POLICY_DISCOVERABLE').state).toBe('NOT_MET')
    expect(stateOf(o, 'TESTING_AUTHORIZED').state).toBe('NOT_MET')
  })
})

/**
 * Adversarial: Goal 5 status, VDP figures, security.txt and change detection,
 * end to end through executeRun.
 */

import { describe, expect, it } from 'vitest'
import { parseSecurityTxt } from '../../packages/core/src/normalize/security-txt.ts'
import { detectVdpChange } from '../../packages/core/src/assess/vdp-change.ts'
import { AS_OF, NO_STXT, STRONG_POLICY, daysAfter, daysAgo, goalOf, inputs, metricOf, run, stateOf, vdpFromText, vendor, vr } from './helpers.ts'

describe('Goal 5 status from adversarial policy text', () => {
  // Impact of the phrase-rule defects (vdp-phrase-rules.test.ts): a policy that forbids
  // testing, denies safe harbor and forbids disclosure is published as VERIFIED with
  // "Evidence supports all four pledge elements".
  it('DEFECT g5-verified-from-negated-policy: a policy that refuses every pledge element must not be VERIFIED', () => {
    const v = vendor('acme')
    const text = [
      "Security testing isn't permitted on our products.",
      'Safe harbor does not apply to security research on our products.',
      'Public disclosure of vulnerabilities is forbidden.',
      'Please report vulnerabilities by email to security@acme.example.',
    ].join('\n')
    const out = run(inputs({ vendors: [v], vdp: [vdpFromText('acme', text)] }))
    expect(goalOf(out, 'acme', 'G5').status).not.toBe('VERIFIED')
    expect(metricOf(out, 'acme', 'vdp.pledge_elements_met').value).toBeLessThanOrEqual(1)
  })

  // Defect: assessVdp turns a failed policy fetch into UNKNOWN for the text criteria,
  // but REPORTING_CHANNEL becomes PARTIAL from the security.txt Contact
  // (VDP.REPORTING.STXT_ONLY). vdpRetrievalFailed() requires ALL four pledge criteria
  // to be UNKNOWN, so the fetch failure is no longer recognised:
  //   - G5 is NOT_VERIFIED with the reason "A policy was found, but none of the four
  //     pledge elements is supported by it" - a statement about the policy's content
  //     that nobody read. statusRule: DATA_ERROR when the policy could not be retrieved.
  //   - vdp.pledge_elements_met is reported as 0 (value) although 3 of 4 are UNKNOWN.
  // This is the common real case: security.txt resolves, the policy page times out.
  it('DEFECT g5-fetch-failed-with-stxt-contact: policy fetch failure must be DATA_ERROR, not "none of the elements is supported"', () => {
    const v = vendor('acme')
    const obs = vdpFromText('acme', undefined, { fetchFailed: true })
    expect(stateOf(obs, 'TESTING_AUTHORIZED').state).toBe('UNKNOWN') // the pipeline did mark it unreadable
    const out = run(inputs({ vendors: [v], vdp: [obs] }))
    const g5 = goalOf(out, 'acme', 'G5')
    expect(g5.status).toBe('DATA_ERROR')
    expect(g5.statusReason).not.toMatch(/none of the four pledge elements is supported by it/)
  })
  it('DEFECT g5-fetch-failed-with-stxt-contact: pledge_elements_met must not be 0 when 3 of 4 elements are UNKNOWN', () => {
    const v = vendor('acme')
    const out = run(inputs({ vendors: [v], vdp: [vdpFromText('acme', undefined, { fetchFailed: true })] }))
    expect(metricOf(out, 'acme', 'vdp.pledge_elements_met').value).toBeNull()
  })

  it('handled: policy fetch failed and no security.txt contact -> DATA_ERROR, figures null', () => {
    const v = vendor('acme')
    const out = run(inputs({ vendors: [v], vdp: [vdpFromText('acme', undefined, { fetchFailed: true, securityTxt: NO_STXT })] }))
    expect(goalOf(out, 'acme', 'G5').status).toBe('DATA_ERROR')
    expect(metricOf(out, 'acme', 'vdp.pledge_elements_met').value).toBeNull()
  })

  // Defect: a JavaScript shell / interstitial page has "readable" text, so every text
  // criterion is determined NOT_MET ("the policy was read; no rule matched") and the
  // five text slots count as OBSERVED in evidence coverage. Nothing was read: the
  // correct state is UNKNOWN (page not readable), and the slots must not count.
  it('DEFECT vdp-js-shell-counted-as-read: an interstitial page must yield UNKNOWN, not NOT_MET', () => {
    const o = vdpFromText('acme', 'Please enable JavaScript to view this page.')
    expect(stateOf(o, 'TESTING_AUTHORIZED').state).toBe('UNKNOWN')
  })
  it('DEFECT vdp-js-shell-counted-as-read: coverage must not count an unread page as observed', () => {
    const v = vendor('acme')
    const out = run(inputs({ vendors: [v], vdp: [vdpFromText('acme', 'Loading...')] }))
    const unobserved = vr(out, 'acme').coverage.unobserved.map((u) => u.metricId)
    expect(unobserved).toContain('vdp.criterion.TESTING_AUTHORIZED')
  })

  // Hypothesis-grade (design gap, failing test): wordCount is recorded "for plausibility"
  // (model/vdp.ts) but no rule reads it. Four sentences (37 words) earn G5 VERIFIED.
  it('DEFECT vdp-no-plausibility-floor: a 37-word page should not earn VERIFIED without a plausibility check', () => {
    const v = vendor('acme')
    const tiny = 'We authorize testing. We will not pursue legal action against good-faith researchers. Report issues to security@acme.example by email. Coordinated disclosure is welcome after a fix. This policy applies to all products.'
    const obs = vdpFromText('acme', tiny)
    expect(obs.policy.wordCount).toBeLessThan(40)
    const out = run(inputs({ vendors: [v], vdp: [obs] }))
    expect(goalOf(out, 'acme', 'G5').status).not.toBe('VERIFIED')
  })
})

describe('security.txt edge cases', () => {
  // Defect: parseSecurityTxt warns BAD_CONTACT_URI but still stores the value, and
  // assessVdp counts any stored contact: a placeholder "Contact: none" yields
  // SECURITY_CONTACT MET and REPORTING_CHANNEL PARTIAL (0.5 credit).
  it('DEFECT stxt-placeholder-contact: "Contact: none" must not satisfy SECURITY_CONTACT', () => {
    const s = parseSecurityTxt(`Contact: none\nExpires: ${daysAfter(100).replace('.000', '')}\n`, { url: 'https://acme.example/.well-known/security.txt', snapshotId: 'SN-x', asOf: AS_OF })
    expect(s.warnings.some((w) => w.startsWith('BAD_CONTACT_URI'))).toBe(true)
    const o = vdpFromText('acme', undefined, { found: false, securityTxt: s })
    expect(stateOf(o, 'SECURITY_CONTACT').state).not.toBe('MET')
    expect(stateOf(o, 'REPORTING_CHANNEL').state).not.toBe('PARTIAL')
  })

  // Hypothesis-grade (failing test): RFC 9116 forbids more than one Expires. The parser
  // warns MULTIPLE_EXPIRES and uses the first; if the first is in the future and a later
  // one has passed, CURRENT is MET from a file that contradicts itself.
  it('DEFECT stxt-multiple-expires: contradictory Expires lines should not yield CURRENT MET', () => {
    const fut = daysAfter(100).replace('.000', '')
    const past = daysAgo(100).replace('.000', '')
    const s = parseSecurityTxt(`Contact: mailto:security@acme.example\nExpires: ${fut}\nExpires: ${past}\n`, { url: 'https://acme.example/.well-known/security.txt', snapshotId: 'SN-x', asOf: AS_OF })
    expect(s.warnings.some((w) => w.startsWith('MULTIPLE_EXPIRES'))).toBe(true)
    const o = vdpFromText('acme', undefined, { found: false, securityTxt: s })
    expect(stateOf(o, 'CURRENT').state).not.toBe('MET')
  })

  // Robustness: a stated "Last updated" date after asOf is treated as recent.
  it('DEFECT vdp-future-last-updated: a policy dated after asOf must not satisfy CURRENT', () => {
    const o = vdpFromText('acme', 'Last updated: 2030-01-01\nWe authorize testing of our products.', { securityTxt: NO_STXT })
    expect(stateOf(o, 'CURRENT').state).not.toBe('MET')
  })

  it('handled: expired security.txt and undated policy -> CURRENT NOT_MET with EXPIRED warning', () => {
    const s = parseSecurityTxt(`Contact: mailto:security@acme.example\nExpires: ${daysAgo(10).replace('.000', '')}\n`, { url: 'https://acme.example/.well-known/security.txt', snapshotId: 'SN-x', asOf: AS_OF })
    expect(s.warnings.some((w) => w.startsWith('EXPIRED'))).toBe(true)
    const o = vdpFromText('acme', 'We authorize testing of our products.', { securityTxt: s })
    expect(stateOf(o, 'CURRENT')).toMatchObject({ state: 'NOT_MET', ruleId: 'VDP.CURRENT.EXPIRED' })
  })

  it('handled: Policy: and Contact: lines inside comments are ignored', () => {
    const s = parseSecurityTxt('# Contact: mailto:security@acme.example\n# Policy: https://acme.example/vdp\n', { url: 'https://acme.example/.well-known/security.txt', snapshotId: 'SN-x', asOf: AS_OF })
    expect(s.present).toBe(false)
    expect(s.contacts).toEqual([])
    expect(s.policyUrls).toEqual([])
  })

  it('handled: a security.txt alone is not a policy (G5 NOT_VERIFIED, pledge elements not MET)', () => {
    const v = vendor('acme')
    const out = run(inputs({ vendors: [v], vdp: [vdpFromText('acme', undefined, { found: false })] }))
    expect(goalOf(out, 'acme', 'G5').status).toBe('NOT_VERIFIED')
    expect(metricOf(out, 'acme', 'vdp.pledge_elements_met').value).toBe(0)
  })
})

describe('VDP change detection', () => {
  // Defect: when the current policy fetch failed (and the pipeline did not carry the
  // earlier observation), detectVdpChange compares MET with UNKNOWN and reports
  // "Observed change in the VDP ... review recommended", textChanged: true. A fetch
  // failure is not a change in the vendor's policy. Correct: no VdpChange (or a
  // DATA_QUALITY note), never CHANGE_DETECTED with review recommended.
  it('DEFECT vdp-change-from-fetch-failure: UNKNOWN after a failed fetch must not be reported as a policy change', () => {
    const prev = vdpFromText('acme', STRONG_POLICY, { observedAt: daysAgo(90) })
    const cur = vdpFromText('acme', undefined, { fetchFailed: true, securityTxt: NO_STXT })
    expect(detectVdpChange(prev, cur)).toEqual([])
  })
  it('DEFECT vdp-change-from-fetch-failure: run output must not carry CHANGE_DETECTED "review recommended" for a fetch failure', () => {
    const v = vendor('acme')
    const out = run(
      inputs({
        vendors: [v],
        vdp: [vdpFromText('acme', undefined, { fetchFailed: true, securityTxt: NO_STXT })],
        previousVdp: [vdpFromText('acme', STRONG_POLICY, { observedAt: daysAgo(90) })],
      }),
    )
    expect(vr(out, 'acme').anomalies.filter((a) => a.kind === 'CHANGE_DETECTED')).toEqual([])
  })

  it('handled: an unchanged policy produces no change', () => {
    const a = vdpFromText('acme', STRONG_POLICY, { observedAt: daysAgo(90) })
    const b = vdpFromText('acme', STRONG_POLICY)
    expect(detectVdpChange(a, b)).toEqual([])
  })
})

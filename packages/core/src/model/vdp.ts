/**
 * Vulnerability disclosure policy observations.
 *
 * A security.txt file is not a VDP. Goal 5 of the pledge asks for a policy
 * that (1) authorizes testing by the public, (2) commits to not pursuing
 * legal action against good-faith research, (3) provides a clear reporting
 * channel and (4) allows public disclosure in line with coordinated
 * disclosure practice. TOUCHSTONE assesses each element separately, quotes
 * the sentence that supports each determination, and keeps "could not be
 * determined" distinct from "not present".
 */

export type VdpCriterionId =
  | 'POLICY_DISCOVERABLE' // a policy document was found via security.txt Policy:, registry URL, or vendor domain
  | 'SECURITY_CONTACT' // a security contact exists (security.txt Contact: or a policy-stated address/form)
  | 'REPORTING_CHANNEL' // PLEDGE: a clear channel to report vulnerabilities
  | 'TESTING_AUTHORIZED' // PLEDGE: authorizes testing by members of the public
  | 'GOOD_FAITH_SAFE_HARBOR' // PLEDGE: commits to not recommending/pursuing legal action for good-faith research
  | 'PUBLIC_DISCLOSURE_ALLOWED' // PLEDGE: allows public disclosure (coordinated)
  | 'SCOPE_DEFINED' // states which products/assets are in scope
  | 'CURRENT' // security.txt Expires not passed and/or policy dated within the methodology window

/** Outcome of one criterion. UNKNOWN is never counted as MET. */
export type CriterionState =
  | 'MET'
  | 'PARTIAL' // evidence supports part of the criterion (e.g. scope limited to web assets only)
  | 'NOT_MET' // the policy was read and does not contain it
  | 'CONTRADICTED' // the policy contains prohibitive language against it
  | 'UNKNOWN' // could not be determined (no policy text, fetch failed, page not readable)

export type CriterionResult = {
  criterion: VdpCriterionId
  state: CriterionState
  /** Rule id that produced the state, e.g. "VDP.SAFE_HARBOR.R2". */
  ruleId: string
  /** The sentence(s) quoted from the source that support the state (<= 300 chars each). */
  quotes: string[]
  note?: string
}

export type SecurityTxt = {
  present: boolean
  url?: string
  snapshotId?: string
  contacts: string[]
  expires?: string
  policyUrls: string[]
  canonical: string[]
  /** Parse warnings (unknown fields, multiple Expires, missing Expires, ...). */
  warnings: string[]
  signed: boolean
}

/** Prohibitive language detected in a policy: reported as observed deviation. */
export type ProhibitiveFinding = {
  ruleId: string
  quote: string
  againstCriterion: VdpCriterionId
}

export type VdpObservation = {
  vendorId: string
  observedAt: string
  securityTxt: SecurityTxt
  policy: {
    found: boolean
    url?: string
    snapshotId?: string
    /** sha256 of the normalized policy text, used for change detection. */
    textHash?: string
    /** Date the policy states it was last updated, when stated. */
    statedLastUpdated?: string
    /** Hosting: vendor domain or a known disclosure platform. */
    host?: string
    /** Count of words extracted, for plausibility (a 12-word "policy" is suspicious). */
    wordCount?: number
  }
  criteria: CriterionResult[]
  prohibitive: ProhibitiveFinding[]
  /** Set when a fetch failed and this observation is carried from an earlier snapshot. */
  carriedFromSnapshotId?: string
}

/**
 * Vulnerability disclosure policy assessment (Goal 5).
 *
 * Eight criteria, each with an explicit rule id and the sentence(s) quoted
 * from the source that support the determination. Text rules are phrase
 * rules held as data (VDP_RULES) so the methodology document can list them
 * verbatim; the structural rules (security.txt fields, discoverability,
 * currency) are listed in VDP_STRUCTURAL_RULES.
 *
 * States:
 *   MET           a rule found supporting language (quoted)
 *   PARTIAL       supporting language that is limited (e.g. testing only on some assets)
 *   CONTRADICTED  prohibitive language against the criterion (quoted, and listed as a ProhibitiveFinding)
 *   NOT_MET       the policy was read and contains no supporting language, or no policy exists
 *   UNKNOWN       could not be determined (policy fetch failed, page unreadable, no dates to judge)
 *
 * UNKNOWN is never MET, and never NOT_MET: "we could not read it" is a
 * different finding from "it is not there".
 *
 * Phrase matching: the sentence is lower-cased, curly quotes straightened and
 * whitespace collapsed. A phrase that starts with a letter or digit must
 * start at a word boundary and may be a word prefix ("disclos" matches
 * "disclose" and "disclosure"). A rule fires on a sentence when every
 * `allOf` group has at least one phrase present and no `noneOf` phrase is
 * present. When several rules for a criterion fire, the highest precedence
 * wins (CONTRADICTED 100 > limiting PARTIAL 60 > MET 50).
 */

import type {
  CriterionResult,
  CriterionState,
  MethodologyParameters,
  ProhibitiveFinding,
  SecurityTxt,
  VdpCriterionId,
  VdpObservation,
} from '../model/index.ts'
import { cleanText } from '../util/sanitize.ts'
import { sha256Text } from '../util/sha256.ts'

export type VdpRule = {
  id: string
  criterion: VdpCriterionId
  effect: 'MET' | 'PARTIAL' | 'CONTRADICTED'
  precedence: number
  description: string
  /** Every group must have at least one phrase present in the sentence (word-start match). */
  allOf: string[][]
  /** The rule does not fire on a sentence containing any of these (word-start match). No finding. */
  noneOf: string[]
  /**
   * Negation markers, matched anywhere (also inside words: "not " in "cannot ", "n't" in "isn't")
   * within the clause that holds the rule's anchor (its first-group match). A negated MET/PARTIAL
   * rule becomes a CONTRADICTED finding for the criterion (rule id + ".NEGATED"), never credit.
   */
  negations?: string[]
  /**
   * Qualifiers that make a negated clause an ordinary scope or coordination limit ("testing
   * outside this scope is not authorized", "do not disclose before a fix"): such a clause is
   * neither credited nor treated as a contradiction.
   */
  qualifiers?: string[]
}

export const VDP_CRITERIA: readonly VdpCriterionId[] = [
  'POLICY_DISCOVERABLE',
  'SECURITY_CONTACT',
  'REPORTING_CHANNEL',
  'TESTING_AUTHORIZED',
  'GOOD_FAITH_SAFE_HARBOR',
  'PUBLIC_DISCLOSURE_ALLOWED',
  'SCOPE_DEFINED',
  'CURRENT',
]

/** The four elements the pledge names for Goal 5. */
export const PLEDGE_VDP_CRITERIA: readonly VdpCriterionId[] = ['REPORTING_CHANNEL', 'TESTING_AUTHORIZED', 'GOOD_FAITH_SAFE_HARBOR', 'PUBLIC_DISCLOSURE_ALLOWED']

/** Negation markers shared by the permissive rules. Matched as substrings, so "cannot" and "isn't" are caught. */
export const VDP_NEGATIONS: readonly string[] = [
  'not ',
  "n't",
  'never',
  'cannot',
  'can not',
  'prohibit',
  'forbid',
  'no longer',
  'unauthoriz',
  'unauthoris',
  'without our authoriz',
  'without authoriz',
  'without prior authoriz',
  'without our permission',
  'without permission',
  'without prior permission',
  'without written permission',
  'without our written',
  'without explicit',
  'does not apply',
  'no safe harbo',
  'no legal safe harbo',
]

/** A negated clause that also limits scope is an ordinary scope statement, not a refusal. */
export const VDP_SCOPE_QUALIFIERS: readonly string[] = [
  'outside',
  'out of scope',
  'out-of-scope',
  'not listed',
  'other than',
  'beyond',
  'not in accordance',
  'not consistent with',
  'inconsistent with',
  'in violation',
  'violat',
  'do not follow',
  "don't follow",
  'not comply',
  'fail to comply',
  'not covered',
  'excluded',
  'third-party',
  'third party',
  'not owned',
]

/** A negated disclosure clause that sets a coordination window is coordinated disclosure, not a ban. */
export const VDP_COORDINATION_QUALIFIERS: readonly string[] = ['until', 'before', 'prior to', 'after', ' once', 'within', ' days', 'coordinat', 'unless']

/** Legal action conditioned on NOT following the policy is compatible with the pledge commitment. */
export const VDP_LEGAL_CONDITION_EXCLUSIONS: readonly string[] = [
  'will not pursue', 'will not take', 'will not initiate', "won't pursue", "won't take", 'not to pursue',
  'do not follow', "don't follow", 'not comply', 'fail to comply', 'failure to comply', 'violat', 'outside this policy',
  'outside the scope', 'outside of this policy', 'not in accordance', 'not consistent with', 'inconsistent with', 'breach',
  'not acting in good faith', 'bad faith',
]

export const VDP_RULES: readonly VdpRule[] = [
  // ---------------------------------------------------------------- reporting channel
  {
    id: 'VDP.REPORTING.R1',
    criterion: 'REPORTING_CHANNEL',
    effect: 'MET',
    precedence: 50,
    description: 'The policy tells reporters how to report: a reporting verb together with a channel (address, form, portal, platform or URL).',
    allOf: [
      ['report', 'submit', 'send', 'contact us', 'reach us', 'email us', 'e-mail us', 'notify us', 'let us know'],
      ['@', 'mailto:', 'form', 'portal', 'https://', 'email', 'e-mail', 'platform', 'hackerone', 'bugcrowd', 'intigriti', 'yeswehack'],
    ],
    noneOf: ['do not report', 'not accept'],
  },
  // ---------------------------------------------------------------- testing
  {
    id: 'VDP.TESTING.C1',
    criterion: 'TESTING_AUTHORIZED',
    effect: 'CONTRADICTED',
    precedence: 100,
    description: 'Testing requires prior written or explicit permission: testing by the public is not authorized.',
    allOf: [
      ['written permission', 'prior written', 'prior authorization', 'prior authorisation', 'prior approval', 'explicit permission', 'express permission', 'written consent', 'written authorization'],
      ['test', 'scan', 'research', 'assess', 'probe'],
    ],
    noneOf: [],
  },
  {
    id: 'VDP.TESTING.C2',
    criterion: 'TESTING_AUTHORIZED',
    effect: 'CONTRADICTED',
    precedence: 100,
    description: 'The policy prohibits testing outright.',
    allOf: [
      [
        'do not test', 'must not test', 'may not test', 'not permitted to test', 'testing is prohibited', 'testing is not permitted', 'testing is not authorized',
        'not authorized to test', 'prohibits testing', 'prohibit testing', 'prohibits any testing', 'no testing', 'testing is forbidden', 'forbids testing',
      ],
    ],
    noneOf: [],
  },
  {
    id: 'VDP.TESTING.P1',
    criterion: 'TESTING_AUTHORIZED',
    effect: 'PARTIAL',
    precedence: 60,
    description: 'Testing is authorized, but only on a restricted subset of the vendor’s products or assets.',
    allOf: [
      ['authoriz', 'authoris', 'permit', 'allowed', 'may test', 'may conduct', 'welcome', 'invite', 'encourage'],
      ['test', 'security research', 'vulnerability research', 'research activit', 'good faith research', 'good-faith research'],
      ['only', 'limited to', 'restricted to', 'solely', 'exclusively'],
    ],
    noneOf: ['not limited to'],
    negations: [...VDP_NEGATIONS],
    qualifiers: [...VDP_SCOPE_QUALIFIERS],
  },
  {
    id: 'VDP.TESTING.R1',
    criterion: 'TESTING_AUTHORIZED',
    effect: 'MET',
    precedence: 50,
    description: 'The policy authorizes, permits or invites security testing by the public.',
    allOf: [
      ['authoriz', 'authoris', 'permit', 'allowed', 'may test', 'may conduct', 'welcome', 'invite', 'encourage'],
      ['test', 'security research', 'vulnerability research', 'research activit', 'good faith research', 'good-faith research'],
    ],
    noneOf: [],
    negations: [...VDP_NEGATIONS],
    qualifiers: [...VDP_SCOPE_QUALIFIERS],
  },
  // ---------------------------------------------------------------- safe harbor
  {
    id: 'VDP.SAFE_HARBOR.C1',
    criterion: 'GOOD_FAITH_SAFE_HARBOR',
    effect: 'CONTRADICTED',
    precedence: 100,
    description: 'The policy reserves or threatens legal action against researchers. Legal action conditioned on not following the policy is not a contradiction.',
    allOf: [
      [
        'reserve the right to pursue legal', 'reserves the right to pursue legal', 'reserve the right to take legal', 'reserves the right to take legal',
        'reserve the right to initiate legal', 'reserves the right to initiate legal', 'reserve all legal', 'reserves all legal', 'may pursue legal action',
        'may take legal action', 'may initiate legal action', 'will pursue legal action', 'will take legal action', 'may result in legal action',
        'will result in legal action', 'may be prosecuted', 'will be prosecuted', 'referred to law enforcement', 'criminal prosecution',
        'hesitate to pursue legal', 'hesitate to take legal',
      ],
    ],
    noneOf: [...VDP_LEGAL_CONDITION_EXCLUSIONS],
  },
  {
    id: 'VDP.SAFE_HARBOR.R1',
    criterion: 'GOOD_FAITH_SAFE_HARBOR',
    effect: 'MET',
    precedence: 50,
    description: 'The policy commits not to recommend or pursue legal action against good-faith research, or states the research is considered authorized.',
    allOf: [
      [
        'will not pursue legal', 'will not take legal', 'will not initiate legal', 'will not bring legal', 'will not recommend or pursue legal',
        'not recommend or pursue legal', "won't pursue legal", "won't take legal", 'will not file', 'will not sue', 'will not bring a lawsuit',
        'not to pursue legal', 'will not seek prosecution', 'will not report you to law enforcement', 'consider your research to be authorized',
        'consider your research authorized', 'consider such research authorized', 'deem your research authorized', 'considered authorized',
      ],
    ],
    noneOf: [],
    // These phrases are negative in form ("will not pursue"); only a negation of the authorization itself counts.
    negations: ['not considered', 'not be considered', "n't considered", 'never considered', 'no longer considered', 'not deem'],
    qualifiers: [...VDP_SCOPE_QUALIFIERS],
  },
  {
    id: 'VDP.SAFE_HARBOR.R2',
    criterion: 'GOOD_FAITH_SAFE_HARBOR',
    effect: 'MET',
    precedence: 50,
    description: 'The policy offers a safe harbor in a sentence about good-faith research or legal action (a bare "Safe harbor" heading does not count).',
    allOf: [
      ['safe harbor', 'safe harbour'],
      ['good faith', 'good-faith', 'legal', 'research', 'comply', 'complian', 'authoriz'],
    ],
    noneOf: [],
    negations: [...VDP_NEGATIONS],
    qualifiers: [...VDP_SCOPE_QUALIFIERS],
  },
  // ---------------------------------------------------------------- public disclosure
  {
    id: 'VDP.DISCLOSURE.C1',
    criterion: 'PUBLIC_DISCLOSURE_ALLOWED',
    effect: 'CONTRADICTED',
    precedence: 100,
    description: 'The policy forbids public disclosure without a path to coordinated disclosure (no "until", "after" or time frame).',
    allOf: [
      [
        'must not disclose', 'may not disclose', 'shall not disclose', 'do not disclose', 'will not disclose', 'not to disclose', 'never disclose',
        'must not publish', 'may not publish', 'shall not publish', 'do not publish', 'not publicly disclose', 'not permitted to disclose',
        'not permitted to publish', 'prohibited from disclos', 'prohibited from publish', 'public disclosure is prohibited',
        'public disclosure is not permitted', 'public disclosure is forbidden', 'keep confidential', 'remain confidential', 'confidential indefinitely',
      ],
    ],
    noneOf: ['until', 'unless', 'prior to', 'before', 'without coordinat', 'without first', 'within', 'after', 'once'],
  },
  {
    id: 'VDP.DISCLOSURE.R1',
    criterion: 'PUBLIC_DISCLOSURE_ALLOWED',
    effect: 'MET',
    precedence: 50,
    description: 'The policy allows public disclosure or describes coordinated disclosure.',
    allOf: [
      [
        'coordinated disclosure', 'coordinated vulnerability disclosure', 'coordinate disclosure', 'coordinate public disclosure', 'public disclosure',
        'publicly disclose', 'disclose publicly', 'publish your findings', 'publish the details', 'publish details', 'publish your research',
        'may publish', 'may disclose', 'free to disclose', 'free to publish',
      ],
    ],
    noneOf: [],
    negations: [...VDP_NEGATIONS],
    qualifiers: [...VDP_COORDINATION_QUALIFIERS],
  },
  {
    id: 'VDP.DISCLOSURE.R2',
    criterion: 'PUBLIC_DISCLOSURE_ALLOWED',
    effect: 'MET',
    precedence: 50,
    description: 'The policy asks reporters to hold disclosure until a fix or a stated time: disclosure is allowed after coordination.',
    allOf: [
      ['disclos', 'publish'],
      ['until', 'after', 'before', 'once', 'days', 'prior to', 'when a fix', 'coordinat'],
    ],
    noneOf: ['never', 'indefinitely', 'without our written', 'without written', 'without prior written', 'not permitted', 'prohibit', 'forbid', "aren't permitted", 'not allowed'],
  },
  // ---------------------------------------------------------------- scope
  {
    id: 'VDP.SCOPE.P1',
    criterion: 'SCOPE_DEFINED',
    effect: 'PARTIAL',
    precedence: 60,
    description: 'Scope is stated but restricted to a subset of the vendor’s products or assets.',
    allOf: [
      ['applies only to', 'only applies to', 'applies solely to', 'limited to', 'restricted to', 'only the following', 'only covers', 'covers only', 'is limited', 'only in scope', 'only these'],
      ['scope', 'policy', 'applies', 'asset', 'system', 'propert', 'domain', 'product', 'service', 'website', 'web'],
    ],
    noneOf: ['not limited to'],
  },
  {
    id: 'VDP.SCOPE.R1',
    criterion: 'SCOPE_DEFINED',
    effect: 'MET',
    precedence: 50,
    description: 'The policy states what is in or out of scope.',
    allOf: [
      [
        'in scope', 'in-scope', 'out of scope', 'out-of-scope', 'scope of this policy', 'this policy applies to', 'policy applies to',
        'the following products', 'the following systems', 'the following assets', 'applies to all', 'covers all',
      ],
    ],
    noneOf: [],
  },
  // ---------------------------------------------------------------- contact (policy text)
  {
    id: 'VDP.CONTACT.R2',
    criterion: 'SECURITY_CONTACT',
    effect: 'MET',
    precedence: 50,
    description: 'The policy names a security mailbox or security team contact.',
    allOf: [['security@', 'psirt@', 'secure@', 'vulnerability@', 'vulns@', 'disclosure@', 'cert@', 'product-security@', 'productsecurity@', 'security contact', 'security team at', 'psirt']],
    noneOf: [],
  },
]

/** Text that marks a short page as a JavaScript shell or interstitial rather than a policy. */
export const VDP_INTERSTITIAL_MARKERS: readonly string[] = [
  'enable javascript',
  'javascript is required',
  'javascript must be enabled',
  'requires javascript',
  'turn on javascript',
  'javascript is disabled',
  'loading...',
  `loading${String.fromCodePoint(0x2026)}`,
  'please wait',
  'checking your browser',
  'just a moment',
  'verify you are human',
  'are you a robot',
  'access denied',
  'captcha',
]

/** Rules that do not read policy text. */
export const VDP_STRUCTURAL_RULES: readonly { id: string; criterion: VdpCriterionId; state: CriterionState; description: string }[] = [
  { id: 'VDP.DISCOVERABLE.STXT', criterion: 'POLICY_DISCOVERABLE', state: 'MET', description: 'A policy was read from the URL in the security.txt Policy field.' },
  { id: 'VDP.DISCOVERABLE.KNOWN', criterion: 'POLICY_DISCOVERABLE', state: 'MET', description: 'A policy was read from the vendor’s registered policy URL (vendor domain or known disclosure platform).' },
  { id: 'VDP.DISCOVERABLE.UNREADABLE', criterion: 'POLICY_DISCOVERABLE', state: 'UNKNOWN', description: 'A policy URL is known but the fetch failed or the page had no readable text.' },
  { id: 'VDP.DISCOVERABLE.NONE', criterion: 'POLICY_DISCOVERABLE', state: 'NOT_MET', description: 'No policy was found in security.txt, the registry, or on the vendor domain.' },
  { id: 'VDP.CONTACT.STXT', criterion: 'SECURITY_CONTACT', state: 'MET', description: 'security.txt lists at least one Contact.' },
  { id: 'VDP.CONTACT.NONE', criterion: 'SECURITY_CONTACT', state: 'NOT_MET', description: 'No security.txt Contact and no security contact in the policy text.' },
  { id: 'VDP.CONTACT.UNKNOWN', criterion: 'SECURITY_CONTACT', state: 'UNKNOWN', description: 'No security.txt Contact, and the policy could not be read.' },
  { id: 'VDP.REPORTING.STXT_ONLY', criterion: 'REPORTING_CHANNEL', state: 'PARTIAL', description: 'The policy does not describe a channel, but security.txt lists a Contact.' },
  { id: 'VDP.NO_POLICY', criterion: 'TESTING_AUTHORIZED', state: 'NOT_MET', description: 'No policy exists: the pledge elements and scope are NOT_MET (applies to every text criterion).' },
  { id: 'VDP.POLICY_UNREADABLE', criterion: 'TESTING_AUTHORIZED', state: 'UNKNOWN', description: 'The policy could not be read: text criteria are UNKNOWN (applies to every text criterion).' },
  { id: 'VDP.NO_MATCH', criterion: 'TESTING_AUTHORIZED', state: 'NOT_MET', description: 'The policy was read and no rule for the criterion matched (applies to every text criterion).' },
  { id: 'VDP.CURRENT.STXT', criterion: 'CURRENT', state: 'MET', description: 'security.txt is present and its Expires date has not passed.' },
  { id: 'VDP.CURRENT.POLICY_DATE', criterion: 'CURRENT', state: 'MET', description: 'The policy states a last-updated date within the methodology window (vdpCurrentWithinDays).' },
  { id: 'VDP.CURRENT.EXPIRED', criterion: 'CURRENT', state: 'NOT_MET', description: 'security.txt Expires has passed and the policy states no recent update.' },
  { id: 'VDP.CURRENT.EXPIRED_POLICY_RECENT', criterion: 'CURRENT', state: 'PARTIAL', description: 'security.txt Expires has passed, but the policy states a recent update.' },
  { id: 'VDP.CURRENT.POLICY_OLD', criterion: 'CURRENT', state: 'NOT_MET', description: 'No valid security.txt, and the policy’s stated update is older than the window.' },
  { id: 'VDP.CURRENT.STXT_CONTRADICTORY', criterion: 'CURRENT', state: 'UNKNOWN', description: 'security.txt states several different Expires dates and the policy states no recent update.' },
  { id: 'VDP.CURRENT.FUTURE_DATE', criterion: 'CURRENT', state: 'UNKNOWN', description: 'The policy states a last-updated date after asOf: implausible, not counted.' },
  { id: 'VDP.*.NEGATED', criterion: 'TESTING_AUTHORIZED', state: 'CONTRADICTED', description: 'A permissive rule matched in a negated clause (e.g. "testing is never permitted"): recorded as prohibitive language (applies to every rule with negations).' },
  { id: 'VDP.CURRENT.NONE', criterion: 'CURRENT', state: 'NOT_MET', description: 'Neither security.txt nor a policy exists (both sources were read).' },
  { id: 'VDP.CURRENT.UNDATED', criterion: 'CURRENT', state: 'UNKNOWN', description: 'No security.txt Expires and no stated policy date: currency cannot be determined.' },
]

// ------------------------------------------------------------------ text utilities

const MAX_QUOTE = 300
const MAX_SENTENCES = 5_000

function isWordChar(c: string | undefined): boolean {
  return c !== undefined && /[a-z0-9]/.test(c)
}

/** Curly single quotes and modifier apostrophe -> "'"; curly double quotes -> '"'. By code point. */
function straightenQuotes(s: string): string {
  let out = ''
  for (const ch of s) {
    const cp = ch.codePointAt(0)!
    if (cp === 0x2018 || cp === 0x2019 || cp === 0x02bc) out += "'"
    else if (cp === 0x201c || cp === 0x201d) out += '"'
    else out += ch
  }
  return out
}

function normalizeSentence(s: string): string {
  return straightenQuotes(s.toLowerCase()).replace(/\s+/g, ' ')
}

/** Index of `phrase` in `s` honouring the word-start rule, or -1. */
export function findPhrase(s: string, phrase: string): number {
  const needsBoundary = /^[a-z0-9]/.test(phrase)
  let from = 0
  for (;;) {
    const i = s.indexOf(phrase, from)
    if (i < 0) return -1
    if (!needsBoundary || !isWordChar(s[i - 1])) return i
    from = i + 1
  }
}

/** Split extracted text into sentences: at line breaks, and after . ! ? followed by whitespace. Linear. */
export function splitSentences(text: string): string[] {
  const out: string[] = []
  let start = 0
  const push = (end: number) => {
    const s = text.slice(start, end).replace(/\s+/g, ' ').trim()
    if (s.length > 0 && out.length < MAX_SENTENCES) out.push(s)
  }
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (c === '\n') {
      push(i)
      start = i + 1
    } else if ((c === '.' || c === '!' || c === '?') && (text[i + 1] === ' ' || text[i + 1] === '\n' || text[i + 1] === undefined)) {
      // Do not split after common abbreviations.
      const prev = text.slice(Math.max(0, i - 4), i).toLowerCase()
      if (prev.endsWith('e.g') || prev.endsWith('i.e') || prev.endsWith(' inc') || prev.endsWith(' etc') || prev.endsWith(' vs')) continue
      push(i + 1)
      start = i + 1
    }
  }
  push(text.length)
  return out
}

/** A quote of at most 300 characters, centred on the match when the sentence is longer. */
function quoteOf(sentence: string, at: number): string {
  if (sentence.length <= MAX_QUOTE) return sentence
  const start = Math.max(0, Math.min(at - 100, sentence.length - (MAX_QUOTE - 2)))
  const body = sentence.slice(start, start + MAX_QUOTE - 2)
  return (start > 0 ? '…' : '') + body + (start + MAX_QUOTE - 2 < sentence.length ? '…' : '')
}

/** Clause boundaries used to scope a negation to the words around a rule's anchor. */
const CLAUSE_BREAKS = [',', ';', ':', '(', ')', ' but ', ' and ', ' or ', ' however', ' whereas ', ' while ', ' although ', ' except ']

/** The clause of `s` that contains index `at`. Linear in the sentence length per break marker. */
export function clauseAround(s: string, at: number): string {
  let start = 0
  let end = s.length
  for (const b of CLAUSE_BREAKS) {
    const before = at > 0 ? s.lastIndexOf(b, at - 1) : -1
    if (before >= 0 && before + b.length <= at && before + b.length > start) start = before + b.length
    const after = s.indexOf(b, at + 1)
    if (after >= 0 && after < end) end = after
  }
  return s.slice(start, end)
}

type RuleMatch = { at: number; negated: boolean }

function ruleMatch(rule: VdpRule, norm: string): RuleMatch | null {
  for (const n of rule.noneOf) if (findPhrase(norm, n) >= 0) return null
  let first = -1
  for (const group of rule.allOf) {
    let hit = -1
    for (const p of group) {
      const i = findPhrase(norm, p)
      if (i >= 0 && (hit < 0 || i < hit)) hit = i
    }
    if (hit < 0) return null
    if (first < 0) first = hit
  }
  if (rule.negations && rule.negations.length > 0 && rule.effect !== 'CONTRADICTED') {
    const clause = ` ${clauseAround(norm, first)} `
    if (rule.negations.some((n) => clause.includes(n))) {
      if (rule.qualifiers?.some((q) => clause.includes(q))) return null
      return { at: first, negated: true }
    }
  }
  return { at: first, negated: false }
}

const MONTHS = ['january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december']

function ymd(y: number, m: number, d: number): string | undefined {
  if (y < 1990 || y > 2100 || m < 1 || m > 12 || d < 1 || d > 31) return undefined
  const t = Date.UTC(y, m - 1, d)
  const back = new Date(t)
  if (back.getUTCMonth() !== m - 1) return undefined
  return back.toISOString().slice(0, 10)
}

function parseLooseDate(s: string): string | undefined {
  const iso = /(\d{4})-(\d{2})-(\d{2})/.exec(s)
  if (iso) return ymd(Number(iso[1]), Number(iso[2]), Number(iso[3]))
  const mdy = /\b([a-z]{3,9})\.? (\d{1,2}),? (\d{4})\b/.exec(s)
  if (mdy) {
    const m = MONTHS.findIndex((x) => x.startsWith(mdy[1]!) && mdy[1]!.length >= 3)
    if (m >= 0) return ymd(Number(mdy[3]), m + 1, Number(mdy[2]))
  }
  const dmy = /\b(\d{1,2}) ([a-z]{3,9})\.? (\d{4})\b/.exec(s)
  if (dmy) {
    const m = MONTHS.findIndex((x) => x.startsWith(dmy[2]!) && dmy[2]!.length >= 3)
    if (m >= 0) return ymd(Number(dmy[3]), m + 1, Number(dmy[1]))
  }
  return undefined
}

const UPDATED_MARKERS = ['last updated', 'last modified', 'last revised', 'updated on', 'revised on', 'effective date', 'effective as of', 'date of last revision']

/** The date a policy states it was last updated ("Last updated: 2026-03-14", "Last updated March 14, 2026"). */
export function parseStatedLastUpdated(text: string): string | undefined {
  const lower = normalizeSentence(text)
  let best: string | undefined
  for (const marker of UPDATED_MARKERS) {
    let from = 0
    for (let n = 0; n < 20; n++) {
      const i = lower.indexOf(marker, from)
      if (i < 0) break
      const d = parseLooseDate(lower.slice(i + marker.length, i + marker.length + 40))
      if (d && (best === undefined || d > best)) best = d
      from = i + marker.length
    }
  }
  return best
}

// ------------------------------------------------------------------ assessment

type Input = {
  vendorId: string
  observedAt: string
  asOf: string
  securityTxt: SecurityTxt
  policy: { found: boolean; url?: string; snapshotId?: string; text?: string; host?: string; fetchFailed?: boolean }
  params: MethodologyParameters
}

function hostOf(url: string | undefined): string | undefined {
  if (!url) return undefined
  try {
    return new URL(url).hostname
  } catch {
    return undefined
  }
}

/** A security.txt Contact credited as a contact: mailto:, https:, http: or tel: with a value. */
export function isCreditableContact(c: string): boolean {
  return /^(?:mailto:[^\s@]+@[^\s@]+|https?:\/\/\S+|tel:\+?[0-9][0-9 ()-]{3,})$/i.test(c.trim())
}

/** How the policy text was obtained, per VdpObservation.policy.retrieval. */
export function policyRetrieval(policy: Input['policy'], text: string, params: MethodologyParameters): VdpObservation['policy']['retrieval'] {
  if (policy.fetchFailed) return 'FETCH_FAILED'
  if (!policy.found) return 'NOT_FOUND'
  const words = countWords(text)
  if (words < 3) return 'UNREADABLE'
  if (words < params.vdpMinimumPolicyWords) {
    const lower = normalizeSentence(text)
    if (VDP_INTERSTITIAL_MARKERS.some((m) => lower.includes(m))) return 'UNREADABLE'
    return 'TOO_SHORT'
  }
  return 'READ'
}

function countWords(text: string): number {
  return text.split(/\s+/).filter((w) => w.length > 0).length
}

type Hit = { ruleId: string; effect: CriterionState; precedence: number; quotes: string[]; contradictsSupport: boolean }

export function assessVdp(input: Input): VdpObservation {
  const { securityTxt: stxt, policy, params } = input
  const text = policy.text === undefined ? '' : cleanText(policy.text).replace(/[ \t\f\v\r]+/g, ' ').replace(/ ?\n ?/g, '\n').trim()
  const retrieval = policyRetrieval(policy, text, params)
  const readable = retrieval === 'READ' || retrieval === 'TOO_SHORT'
  const unreadable = retrieval === 'UNREADABLE' || retrieval === 'FETCH_FAILED'
  const contacts = stxt.present ? stxt.contacts.filter(isCreditableContact) : []

  const sentences = readable ? splitSentences(text) : []
  const normalized = sentences.map(normalizeSentence)

  // Evaluate every text rule over every sentence. A negated permissive rule is a contradiction.
  const hits = new Map<VdpCriterionId, Hit[]>()
  const prohibitive: ProhibitiveFinding[] = []
  const addHit = (criterion: VdpCriterionId, h: Omit<Hit, 'quotes'>, quote: string) => {
    const list = hits.get(criterion) ?? []
    let entry = list.find((x) => x.ruleId === h.ruleId)
    if (!entry) {
      entry = { ...h, quotes: [] }
      list.push(entry)
      hits.set(criterion, list)
    }
    if (!entry.quotes.includes(quote)) entry.quotes.push(quote)
    if (h.effect === 'CONTRADICTED' && prohibitive.length < 20 && !prohibitive.some((p) => p.againstCriterion === criterion && p.quote === quote)) {
      prohibitive.push({ ruleId: h.ruleId, quote, againstCriterion: criterion })
    }
  }
  for (const rule of VDP_RULES) {
    for (let k = 0; k < normalized.length; k++) {
      const m = ruleMatch(rule, normalized[k]!)
      if (!m) continue
      const q = quoteOf(sentences[k]!, m.at)
      if (m.negated) addHit(rule.criterion, { ruleId: `${rule.id}.NEGATED`, effect: 'CONTRADICTED', precedence: 100, contradictsSupport: false }, q)
      else addHit(rule.criterion, { ruleId: rule.id, effect: rule.effect, precedence: rule.precedence, contradictsSupport: false }, q)
    }
  }

  const best = (criterion: VdpCriterionId) => {
    const list = hits.get(criterion)
    if (!list || list.length === 0) return undefined
    return [...list].sort((a, b) => b.precedence - a.precedence)[0]
  }

  const results = new Map<VdpCriterionId, CriterionResult>()
  const set = (criterion: VdpCriterionId, state: CriterionState, ruleId: string, quotes: string[], note?: string) => {
    const r: CriterionResult = { criterion, state, ruleId, quotes: quotes.slice(0, 2).map((q) => (q.length > MAX_QUOTE ? q.slice(0, MAX_QUOTE - 1) + '…' : q)) }
    if (note) r.note = note
    results.set(criterion, r)
  }
  const wordCount = text.length > 0 ? countWords(text) : 0
  const unreadableNote =
    retrieval === 'FETCH_FAILED' ? 'The policy fetch failed; its content is unknown.' : 'The page had no readable policy text (empty, a JavaScript shell or an interstitial).'

  // POLICY_DISCOVERABLE
  const policyHost = policy.host ?? hostOf(policy.url)
  if (readable) {
    const viaStxt = policy.url !== undefined && stxt.policyUrls.includes(policy.url)
    set(
      'POLICY_DISCOVERABLE',
      'MET',
      viaStxt ? 'VDP.DISCOVERABLE.STXT' : 'VDP.DISCOVERABLE.KNOWN',
      [viaStxt ? `Policy: ${policy.url}` : `Policy read from ${policy.url ?? policyHost ?? 'the registered URL'}`],
      retrieval === 'TOO_SHORT' ? `Only ${wordCount} words were extracted (plausibility floor ${params.vdpMinimumPolicyWords}).` : undefined,
    )
  } else if (unreadable) {
    set('POLICY_DISCOVERABLE', 'UNKNOWN', 'VDP.DISCOVERABLE.UNREADABLE', policy.url ? [`Policy URL: ${policy.url}`] : [], unreadableNote)
  } else {
    set('POLICY_DISCOVERABLE', 'NOT_MET', 'VDP.DISCOVERABLE.NONE', [], 'No policy was found in security.txt, the registry, or on the vendor domain.')
  }

  // SECURITY_CONTACT (a security.txt Contact stands on its own, even when the policy is unreadable)
  const contactHit = best('SECURITY_CONTACT')
  if (contacts.length > 0) {
    set('SECURITY_CONTACT', 'MET', 'VDP.CONTACT.STXT', contacts.slice(0, 2).map((c) => `Contact: ${c}`))
  } else if (readable && contactHit && contactHit.effect === 'MET') {
    set('SECURITY_CONTACT', 'MET', contactHit.ruleId, contactHit.quotes)
  } else if (unreadable) {
    set('SECURITY_CONTACT', 'UNKNOWN', 'VDP.CONTACT.UNKNOWN', [], `No usable security.txt Contact; ${unreadableNote.charAt(0).toLowerCase()}${unreadableNote.slice(1)}`)
  } else {
    set('SECURITY_CONTACT', 'NOT_MET', 'VDP.CONTACT.NONE', [], stxt.present && stxt.contacts.length > contacts.length ? 'security.txt lists a Contact that is not a usable URI (placeholder).' : undefined)
  }

  // Text criteria. When the policy could not be read, every one of them is UNKNOWN.
  const textCriteria: VdpCriterionId[] = ['REPORTING_CHANNEL', 'TESTING_AUTHORIZED', 'GOOD_FAITH_SAFE_HARBOR', 'PUBLIC_DISCLOSURE_ALLOWED', 'SCOPE_DEFINED']
  for (const criterion of textCriteria) {
    const hit = best(criterion)
    if (readable && hit) {
      const supporting = (hits.get(criterion) ?? []).some((h) => h.effect !== 'CONTRADICTED')
      const note = hit.effect === 'CONTRADICTED' && supporting ? 'The policy also contains supporting language; prohibitive language takes precedence.' : undefined
      set(criterion, hit.effect, hit.ruleId, hit.quotes, note)
    } else if (unreadable) {
      set(criterion, 'UNKNOWN', 'VDP.POLICY_UNREADABLE', [], unreadableNote)
    } else if (criterion === 'REPORTING_CHANNEL' && contacts.length > 0) {
      set(criterion, 'PARTIAL', 'VDP.REPORTING.STXT_ONLY', contacts.slice(0, 2).map((c) => `Contact: ${c}`), readable ? 'The policy does not describe a reporting channel; security.txt lists a contact.' : 'No policy exists; security.txt lists a contact.')
    } else if (readable) {
      set(criterion, 'NOT_MET', 'VDP.NO_MATCH', [], 'The policy was read; no rule for this criterion matched.')
    } else {
      set(criterion, 'NOT_MET', 'VDP.NO_POLICY', [], 'No policy was found.')
    }
  }

  // CURRENT
  const statedLastUpdated = readable ? parseStatedLastUpdated(text) : undefined
  const asOfT = Date.parse(input.asOf)
  const expT = stxt.present && stxt.expires ? Date.parse(stxt.expires) : NaN
  const stxtValid = !Number.isNaN(expT) && expT >= asOfT
  const stxtExpired = !Number.isNaN(expT) && expT < asOfT
  const contradictoryExpires = stxt.warnings.some((w) => w.startsWith('CONTRADICTORY_EXPIRES'))
  const statedT = statedLastUpdated ? Date.parse(statedLastUpdated) : NaN
  const futureDate = !Number.isNaN(statedT) && statedT > asOfT
  const policyAgeDays = !Number.isNaN(statedT) && !futureDate ? (asOfT - statedT) / 86_400_000 : NaN
  const policyRecent = !Number.isNaN(policyAgeDays) && policyAgeDays <= params.vdpCurrentWithinDays
  const policyOld = !Number.isNaN(policyAgeDays) && policyAgeDays > params.vdpCurrentWithinDays
  const expQuote = stxt.expires ? [`Expires: ${stxt.expires}`] : []
  const dateQuote = statedLastUpdated ? [`Policy states last updated ${statedLastUpdated}`] : []
  if (stxtExpired) {
    if (policyRecent) set('CURRENT', 'PARTIAL', 'VDP.CURRENT.EXPIRED_POLICY_RECENT', [...expQuote, ...dateQuote], 'security.txt has expired; the policy states a recent update.')
    else set('CURRENT', 'NOT_MET', 'VDP.CURRENT.EXPIRED', [...expQuote, ...dateQuote], `security.txt Expires (${stxt.expires}) is before ${input.asOf}.`)
  } else if (stxtValid) {
    set('CURRENT', 'MET', 'VDP.CURRENT.STXT', expQuote)
  } else if (policyRecent) {
    set('CURRENT', 'MET', 'VDP.CURRENT.POLICY_DATE', dateQuote)
  } else if (contradictoryExpires) {
    set('CURRENT', 'UNKNOWN', 'VDP.CURRENT.STXT_CONTRADICTORY', [], 'security.txt states more than one different Expires date; its currency cannot be determined.')
  } else if (futureDate) {
    set('CURRENT', 'UNKNOWN', 'VDP.CURRENT.FUTURE_DATE', dateQuote, `The policy states a last-updated date after ${input.asOf}; the date is implausible and not counted.`)
  } else if (policyOld) {
    set('CURRENT', 'NOT_MET', 'VDP.CURRENT.POLICY_OLD', dateQuote, `The policy's stated update is more than ${params.vdpCurrentWithinDays} days before ${input.asOf}.`)
  } else if (!stxt.present && retrieval === 'NOT_FOUND' && !stxt.warnings.some((w) => w.startsWith('FETCH_FAILED'))) {
    set('CURRENT', 'NOT_MET', 'VDP.CURRENT.NONE', [], 'Neither a security.txt file nor a policy exists, so nothing is kept current.')
  } else {
    set('CURRENT', 'UNKNOWN', 'VDP.CURRENT.UNDATED', [], 'No security.txt Expires and no stated policy date.')
  }

  const obsPolicy: VdpObservation['policy'] = { found: policy.found, retrieval }
  if (policy.url) obsPolicy.url = policy.url
  if (policy.snapshotId) obsPolicy.snapshotId = policy.snapshotId
  if (readable) obsPolicy.textHash = sha256Text(text)
  if (text.length > 0) obsPolicy.wordCount = wordCount
  if (statedLastUpdated) obsPolicy.statedLastUpdated = statedLastUpdated
  if (policyHost) obsPolicy.host = policyHost

  return {
    vendorId: input.vendorId,
    observedAt: input.observedAt,
    securityTxt: stxt,
    policy: obsPolicy,
    criteria: VDP_CRITERIA.map((c) => results.get(c)!),
    prohibitive,
  }
}

/** Count of the four pledge elements in state MET. */
export function pledgeElementsMet(obs: VdpObservation): number {
  return obs.criteria.filter((c) => PLEDGE_VDP_CRITERIA.includes(c.criterion) && c.state === 'MET').length
}

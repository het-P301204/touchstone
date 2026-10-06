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
  /** Every group must have at least one phrase present in the sentence. */
  allOf: string[][]
  /** The rule does not fire on a sentence containing any of these. */
  noneOf: string[]
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

const NEGATIONS = ['not ', 'never', 'prohibit', "don't", 'do not', 'must not', 'may not', 'cannot', 'unauthoriz']

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
    allOf: [['do not test', 'must not test', 'may not test', 'not permitted to test', 'testing is prohibited', 'testing is not permitted', 'testing is not authorized', 'not authorized to test', 'prohibits testing', 'prohibit testing', 'prohibits any testing', 'no testing']],
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
    noneOf: ['not authoriz', 'not permit', 'not allowed', 'not limited to', 'prohibit'],
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
    noneOf: NEGATIONS,
  },
  // ---------------------------------------------------------------- safe harbor
  {
    id: 'VDP.SAFE_HARBOR.C1',
    criterion: 'GOOD_FAITH_SAFE_HARBOR',
    effect: 'CONTRADICTED',
    precedence: 100,
    description: 'The policy reserves or threatens legal action against researchers.',
    allOf: [
      [
        'reserve the right to pursue legal', 'reserves the right to pursue legal', 'reserve the right to take legal', 'reserves the right to take legal',
        'reserve the right to initiate legal', 'reserves the right to initiate legal', 'reserve all legal', 'reserves all legal', 'may pursue legal action',
        'may take legal action', 'may initiate legal action', 'will pursue legal action', 'will take legal action', 'may result in legal action',
        'will result in legal action', 'may be prosecuted', 'will be prosecuted', 'referred to law enforcement', 'criminal prosecution',
      ],
    ],
    noneOf: ['will not', "won't", 'not pursue', 'not take', 'not initiate'],
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
    noneOf: ['no safe harbor', 'no safe harbour', 'does not provide', 'not offer'],
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
        'public disclosure is not permitted', 'keep confidential', 'remain confidential', 'confidential indefinitely',
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
    noneOf: NEGATIONS,
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
    noneOf: ['never', 'indefinitely', 'without our written', 'without written', 'without prior written', 'not permitted', 'prohibit'],
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

function ruleMatch(rule: VdpRule, norm: string): number {
  for (const n of rule.noneOf) if (findPhrase(norm, n) >= 0) return -1
  let first = -1
  for (const group of rule.allOf) {
    let hit = -1
    for (const p of group) {
      const i = findPhrase(norm, p)
      if (i >= 0 && (hit < 0 || i < hit)) hit = i
    }
    if (hit < 0) return -1
    if (first < 0) first = hit
  }
  return first
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

export function assessVdp(input: Input): VdpObservation {
  const { securityTxt: stxt, policy, params } = input
  const text = policy.text === undefined ? '' : cleanText(policy.text).replace(/[ \t\f\v\r]+/g, ' ').replace(/ ?\n ?/g, '\n').trim()
  const readable = policy.found && !policy.fetchFailed && text.length > 0
  const unreadable = (policy.found && !readable) || (!policy.found && policy.fetchFailed === true)

  const sentences = readable ? splitSentences(text) : []
  const normalized = sentences.map(normalizeSentence)

  // Evaluate every text rule over every sentence.
  const hits = new Map<VdpCriterionId, { rule: VdpRule; quotes: string[] }[]>()
  const prohibitive: ProhibitiveFinding[] = []
  for (const rule of VDP_RULES) {
    const quotes: string[] = []
    for (let k = 0; k < normalized.length; k++) {
      const at = ruleMatch(rule, normalized[k]!)
      if (at < 0) continue
      const q = quoteOf(sentences[k]!, at)
      if (!quotes.includes(q)) quotes.push(q)
      if (rule.effect === 'CONTRADICTED' && prohibitive.length < 20 && !prohibitive.some((p) => p.ruleId === rule.id && p.quote === q)) {
        prohibitive.push({ ruleId: rule.id, quote: q, againstCriterion: rule.criterion })
      }
    }
    if (quotes.length > 0) {
      const list = hits.get(rule.criterion) ?? []
      list.push({ rule, quotes })
      hits.set(rule.criterion, list)
    }
  }

  const best = (criterion: VdpCriterionId) => {
    const list = hits.get(criterion)
    if (!list || list.length === 0) return undefined
    return [...list].sort((a, b) => b.rule.precedence - a.rule.precedence)[0]
  }

  const results = new Map<VdpCriterionId, CriterionResult>()
  const set = (criterion: VdpCriterionId, state: CriterionState, ruleId: string, quotes: string[], note?: string) => {
    const r: CriterionResult = { criterion, state, ruleId, quotes: quotes.slice(0, 2).map((q) => (q.length > MAX_QUOTE ? q.slice(0, MAX_QUOTE - 1) + '…' : q)) }
    if (note) r.note = note
    results.set(criterion, r)
  }

  // POLICY_DISCOVERABLE
  const policyHost = policy.host ?? hostOf(policy.url)
  if (readable) {
    const viaStxt = policy.url !== undefined && stxt.policyUrls.includes(policy.url)
    set('POLICY_DISCOVERABLE', 'MET', viaStxt ? 'VDP.DISCOVERABLE.STXT' : 'VDP.DISCOVERABLE.KNOWN', [viaStxt ? `Policy: ${policy.url}` : `Policy read from ${policy.url ?? policyHost ?? 'the registered URL'}`])
  } else if (unreadable) {
    set('POLICY_DISCOVERABLE', 'UNKNOWN', 'VDP.DISCOVERABLE.UNREADABLE', policy.url ? [`Policy URL: ${policy.url}`] : [], policy.fetchFailed ? 'The policy fetch failed; the policy may exist.' : 'The policy page had no readable text.')
  } else {
    set('POLICY_DISCOVERABLE', 'NOT_MET', 'VDP.DISCOVERABLE.NONE', [], 'No policy was found in security.txt, the registry, or on the vendor domain.')
  }

  // SECURITY_CONTACT
  const contactHit = best('SECURITY_CONTACT')
  if (stxt.present && stxt.contacts.length > 0) {
    set('SECURITY_CONTACT', 'MET', 'VDP.CONTACT.STXT', stxt.contacts.slice(0, 2).map((c) => `Contact: ${c}`))
  } else if (contactHit) {
    set('SECURITY_CONTACT', 'MET', contactHit.rule.id, contactHit.quotes)
  } else if (unreadable) {
    set('SECURITY_CONTACT', 'UNKNOWN', 'VDP.CONTACT.UNKNOWN', [], 'No security.txt Contact; the policy could not be read.')
  } else {
    set('SECURITY_CONTACT', 'NOT_MET', 'VDP.CONTACT.NONE', [])
  }

  // Text criteria.
  const textCriteria: VdpCriterionId[] = ['REPORTING_CHANNEL', 'TESTING_AUTHORIZED', 'GOOD_FAITH_SAFE_HARBOR', 'PUBLIC_DISCLOSURE_ALLOWED', 'SCOPE_DEFINED']
  for (const criterion of textCriteria) {
    const hit = best(criterion)
    const stxtContact = criterion === 'REPORTING_CHANNEL' && stxt.present && stxt.contacts.length > 0
    if (readable && hit) {
      const note =
        hit.rule.effect === 'CONTRADICTED' && (hits.get(criterion) ?? []).some((h) => h.rule.effect !== 'CONTRADICTED')
          ? 'The policy also contains supporting language; prohibitive language takes precedence.'
          : undefined
      set(criterion, hit.rule.effect, hit.rule.id, hit.quotes, note)
    } else if (stxtContact) {
      set(criterion, 'PARTIAL', 'VDP.REPORTING.STXT_ONLY', stxt.contacts.slice(0, 2).map((c) => `Contact: ${c}`), readable ? 'The policy does not describe a reporting channel; security.txt lists a contact.' : 'No readable policy; security.txt lists a contact.')
    } else if (readable) {
      set(criterion, 'NOT_MET', 'VDP.NO_MATCH', [], 'The policy was read; no rule for this criterion matched.')
    } else if (unreadable) {
      set(criterion, 'UNKNOWN', 'VDP.POLICY_UNREADABLE', [], policy.fetchFailed ? 'The policy fetch failed.' : 'The policy page had no readable text.')
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
  const policyAgeDays = statedLastUpdated ? (asOfT - Date.parse(statedLastUpdated)) / 86_400_000 : NaN
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
  } else if (policyOld) {
    set('CURRENT', 'NOT_MET', 'VDP.CURRENT.POLICY_OLD', dateQuote, `The policy's stated update is more than ${params.vdpCurrentWithinDays} days before ${input.asOf}.`)
  } else if (!stxt.present && !policy.found && !unreadable && !stxt.warnings.some((w) => w.startsWith('FETCH_FAILED'))) {
    set('CURRENT', 'NOT_MET', 'VDP.CURRENT.NONE', [], 'Neither a security.txt file nor a policy exists, so nothing is kept current.')
  } else {
    set('CURRENT', 'UNKNOWN', 'VDP.CURRENT.UNDATED', [], 'No security.txt Expires and no stated policy date.')
  }

  const obsPolicy: VdpObservation['policy'] = { found: policy.found }
  if (policy.url) obsPolicy.url = policy.url
  if (policy.snapshotId) obsPolicy.snapshotId = policy.snapshotId
  if (readable) {
    obsPolicy.textHash = sha256Text(text)
    obsPolicy.wordCount = text.split(/\s+/).filter((w) => w.length > 0).length
  }
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

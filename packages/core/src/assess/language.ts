/**
 * Measurement language. Text TOUCHSTONE writes about a vendor (status
 * reasons, anomaly headlines and details, benchmark wording, ranking notes)
 * never calls a vendor compliant, secure, insecure or failed, and never
 * alleges a violation. The quality gate scans generated text with this list.
 *
 * Matching is whole-word and case-insensitive. Hyphens separate words, so
 * "non-compliance", "compliance-ready" and "insecure-by-default" are caught.
 */

/** Judgement words that must not appear in generated vendor-facing text. */
export const BANNED_TERMS: string[] = [
  'compliant',
  'noncompliant',
  'compliance',
  'noncompliance',
  'secure',
  'insecure',
  'insecurely',
  'fail',
  'fails',
  'failed',
  'failing',
  'failure',
  'violate',
  'violates',
  'violated',
  'violation',
  'violations',
]

/** Proper names that contain a banned word and are allowed verbatim. */
const ALLOWED_PHRASES = [/secure by design/gi]

function isWordChar(c: string | undefined): boolean {
  return c !== undefined && /[A-Za-z0-9]/.test(c)
}

/** Banned terms found in `text` as whole words (case-insensitive; hyphens separate words). */
export function findBannedTerms(text: string): string[] {
  let t = text
  for (const re of ALLOWED_PHRASES) t = t.replace(re, ' ')
  const lower = t.toLowerCase()
  const found: string[] = []
  for (const term of BANNED_TERMS) {
    let i = lower.indexOf(term)
    while (i !== -1) {
      if (!isWordChar(lower[i - 1]) && !isWordChar(lower[i + term.length])) {
        found.push(term)
        break
      }
      i = lower.indexOf(term, i + 1)
    }
  }
  return found
}

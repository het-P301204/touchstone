/**
 * security.txt (RFC 9116) parser.
 *
 * A security.txt file is a contact pointer, not a disclosure policy. It
 * contributes the SECURITY_CONTACT criterion, a Policy: URL for discovery,
 * and an Expires: date for the CURRENT criterion. Every deviation from the
 * RFC is kept as a warning with a stable code prefix:
 *
 *   NO_CONTACT, NO_EXPIRES, MULTIPLE_EXPIRES, INVALID_EXPIRES, EXPIRED,
 *   EXPIRES_TOO_FAR, INSECURE_URI, BAD_CONTACT_URI, UNKNOWN_FIELD,
 *   MALFORMED_LINE, CANONICAL_MISMATCH, TRUNCATED, EMPTY
 */

import type { SecurityTxt } from '../model/index.ts'
import { cleanText } from '../util/sanitize.ts'

export const SECURITY_TXT_FIELDS: readonly string[] = [
  'acknowledgments',
  'canonical',
  'contact',
  'encryption',
  'expires',
  'hiring',
  'policy',
  'preferred-languages',
  'csaf', // registered by the OASIS CSAF standard
]

const MAX_LINES = 1_000
const MAX_LINE = 2_048
const MAX_VALUES = 50

/** RFC 3339 date-time (Expires must use it). */
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:[Zz]|[+-]\d{2}:\d{2})$/

function isUri(v: string): boolean {
  return /^[a-z][a-z0-9+.-]{0,20}:\S+$/i.test(v)
}

export function parseSecurityTxt(text: string, ctx: { url: string; snapshotId: string; asOf: string }): SecurityTxt {
  const result: SecurityTxt = {
    present: false,
    url: ctx.url,
    snapshotId: ctx.snapshotId,
    contacts: [],
    policyUrls: [],
    canonical: [],
    warnings: [],
    signed: false,
  }
  const warn = (w: string) => {
    if (result.warnings.length < 100) result.warnings.push(w)
  }
  const body = cleanText(text)
  if (body.trim().length === 0) {
    warn('EMPTY: the file is empty.')
    return result
  }

  // OpenPGP cleartext signature framing (RFC 4880 section 7).
  let lines = body.split(/\r\n|\r|\n/)
  if (lines.length > MAX_LINES) {
    warn(`TRUNCATED: only the first ${MAX_LINES} lines were read.`)
    lines = lines.slice(0, MAX_LINES)
  }
  const firstContent = lines.findIndex((l) => l.trim().length > 0)
  if (firstContent >= 0 && lines[firstContent]!.trim() === '-----BEGIN PGP SIGNED MESSAGE-----') {
    result.signed = true
    let i = firstContent + 1
    while (i < lines.length && lines[i]!.trim().length > 0) i++ // armor headers ("Hash: SHA256")
    const sigStart = lines.findIndex((l, k) => k > i && l.trim() === '-----BEGIN PGP SIGNATURE-----')
    lines = lines.slice(i + 1, sigStart < 0 ? lines.length : sigStart).map((l) => (l.startsWith('- ') ? l.slice(2) : l))
  }

  const expires: string[] = []
  let fields = 0
  for (const rawLine of lines) {
    const line = rawLine.length > MAX_LINE ? rawLine.slice(0, MAX_LINE) : rawLine
    const t = line.trim()
    if (t.length === 0 || t.startsWith('#')) continue
    const colon = t.indexOf(':')
    if (colon <= 0) {
      warn(`MALFORMED_LINE: "${t.slice(0, 80)}"`)
      continue
    }
    const name = t.slice(0, colon).trim().toLowerCase()
    const value = t.slice(colon + 1).trim()
    if (!/^[a-z0-9-]{1,40}$/.test(name)) {
      warn(`MALFORMED_LINE: "${t.slice(0, 80)}"`)
      continue
    }
    if (!SECURITY_TXT_FIELDS.includes(name)) {
      warn(`UNKNOWN_FIELD: "${name}"`)
      continue
    }
    fields++
    if (value.length === 0) {
      warn(`MALFORMED_LINE: empty ${name} value`)
      continue
    }
    switch (name) {
      case 'contact':
        if (!isUri(value)) warn(`BAD_CONTACT_URI: Contact "${value.slice(0, 80)}" is not a URI (mailto:, https: or tel:).`)
        else if (/^http:/i.test(value)) warn(`INSECURE_URI: Contact "${value.slice(0, 80)}" uses http.`)
        if (result.contacts.length < MAX_VALUES) result.contacts.push(value)
        break
      case 'policy':
        if (/^http:/i.test(value)) warn(`INSECURE_URI: Policy "${value.slice(0, 80)}" uses http.`)
        if (result.policyUrls.length < MAX_VALUES) result.policyUrls.push(value)
        break
      case 'canonical':
        if (result.canonical.length < MAX_VALUES) result.canonical.push(value)
        break
      case 'expires':
        expires.push(value)
        break
      default:
        break
    }
  }
  result.present = fields > 0
  if (!result.present) {
    warn('EMPTY: no RFC 9116 fields were found.')
    return result
  }

  if (result.contacts.length === 0) warn('NO_CONTACT: the required Contact field is missing.')
  if (expires.length === 0) warn('NO_EXPIRES: the required Expires field is missing.')
  if (expires.length > 1) warn(`MULTIPLE_EXPIRES: Expires appears ${expires.length} times; the first is used.`)
  const exp = expires[0]
  if (exp !== undefined) {
    const t = RFC3339.test(exp) ? Date.parse(exp) : NaN
    if (Number.isNaN(t)) {
      warn(`INVALID_EXPIRES: "${exp.slice(0, 60)}" is not an RFC 3339 date-time.`)
    } else {
      result.expires = new Date(t).toISOString()
      const asOf = Date.parse(ctx.asOf)
      if (!Number.isNaN(asOf)) {
        if (t < asOf) warn(`EXPIRED: Expires ${result.expires} is before ${new Date(asOf).toISOString()}.`)
        else if (t - asOf > 366 * 86_400_000) warn(`EXPIRES_TOO_FAR: Expires ${result.expires} is more than a year ahead (RFC 9116 recommends less).`)
      }
    }
  }
  if (result.canonical.length > 0 && !result.canonical.includes(ctx.url)) {
    warn(`CANONICAL_MISMATCH: fetched from ${ctx.url}, Canonical lists ${result.canonical.slice(0, 3).join(', ')}.`)
  }
  return result
}

/** True when security.txt has an Expires date before asOf. */
export function securityTxtExpired(s: SecurityTxt, asOf: string): boolean {
  if (!s.present || !s.expires) return false
  const t = Date.parse(s.expires)
  const a = Date.parse(asOf)
  return !Number.isNaN(t) && !Number.isNaN(a) && t < a
}

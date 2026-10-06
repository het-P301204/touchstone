/**
 * Small helpers for reading untrusted parsed JSON without trusting its shape.
 *
 * Every accessor checks own properties only, so a document carrying
 * `__proto__`, `constructor` or `toString` keys can never make a lookup
 * resolve to something inherited from Object.prototype.
 */

export type JsonObject = Record<string, unknown>

export function isObject(v: unknown): v is JsonObject {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Own property or undefined. */
export function own(o: unknown, key: string): unknown {
  if (!isObject(o)) return undefined
  return Object.hasOwn(o, key) ? o[key] : undefined
}

export function str(o: unknown, key: string): string | undefined {
  const v = own(o, key)
  return typeof v === 'string' ? v : undefined
}

export function num(o: unknown, key: string): number | undefined {
  const v = own(o, key)
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined
}

/** Own array property, truncated to `max` elements (defence against oversized documents). */
export function arr(o: unknown, key: string, max = 10_000): unknown[] {
  const v = own(o, key)
  if (!Array.isArray(v)) return []
  return v.length > max ? v.slice(0, max) : v
}

/** Maximum nesting accepted in a source document. CVE JSON needs well under 20 levels. */
export const MAX_JSON_DEPTH = 256

export class JsonTooDeepError extends Error {
  constructor() {
    super(`document nested deeper than ${MAX_JSON_DEPTH} levels`)
    this.name = 'JsonTooDeepError'
  }
}

/** Nesting depth of a parsed JSON value, computed iteratively; stops counting past `limit`. */
export function jsonDepth(v: unknown, limit = MAX_JSON_DEPTH): number {
  let max = 0
  const stack: [unknown, number][] = [[v, 0]]
  while (stack.length > 0) {
    const [x, d] = stack.pop()!
    if (x === null || typeof x !== 'object') continue
    const depth = d + 1
    if (depth > max) max = depth
    if (max > limit) return max
    for (const child of Array.isArray(x) ? x : Object.values(x as JsonObject)) if (child !== null && typeof child === 'object') stack.push([child, depth])
  }
  return max
}

/**
 * Canonical JSON: sorted object keys, no whitespace. Used for content hashes of source records.
 * Throws JsonTooDeepError beyond MAX_JSON_DEPTH levels instead of overflowing the stack.
 */
export function canonicalStringify(v: unknown, depth = 0): string {
  if (v === null || typeof v !== 'object') {
    if (typeof v === 'number' && !Number.isFinite(v)) return 'null'
    if (v === undefined) return 'null'
    return JSON.stringify(v)
  }
  if (depth >= MAX_JSON_DEPTH) throw new JsonTooDeepError()
  if (Array.isArray(v)) return '[' + v.map((x) => canonicalStringify(x, depth + 1)).join(',') + ']'
  const o = v as JsonObject
  const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort()
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalStringify(o[k], depth + 1)).join(',') + '}'
}

/** ISO-8601 timestamp check (date, or date-time with optional fraction and zone). */
const ISO_DATE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/

/** Returns a normalized ISO string (UTC, ms precision) or undefined when absent or unparseable. */
export function isoDate(v: unknown): string | undefined {
  if (typeof v !== 'string' || v.length > 40) return undefined
  const s = v.trim()
  if (!ISO_DATE.test(s)) return undefined
  // Reject impossible calendar values instead of letting Date roll them over (2026-02-30 -> 2026-03-02).
  const y = Number(s.slice(0, 4))
  const mo = Number(s.slice(5, 7))
  const d = Number(s.slice(8, 10))
  if (mo < 1 || mo > 12 || d < 1 || d > new Date(Date.UTC(y, mo, 0)).getUTCDate()) return undefined
  const time = /[T ](\d{2}):(\d{2})(?::(\d{2}))?/.exec(s)
  if (time && (Number(time[1]) > 23 || Number(time[2]) > 59 || Number(time[3] ?? 0) > 59)) return undefined
  const zone = /([+-])(\d{2}):?(\d{2})$/.exec(s.length > 10 ? s.slice(10) : '')
  if (zone && (Number(zone[2]) > 23 || Number(zone[3]) > 59)) return undefined
  // A date-time without a zone is read as UTC: CVE timestamps are UTC by schema.
  const withZone = /[T ]\d{2}:\d{2}/.test(s) && !/(?:Z|[+-]\d{2}:?\d{2})$/.test(s) ? s.replace(' ', 'T') + 'Z' : s.replace(' ', 'T')
  const t = Date.parse(withZone)
  if (Number.isNaN(t)) return undefined
  return new Date(t).toISOString()
}

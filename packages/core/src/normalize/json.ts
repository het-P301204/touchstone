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

/** Canonical JSON: sorted object keys, no whitespace. Used for content hashes of source records. */
export function canonicalStringify(v: unknown): string {
  if (v === null || typeof v !== 'object') {
    if (typeof v === 'number' && !Number.isFinite(v)) return 'null'
    if (v === undefined) return 'null'
    return JSON.stringify(v)
  }
  if (Array.isArray(v)) return '[' + v.map((x) => canonicalStringify(x)).join(',') + ']'
  const o = v as JsonObject
  const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort()
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalStringify(o[k])).join(',') + '}'
}

/** ISO-8601 timestamp check (date, or date-time with optional fraction and zone). */
const ISO_DATE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/

/** Returns a normalized ISO string (UTC, ms precision) or undefined when absent or unparseable. */
export function isoDate(v: unknown): string | undefined {
  if (typeof v !== 'string' || v.length > 40) return undefined
  const s = v.trim()
  if (!ISO_DATE.test(s)) return undefined
  // A date-time without a zone is read as UTC: CVE timestamps are UTC by schema.
  const withZone = /[T ]\d{2}:\d{2}/.test(s) && !/(?:Z|[+-]\d{2}:?\d{2})$/.test(s) ? s.replace(' ', 'T') + 'Z' : s.replace(' ', 'T')
  const t = Date.parse(withZone)
  if (Number.isNaN(t)) return undefined
  return new Date(t).toISOString()
}

/**
 * Canonical JSON: object keys sorted by UTF-16 code unit order, no
 * whitespace, `undefined` object members omitted, `undefined` array members
 * written as null. Numbers and strings are serialized exactly as
 * JSON.stringify does (so NaN and Infinity become null; the quality gate
 * checks separately that no output number is non-finite).
 *
 * Every hash in TOUCHSTONE (inputsHash, outputsHash, evidence ids) is a
 * sha256 over this form, so it must never depend on insertion order.
 */
export function canonicalJson(v: unknown): string {
  return write(v)
}

function write(v: unknown): string {
  if (v === null) return 'null'
  switch (typeof v) {
    case 'string':
      return JSON.stringify(v)
    case 'number':
      return JSON.stringify(v)
    case 'boolean':
      return v ? 'true' : 'false'
    case 'bigint':
      return v.toString()
    case 'undefined':
    case 'function':
    case 'symbol':
      return 'null'
    default:
      break
  }
  if (Array.isArray(v)) {
    let out = '['
    for (let i = 0; i < v.length; i++) {
      if (i > 0) out += ','
      out += write(v[i])
    }
    return `${out}]`
  }
  const obj = v as Record<string, unknown>
  const keys = Object.keys(obj).sort()
  let out = '{'
  let first = true
  for (const k of keys) {
    const val = obj[k]
    if (val === undefined || typeof val === 'function' || typeof val === 'symbol') continue
    if (!first) out += ','
    first = false
    out += `${JSON.stringify(k)}:${write(val)}`
  }
  return `${out}}`
}

/** Every number reachable from `v` is finite. */
export function allNumbersFinite(v: unknown): boolean {
  if (typeof v === 'number') return Number.isFinite(v)
  if (v === null || typeof v !== 'object') return true
  if (Array.isArray(v)) return v.every(allNumbersFinite)
  return Object.values(v as Record<string, unknown>).every(allNumbersFinite)
}

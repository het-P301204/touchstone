/**
 * CISA Secure by Design Pledge signer list.
 *
 * The page (https://www.cisa.gov/securebydesign/pledge/secure-design-pledge-signers)
 * states a count in a heading ("387 Companies") followed by a table with one
 * company name per cell. The declared count and the parsed count are both
 * kept; a mismatch is a warning, never silently reconciled.
 */

import { htmlToText } from '../text/html.ts'

const HEADING = /<h([1-6])\b[^>]*>\s*([0-9][0-9,]{0,8})\s+Companies\s*<\/h\1\s*>/i

/** Lower-cases ASCII letters only, so indexes stay aligned with the original string. */
function asciiLower(s: string): string {
  return s.replace(/[A-Z]+/g, (m) => m.toLowerCase())
}

/**
 * Monotonic indexOf: queries for the same needle must use non-decreasing
 * `from` values, and each needle's search resumes where the last one ended,
 * so scanning a whole document for several markers stays linear.
 */
function cursor(hay: string) {
  const cache = new Map<string, number>()
  return (needle: string, from: number): number => {
    const c = cache.get(needle)
    if (c !== undefined && (c < 0 || c >= from)) return c
    const k = hay.indexOf(needle, from)
    cache.set(needle, k)
    return k
  }
}

/** Cell texts of every <td>/<th> in the slice. Linear in the slice length. */
function cellTexts(src: string): string[] {
  const out: string[] = []
  const lower = asciiLower(src)
  const next = cursor(lower)
  const isBoundary = (c: number) => c === 0x3e || c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d || c === 0x2f
  let i = 0
  for (;;) {
    const td = next('<td', i)
    const th = next('<th', i)
    const open = td < 0 ? th : th < 0 ? td : Math.min(td, th)
    if (open < 0) break
    // Must be exactly <td or <th followed by whitespace, ">" or "/" (not <thead>).
    if (!isBoundary(lower.charCodeAt(open + 3))) {
      i = open + 3
      continue
    }
    const gt = next('>', open)
    if (gt < 0) break
    // Content ends at the next cell, row or table boundary.
    let end = lower.length
    for (const marker of ['</td', '</th', '<td', '<th', '</tr', '<tr', '</table']) {
      const k = next(marker, gt + 1)
      if (k >= 0 && k < end) end = k
    }
    out.push(htmlToText(src.slice(gt + 1, end)).text.replace(/\s+/g, ' ').trim())
    i = end
  }
  return out
}

export function parseSignerList(html: string): { declaredCount: number | null; names: string[]; warnings: string[] } {
  const warnings: string[] = []
  const m = HEADING.exec(html)
  let declaredCount: number | null = null
  let tableFrom = 0
  if (m) {
    declaredCount = Number(m[2]!.replace(/,/g, ''))
    tableFrom = m.index + m[0].length
  } else {
    warnings.push('NO_DECLARED_COUNT: no "<N> Companies" heading found; the declared count is unknown.')
  }
  const lower = asciiLower(html)
  const tableStart = lower.indexOf('<table', tableFrom)
  if (tableStart < 0) {
    warnings.push('NO_TABLE: no signer table found.')
    return { declaredCount, names: [], warnings }
  }
  const tableEndIdx = lower.indexOf('</table', tableStart)
  const tableEnd = tableEndIdx < 0 ? html.length : tableEndIdx
  if (tableEndIdx < 0) warnings.push('UNTERMINATED_TABLE: the signer table is not closed.')

  const names: string[] = []
  const seen = new Set<string>()
  for (const cell of cellTexts(html.slice(tableStart, tableEnd))) {
    if (cell.length === 0) continue
    if (cell.length > 200) {
      warnings.push(`LONG_CELL: a cell of ${cell.length} characters was skipped.`)
      continue
    }
    const key = cell.toLowerCase()
    if (seen.has(key)) {
      warnings.push(`DUPLICATE_NAME: "${cell}" is listed more than once.`)
      continue
    }
    seen.add(key)
    names.push(cell)
  }
  if (declaredCount !== null && declaredCount !== names.length) {
    warnings.push(`COUNT_MISMATCH: the page declares ${declaredCount} companies; ${names.length} names were parsed.`)
  }
  return { declaredCount, names, warnings }
}

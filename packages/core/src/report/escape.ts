/**
 * Escaping for exported text. Every string that came from a source (vendor
 * names, CVE titles, policy quotes, dispute statements) is untrusted:
 *   - invisible and bidirectional control characters are stripped (Trojan Source)
 *   - a CSV cell a spreadsheet would execute (leading = + - @ tab CR, their
 *     full-width forms, or whitespace then = + - @) is prefixed with '
 *   - Markdown inline text escapes the characters that create links, images,
 *     HTML, emphasis and table cells (|), and newlines collapse to spaces
 */

import { cleanText } from '../util/sanitize.ts'

const FULLWIDTH_TRIGGERS = new Set([0xff1d, 0xff0b, 0xff0d, 0xff20]) // ＝ ＋ － ＠

function needsFormulaGuard(x: string): boolean {
  if (x.length === 0) return false
  const c = x.charCodeAt(0)
  if (c === 0x3d || c === 0x2b || c === 0x2d || c === 0x40 || c === 0x09 || c === 0x0d) return true
  if (FULLWIDTH_TRIGGERS.has(c)) return true
  const trimmed = x.trimStart()
  if (trimmed.length !== x.length && trimmed.length > 0) {
    const t = trimmed.charCodeAt(0)
    return t === 0x3d || t === 0x2b || t === 0x2d || t === 0x40 || FULLWIDTH_TRIGGERS.has(t)
  }
  return false
}

/** One CSV cell. Numbers are written as numbers (a number cannot be a formula); strings are guarded and quoted. */
export function csvCell(v: unknown): string {
  if (typeof v === 'number') return Number.isFinite(v) ? String(v) : ''
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  let x = cleanText(v === null || v === undefined ? '' : String(v))
  if (needsFormulaGuard(x)) x = `'${x}`
  return /[",\n\r]/.test(x) ? `"${x.replace(/"/g, '""')}"` : x
}

export function csvRow(cells: unknown[]): string {
  return cells.map(csvCell).join(',')
}

/** Escape inline Markdown so source text cannot create links, images, HTML, emphasis or table cells. */
export function mdInline(v: string): string {
  return cleanText(v)
    .replace(/[\\`*_{}[\]()<>#+!|&~]/g, (c) => `\\${c}`)
    .replace(/\r\n|\r|\n/g, ' ')
}

/** A Markdown table cell: inline-escaped, whitespace collapsed, never empty. */
export function mdCell(v: string): string {
  return mdInline(v).replace(/\s+/g, ' ').trim() || ' '
}

export function mdCode(v: string): string {
  const text = cleanText(v).replace(/\r\n?/g, '\n')
  const fence = '`'.repeat(Math.max(3, ...[...text.matchAll(/`+/g)].map((m) => m[0].length + 1)))
  return `${fence}text\n${text}\n${fence}`
}

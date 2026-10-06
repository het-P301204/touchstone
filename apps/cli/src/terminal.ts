/**
 * Terminal safety and styling.
 *
 * Every string that came from data (vendor names, CVE titles, policy quotes,
 * dispute statements, run ids read from a bundle) passes through `term()` or
 * `termDocument()` before it is printed. An ESC or C1 control character in a
 * vendor name could otherwise rewrite the reader's terminal (move the cursor,
 * recolour, hide lines, set the window title), and bidi overrides could make
 * text read differently from what it contains.
 *
 * Code point sets are built with String.fromCodePoint, never typed literally.
 */
import { cleanText } from '../../../packages/core/src/util/sanitize.ts'

const cp = (n: number) => String.fromCodePoint(n)
const range = (a: number, b: number) => `${cp(a)}-${cp(b)}`

/** C0 controls (all, including TAB/LF/CR), DEL and C1 controls. */
const CONTROL = new RegExp(`[${range(0x00, 0x1f)}${range(0x7f, 0x9f)}]`, 'gu')
/** C0 except LF and TAB, DEL and C1: for multi-line documents (Markdown, CSV). */
const CONTROL_KEEP_LINES = new RegExp(`[${range(0x00, 0x08)}${range(0x0b, 0x1f)}${range(0x7f, 0x9f)}]`, 'gu')
/** Characters JSON.stringify leaves raw that a terminal or viewer may act on: C1, bidi, zero-width, separators. */
const JSON_UNSAFE = new RegExp(`[${range(0x7f, 0x9f)}${cp(0x061c)}${cp(0x180e)}${range(0x200b, 0x200f)}${range(0x2028, 0x202e)}${range(0x2066, 0x2069)}${cp(0xfeff)}]`, 'gu')

/** One line of data-derived text, safe to print: no controls, no newlines, no bidi or invisible characters. */
export function term(s: unknown): string {
  return cleanText(String(s ?? '')).replace(CONTROL, ' ')
}

/** A multi-line document (Markdown, CSV) for a terminal: keeps LF/TAB, removes every other control and invisible character. */
export function termDocument(s: string): string {
  return cleanText(s.replace(/\r\n/g, '\n')).replace(CONTROL_KEEP_LINES, '')
}

/** Escape characters JSON leaves raw (C1, bidi, invisible) as \u escapes. The result is equivalent JSON. */
export function jsonSafe(json: string): string {
  return json.replace(JSON_UNSAFE, (ch) => `\\u${ch.codePointAt(0)!.toString(16).padStart(4, '0')}`)
}

export type Style = {
  bold(s: string): string
  dim(s: string): string
  red(s: string): string
  yellow(s: string): string
  green(s: string): string
}

const ESC = cp(0x1b)
const wrap = (open: number, close: number) => (s: string) => `${ESC}[${open}m${s}${ESC}[${close}m`

export function style(enabled: boolean): Style {
  if (!enabled) {
    const id = (s: string) => s
    return { bold: id, dim: id, red: id, yellow: id, green: id }
  }
  return { bold: wrap(1, 22), dim: wrap(2, 22), red: wrap(31, 39), yellow: wrap(33, 39), green: wrap(32, 39) }
}

/** Colour only for an interactive terminal, and never when NO_COLOR is set (https://no-color.org). */
export function colorEnabled(stream: { isTTY?: boolean }, env: NodeJS.ProcessEnv, flagOff: boolean): boolean {
  if (flagOff) return false
  if (env['NO_COLOR'] !== undefined && env['NO_COLOR'] !== '') return false
  if (env['FORCE_COLOR'] !== undefined && env['FORCE_COLOR'] !== '' && env['FORCE_COLOR'] !== '0') return true
  return !!stream.isTTY && env['TERM'] !== 'dumb'
}

/** Pad to a visible width (input must already be control-free). */
export function pad(s: string, width: number): string {
  const len = [...s].length
  return len >= width ? s : s + ' '.repeat(width - len)
}

/** Greedy word wrap for plain text (input must already be control-free). */
export function wrapText(s: string, width: number, indent = ''): string {
  const words = s.split(/\s+/).filter(Boolean)
  const lines: string[] = []
  let line = ''
  for (const w of words) {
    if (line && [...line].length + 1 + [...w].length > width) {
      lines.push(indent + line)
      line = w
    } else line = line ? `${line} ${w}` : w
  }
  if (line) lines.push(indent + line)
  return lines.join('\n')
}

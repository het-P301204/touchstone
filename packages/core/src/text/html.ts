/**
 * Hardened HTML-to-text.
 *
 * Policy pages and the signer list are untrusted HTML. This extractor is a
 * single forward scan: every character of the input is examined a bounded
 * number of times, so run time is linear in the input length whatever the
 * nesting depth or malformation (1 MB of "<" characters, unterminated
 * comments, unclosed attributes). There is no DOM, no regex over the whole
 * document, no recursion, and nothing is ever executed or fetched.
 *
 *  - script, style, noscript, template, iframe, object, svg, math, head
 *    content is dropped;
 *  - comments, doctype and processing instructions are dropped;
 *  - block-level elements and <br> become line breaks (sentence boundaries);
 *  - entities are decoded (named subset, decimal, hex); invalid code points
 *    become U+FFFD;
 *  - invisible / bidi / control characters are removed (stripInvisible);
 *  - whitespace is collapsed; lines are trimmed and empty lines dropped.
 */

import { stripInvisible } from '../util/sanitize.ts'

/** Elements whose content is dropped entirely. */
const DROP_CONTENT = new Set(['script', 'style', 'noscript', 'template', 'iframe', 'object', 'svg', 'math', 'head', 'textarea', 'select'])

/** Elements that end a line (sentence boundary). */
const BLOCK = new Set([
  'address', 'article', 'aside', 'blockquote', 'br', 'caption', 'dd', 'details', 'dialog', 'div', 'dl', 'dt',
  'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hr',
  'li', 'main', 'nav', 'ol', 'p', 'pre', 'section', 'summary', 'table', 'tbody', 'td', 'tfoot', 'th',
  'thead', 'title', 'tr', 'ul', 'body', 'html',
])

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ensp: ' ', emsp: ' ', thinsp: ' ',
  ndash: '–', mdash: '—', lsquo: '‘', rsquo: '’', sbquo: '‚', ldquo: '“', rdquo: '”', bdquo: '„',
  hellip: '…', copy: '©', reg: '®', trade: '™', middot: '·', bull: '•', laquo: '«', raquo: '»',
  sect: '§', para: '¶', deg: '°', euro: '€', pound: '£', yen: '¥', cent: '¢', times: '×', divide: '÷',
  shy: '', zwj: '', zwnj: '', lrm: '', rlm: '',
  eacute: 'é', egrave: 'è', ecirc: 'ê', aacute: 'á', agrave: 'à', acirc: 'â', auml: 'ä', ouml: 'ö',
  uuml: 'ü', szlig: 'ß', ccedil: 'ç', ntilde: 'ñ', oacute: 'ó', iacute: 'í', uacute: 'ú',
}

function isNameChar(c: number): boolean {
  return (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39) || c === 0x2d || c === 0x5f || c === 0x3a
}

function isAlpha(c: number): boolean {
  return (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a)
}

function isSpaceCode(c: number): boolean {
  return (
    c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d || c === 0x0c || c === 0xa0 || c === 0x1680 ||
    (c >= 0x2000 && c <= 0x200a) || c === 0x202f || c === 0x205f || c === 0x3000
  )
}

/**
 * Decode character references in a text run. Linear: each "&" looks ahead at
 * most 34 characters.
 */
export function decodeEntities(s: string): string {
  if (s.indexOf('&') < 0) return s
  let out = ''
  let last = 0
  let i = s.indexOf('&')
  while (i >= 0) {
    let decoded: string | null = null
    let end = i
    if (s.charCodeAt(i + 1) === 0x23 /* # */) {
      const hex = s.charCodeAt(i + 2) === 0x78 || s.charCodeAt(i + 2) === 0x58
      let j = i + (hex ? 3 : 2)
      const start = j
      while (j < s.length && j - start < 8) {
        const c = s.charCodeAt(j)
        const ok = hex ? (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66) || (c >= 0x41 && c <= 0x46) : c >= 0x30 && c <= 0x39
        if (!ok) break
        j++
      }
      if (j > start) {
        const cp = parseInt(s.slice(start, j), hex ? 16 : 10)
        const valid = cp > 0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff)
        decoded = String.fromCodePoint(valid ? cp : 0xfffd)
        end = s.charCodeAt(j) === 0x3b ? j + 1 : j
      }
    } else {
      let j = i + 1
      while (j < s.length && j - i <= 32 && isAlpha(s.charCodeAt(j))) j++
      if (j > i + 1 && s.charCodeAt(j) === 0x3b) {
        const name = s.slice(i + 1, j)
        const v = Object.hasOwn(NAMED_ENTITIES, name) ? NAMED_ENTITIES[name] : Object.hasOwn(NAMED_ENTITIES, name.toLowerCase()) ? NAMED_ENTITIES[name.toLowerCase()] : undefined
        if (v !== undefined) {
          decoded = v
          end = j + 1
        }
      }
    }
    if (decoded !== null) {
      out += s.slice(last, i) + decoded
      last = end
      i = s.indexOf('&', end)
    } else {
      i = s.indexOf('&', i + 1)
    }
  }
  return out + s.slice(last)
}

class TextWriter {
  out = ''
  pendingSpace = false
  pendingBreak = false
  max: number
  truncated = false
  constructor(max: number) {
    this.max = max
  }
  text(s: string): void {
    if (this.truncated) return
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i)
      if (isSpaceCode(c)) {
        this.pendingSpace = true
        continue
      }
      if (this.out.length > 0) {
        if (this.pendingBreak) this.out += '\n'
        else if (this.pendingSpace) this.out += ' '
      }
      this.pendingBreak = false
      this.pendingSpace = false
      if (this.out.length >= this.max) {
        this.truncated = true
        return
      }
      this.out += s[i]
    }
  }
  brk(): void {
    this.pendingBreak = true
  }
}

/** Index just after the next unquoted ">" at or after `from`, or -1. Linear in the distance scanned. */
function tagEnd(html: string, from: number): number {
  let quote = 0
  for (let j = from; j < html.length; j++) {
    const c = html.charCodeAt(j)
    if (quote !== 0) {
      if (c === quote) quote = 0
    } else if (c === 0x22 || c === 0x27) {
      quote = c
    } else if (c === 0x3e) {
      return j + 1
    }
  }
  return -1
}

/** Index of the start of the closing tag `</name` (case-insensitive) at or after `from`, or -1. */
function findClose(html: string, from: number, name: string): number {
  let i = html.indexOf('<', from)
  while (i >= 0) {
    if (html.charCodeAt(i + 1) === 0x2f) {
      let k = 0
      while (k < name.length && (html.charCodeAt(i + 2 + k) | 0x20) === name.charCodeAt(k)) k++
      if (k === name.length && !isNameChar(html.charCodeAt(i + 2 + k))) return i
    }
    i = html.indexOf('<', i + 1)
  }
  return -1
}

export function htmlToText(html: string, opts?: { maxChars?: number }): { text: string; truncated: boolean } {
  const max = Math.max(0, opts?.maxChars ?? 500_000)
  const w = new TextWriter(max)
  const n = html.length
  let i = 0
  let runStart = 0
  const flush = (end: number) => {
    if (end > runStart) w.text(decodeEntities(html.slice(runStart, end)))
  }

  while (i < n && !w.truncated) {
    const lt = html.indexOf('<', i)
    if (lt < 0) break
    const next = html.charCodeAt(lt + 1)
    // Comment.
    if (next === 0x21 /* ! */ && html.startsWith('<!--', lt)) {
      flush(lt)
      const end = html.indexOf('-->', lt + 4)
      i = runStart = end < 0 ? n : end + 3
      continue
    }
    // Doctype, CDATA, processing instruction.
    if (next === 0x21 || next === 0x3f /* ? */) {
      flush(lt)
      const end = html.indexOf('>', lt + 2)
      i = runStart = end < 0 ? n : end + 1
      continue
    }
    const closing = next === 0x2f
    const nameStart = closing ? lt + 2 : lt + 1
    if (!isAlpha(html.charCodeAt(nameStart))) {
      // A literal "<" in text ("a < b", "<<<"). Keep it as text.
      i = lt + 1
      continue
    }
    flush(lt)
    let j = nameStart
    while (j < n && j - nameStart < 32 && isNameChar(html.charCodeAt(j))) j++
    const name = html.slice(nameStart, j).toLowerCase()
    const end = tagEnd(html, j)
    if (end < 0) {
      // Unterminated tag: everything after it is attribute soup, not text.
      runStart = n
      break
    }
    i = runStart = end
    // Block elements end a line; inline elements (a, b, span, ...) add nothing, as in a browser.
    if (BLOCK.has(name)) w.brk()
    if (!closing && DROP_CONTENT.has(name) && html.charCodeAt(end - 2) !== 0x2f) {
      const close = findClose(html, end, name)
      if (close < 0) {
        runStart = n
        break
      }
      const closeEnd = tagEnd(html, close + 2)
      i = runStart = closeEnd < 0 ? n : closeEnd
      w.brk()
    }
  }
  if (!w.truncated) flush(n)

  const { text } = stripInvisible(w.out)
  return { text, truncated: w.truncated }
}

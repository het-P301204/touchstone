/**
 * A small, dependency-free PDF 1.4 writer for the vendor report.
 *
 * It uses the three standard Type 1 fonts every PDF reader ships
 * (Helvetica, Helvetica-Bold, Courier) with WinAnsi encoding, so the file
 * embeds no fonts and needs no third-party library. Characters outside
 * WinAnsi are transliterated (→ to ->) or replaced with '?'. Content streams
 * are uncompressed and the creation date comes from the run's asOf, so the
 * output is deterministic and easy to audit.
 */

import { cleanText } from '../util/sanitize.ts'
import type { Block } from './document.ts'

const PAGE_W = 595.28
const PAGE_H = 841.89
const MARGIN_X = 50
const MARGIN_TOP = 60
const MARGIN_BOTTOM = 60
const CONTENT_W = PAGE_W - MARGIN_X * 2

/* Helvetica advance widths (1/1000 em) for printable ASCII 32..126 (Adobe AFM). */
const HELV = [
  278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
  1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
  333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
]

type Font = 'F1' | 'F2' | 'F3'

function charWidth(code: number, font: Font): number {
  if (font === 'F3') return 600
  const w = code >= 32 && code <= 126 ? HELV[code - 32]! : 556
  return font === 'F2' ? w * 1.06 : w
}

function textWidth(bytes: number[], font: Font, size: number): number {
  let w = 0
  for (const b of bytes) w += charWidth(b, font)
  return (w / 1000) * size
}

/* ---------------------------------------------------------- WinAnsi encoding */

const WIN_ANSI_EXTRA: Record<number, number> = {
  0x20ac: 0x80, 0x201a: 0x82, 0x0192: 0x83, 0x201e: 0x84, 0x2026: 0x85, 0x2020: 0x86, 0x2021: 0x87, 0x02c6: 0x88, 0x2030: 0x89,
  0x0160: 0x8a, 0x2039: 0x8b, 0x0152: 0x8c, 0x017d: 0x8e, 0x2018: 0x91, 0x2019: 0x92, 0x201c: 0x93, 0x201d: 0x94, 0x2022: 0x95,
  0x2013: 0x96, 0x2014: 0x97, 0x02dc: 0x98, 0x2122: 0x99, 0x0161: 0x9a, 0x203a: 0x9b, 0x0153: 0x9c, 0x017e: 0x9e, 0x0178: 0x9f,
}
const TRANSLIT: Record<number, string> = {
  0x2192: '->', 0x2190: '<-', 0x2193: 'v', 0x2191: '^', 0x2264: '<=', 0x2265: '>=', 0x2260: '<>', 0x2212: '-', 0x2248: '~',
}

export function encodeWinAnsi(text: string): number[] {
  const out: number[] = []
  for (const ch of cleanText(text)) {
    const cp = ch.codePointAt(0)!
    if (cp === 9 || cp === 10 || cp === 13) out.push(32)
    else if (cp >= 32 && cp <= 126) out.push(cp)
    else if (cp >= 0xa0 && cp <= 0xff) out.push(cp)
    else if (WIN_ANSI_EXTRA[cp] !== undefined) out.push(WIN_ANSI_EXTRA[cp]!)
    else if (TRANSLIT[cp] !== undefined) for (const c of TRANSLIT[cp]!) out.push(c.charCodeAt(0))
    else if (cp >= 32) out.push(63)
  }
  return out
}

function pdfString(bytes: number[]): string {
  let s = '('
  for (const b of bytes) {
    if (b === 0x28 || b === 0x29 || b === 0x5c) s += `\\${String.fromCharCode(b)}`
    else if (b < 32 || b > 126) s += `\\${b.toString(8).padStart(3, '0')}`
    else s += String.fromCharCode(b)
  }
  return `${s})`
}

/** Greedy word wrap on encoded bytes; long tokens are hard-broken. */
function wrap(text: string, font: Font, size: number, width: number): number[][] {
  const lines: number[][] = []
  for (const para of text.split('\n')) {
    const words = para.split(/(\s+)/).filter((w) => w.length > 0)
    let line: number[] = []
    for (const w of words) {
      if (/^\s+$/.test(w)) {
        if (line.length) line.push(32)
        continue
      }
      const wb = encodeWinAnsi(w)
      if (textWidth([...line, ...wb], font, size) <= width) {
        line.push(...wb)
        continue
      }
      if (line.length) {
        while (line.length && line[line.length - 1] === 32) line.pop()
        lines.push(line)
      }
      let chunk: number[] = []
      for (const ch of wb) {
        if (chunk.length && textWidth([...chunk, ch], font, size) > width) {
          lines.push(chunk)
          chunk = []
        }
        chunk.push(ch)
      }
      line = chunk
    }
    while (line.length && line[line.length - 1] === 32) line.pop()
    lines.push(line)
  }
  return lines
}

/* ------------------------------------------------------------------- layout */

type Page = { ops: string[] }

class Layout {
  pages: Page[] = []
  y = 0
  constructor() {
    this.newPage()
  }
  get page(): Page {
    return this.pages[this.pages.length - 1]!
  }
  newPage(): void {
    this.pages.push({ ops: [] })
    this.y = PAGE_H - MARGIN_TOP
  }
  ensure(h: number): void {
    if (this.y - h < MARGIN_BOTTOM) this.newPage()
  }
  text(x: number, y: number, bytes: number[], font: Font, size: number, gray = 0.12): void {
    this.page.ops.push(`${gray} g BT /${font} ${size} Tf ${x.toFixed(2)} ${y.toFixed(2)} Td ${pdfString(bytes)} Tj ET`)
  }
  rect(x: number, y: number, w: number, h: number, gray: number): void {
    this.page.ops.push(`${gray} g ${x.toFixed(2)} ${y.toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re f`)
  }
  line(x1: number, y1: number, x2: number, y2: number, gray = 0.8, width = 0.5): void {
    this.page.ops.push(`${gray} G ${width} w ${x1.toFixed(2)} ${y1.toFixed(2)} m ${x2.toFixed(2)} ${y2.toFixed(2)} l S`)
  }
  paragraph(text: string, font: Font, size: number, gap = 4): void {
    const leading = size * 1.38
    for (const l of wrap(text, font, size, CONTENT_W)) {
      this.ensure(leading)
      this.y -= leading
      this.text(MARGIN_X, this.y, l, font, size)
    }
    this.y -= gap
  }
  table(head: string[] | null, rows: string[][], widths: number[]): void {
    const size = 7.5
    const leading = 9.5
    const pad = 3
    const drawRow = (cells: string[], bold: boolean, shade: boolean): void => {
      const wrapped = widths.map((w, i) => wrap(cells[i] ?? '', bold ? 'F2' : 'F1', size, w - pad * 2))
      const h = Math.max(1, ...wrapped.map((w) => w.length)) * leading + pad * 2
      if (this.y - h < MARGIN_BOTTOM) {
        this.newPage()
        if (head && !bold) drawRow(head, true, true)
      }
      if (shade) this.rect(MARGIN_X, this.y - h, CONTENT_W, h, 0.93)
      let x = MARGIN_X
      wrapped.forEach((lines, i) => {
        lines.forEach((l, k) => this.text(x + pad, this.y - pad - (k + 1) * leading + 2.5, l, bold ? 'F2' : 'F1', size))
        x += widths[i]!
      })
      this.y -= h
      this.line(MARGIN_X, this.y, MARGIN_X + CONTENT_W, this.y, 0.82, 0.4)
    }
    if (head) drawRow(head, true, true)
    for (const r of rows) drawRow(r, false, false)
    this.y -= 8
  }
}

function columnWidths(head: string[], rows: string[][]): number[] {
  const n = head.length
  const len = Array.from({ length: n }, (_, i) => Math.min(60, Math.max(head[i]!.length, ...rows.map((r) => (r[i] ?? '').length)) + 2))
  const total = len.reduce((a, b) => a + b, 0)
  return len.map((l) => (l / total) * CONTENT_W)
}

function render(blocks: Block[], footer: string): Layout {
  const L = new Layout()
  for (const b of blocks) {
    switch (b.t) {
      case 'h1':
        L.ensure(40)
        L.y -= 22
        for (const l of wrap(b.text, 'F2', 17, CONTENT_W)) {
          L.text(MARGIN_X, L.y, l, 'F2', 17)
          L.y -= 21
        }
        L.y -= 2
        break
      case 'h2':
        L.ensure(60)
        L.y -= 20
        L.text(MARGIN_X, L.y, encodeWinAnsi(b.text), 'F2', 12.5)
        L.y -= 6
        L.line(MARGIN_X, L.y, MARGIN_X + CONTENT_W, L.y, 0.25, 0.8)
        L.y -= 4
        break
      case 'h3':
        L.ensure(40)
        L.y -= 6
        L.paragraph(b.text, 'F2', 9.5, 2)
        break
      case 'p':
        L.paragraph(b.text, 'F1', 9, 5)
        break
      case 'list':
        for (const item of b.items) {
          wrap(item, 'F1', 9, CONTENT_W - 14).forEach((l, i) => {
            L.ensure(12.5)
            L.y -= 12.5
            if (i === 0) L.text(MARGIN_X + 3, L.y, [0x95], 'F1', 9)
            L.text(MARGIN_X + 14, L.y, l, 'F1', 9)
          })
        }
        L.y -= 5
        break
      case 'kv':
        L.table(null, b.rows.map(([k, v]) => [k, v]), [CONTENT_W * 0.32, CONTENT_W * 0.68])
        break
      case 'table':
        if (b.rows.length === 0) L.paragraph('None.', 'F1', 9, 5)
        else L.table(b.head, b.rows, columnWidths(b.head, b.rows))
        break
      case 'rule':
        L.ensure(12)
        L.y -= 6
        L.line(MARGIN_X, L.y, MARGIN_X + CONTENT_W, L.y, 0.6, 0.5)
        L.y -= 6
        break
    }
  }
  const total = L.pages.length
  L.pages.forEach((p, i) => {
    p.ops.push(`0.45 g BT /F1 7 Tf ${MARGIN_X} 34 Td ${pdfString(encodeWinAnsi(footer))} Tj ET`)
    const label = encodeWinAnsi(`Page ${i + 1} of ${total}`)
    p.ops.push(`0.45 g BT /F1 7 Tf ${(PAGE_W - MARGIN_X - textWidth(label, 'F1', 7)).toFixed(2)} 34 Td ${pdfString(label)} Tj ET`)
    p.ops.push(`0.85 G 0.4 w ${MARGIN_X} 44 m ${PAGE_W - MARGIN_X} 44 l S`)
  })
  return L
}

/** Assemble PDF objects into a file with a correct cross-reference table. All content is 8-bit, so string length = byte length. */
function assemble(L: Layout, info: { title: string; created: string }): Uint8Array {
  const objects: string[] = []
  const add = (body: string): number => {
    objects.push(body)
    return objects.length
  }
  const catalog = add('')
  const pages = add('')
  const f1 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>')
  const f2 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>')
  const f3 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>')
  const kids: number[] = []
  for (const p of L.pages) {
    const stream = p.ops.join('\n')
    const content = add(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`)
    kids.push(
      add(
        `<< /Type /Page /Parent ${pages} 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] /Resources << /Font << /F1 ${f1} 0 R /F2 ${f2} 0 R /F3 ${f3} 0 R >> >> /Contents ${content} 0 R >>`,
      ),
    )
  }
  objects[catalog - 1] = `<< /Type /Catalog /Pages ${pages} 0 R >>`
  objects[pages - 1] = `<< /Type /Pages /Kids [${kids.map((k) => `${k} 0 R`).join(' ')}] /Count ${kids.length} >>`
  const date = info.created.replace(/\D/g, '').slice(0, 14).padEnd(14, '0')
  const infoObj = add(`<< /Title ${pdfString(encodeWinAnsi(info.title))} /Producer (TOUCHSTONE report writer) /CreationDate (D:${date}Z) >>`)

  let out = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'
  const offsets: number[] = []
  objects.forEach((body, i) => {
    offsets.push(out.length)
    out += `${i + 1} 0 obj\n${body}\nendobj\n`
  })
  const xref = out.length
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
  for (const o of offsets) out += `${String(o).padStart(10, '0')} 00000 n \n`
  out += `trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R /Info ${infoObj} 0 R >>\nstartxref\n${xref}\n%%EOF\n`
  const bytes = new Uint8Array(out.length)
  for (let i = 0; i < out.length; i++) bytes[i] = out.charCodeAt(i) & 0xff
  return bytes
}

export function renderPdf(blocks: Block[], opts: { title: string; footer: string; created: string }): Uint8Array {
  return assemble(render(blocks, opts.footer), { title: opts.title, created: opts.created })
}

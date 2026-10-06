/**
 * Security review: CLI terminal output and web link rendering (pinned defences).
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { jsonSafe, term, termDocument } from '../../apps/cli/src/terminal.ts'

const cp = (n: number) => String.fromCodePoint(n)
const ROOT = join(import.meta.dirname, '..', '..')

describe('CLI: data-derived text cannot drive the terminal', () => {
  it('ESC, CSI (C1), OSC title-set, BEL and bidi are removed from term() and termDocument()', () => {
    const evil = `Acme${cp(0x1b)}]0;pwned${cp(0x07)}${cp(0x1b)}[2J${cp(0x9b)}31m${cp(0x202e)}cod.exe`
    for (const out of [term(evil), termDocument(evil)]) {
      for (const c of [0x1b, 0x07, 0x9b, 0x202e]) expect(out.includes(cp(c))).toBe(false)
    }
    expect(term('a\nb\rc')).not.toMatch(/[\n\r]/)
  })
  it('jsonSafe escapes C1 and bidi characters JSON.stringify leaves raw, and stays valid JSON', () => {
    const s = jsonSafe(JSON.stringify({ n: `x${cp(0x9b)}y${cp(0x2066)}z` }))
    expect(s.includes(cp(0x9b))).toBe(false)
    expect(JSON.parse(s).n).toBe(`x${cp(0x9b)}y${cp(0x2066)}z`)
  })
})

describe('web: links from data', () => {
  it('ExtLink renders only http(s) URLs as anchors; nothing uses dangerouslySetInnerHTML', () => {
    const controls = readFileSync(join(ROOT, 'apps/web/src/ui/controls.tsx'), 'utf8')
    expect(controls).toMatch(/const safe = \/\^https\?:\\\/\\\/\/i\.test\(href\)/)
    expect(controls).toMatch(/rel="noopener noreferrer"/)
  })
  it('index.html carries a CSP without unsafe-inline scripts', () => {
    const html = readFileSync(join(ROOT, 'apps/web/index.html'), 'utf8')
    const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)![1]!
    expect(csp).toMatch(/script-src 'self'(;|$)/)
    expect(csp).toMatch(/object-src 'none'/)
    expect(csp).toMatch(/base-uri 'none'/)
  })
})

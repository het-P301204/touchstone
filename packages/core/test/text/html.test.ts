import { describe, expect, it } from 'vitest'
import { decodeEntities, htmlToText } from '../../src/text/html.ts'

function timed(fn: () => void): number {
  const t = performance.now()
  fn()
  return performance.now() - t
}

/** Run time for n and 4n; a linear algorithm grows ~4x, a quadratic one ~16x. */
function growth(make: (n: number) => string, n: number): { small: number; large: number } {
  const a = make(n)
  const b = make(4 * n)
  htmlToText(a) // warm up
  const small = Math.max(1, timed(() => htmlToText(a)))
  const large = timed(() => htmlToText(b))
  return { small, large }
}

describe('htmlToText', () => {
  it('extracts text, keeps block boundaries as line breaks and collapses whitespace', () => {
    const { text, truncated } = htmlToText('<html><body><h1>Title</h1><p>One   two\n three.</p><p>Next <b>bold</b><i>italic</i></p><ul><li>a</li><li>b</li></ul></body></html>')
    expect(text).toBe('Title\nOne two three.\nNext bolditalic\na\nb')
    expect(truncated).toBe(false)
  })

  it('drops script, style, noscript, template, head and comments', () => {
    const { text } = htmlToText('<head><title>t</title><style>p{}</style></head><script>alert("<p>x</p>")</script><noscript>n</noscript><template><p>tpl</p></template><!-- c <p>hidden</p> --><p>visible</p>')
    expect(text).toBe('visible')
  })

  it('treats ">" inside quoted attribute values as part of the tag', () => {
    expect(htmlToText('<a title="a > b" href=\'x>y\'>link</a> text').text).toBe('link text')
  })

  it('decodes named, decimal and hex entities; invalid code points become U+FFFD', () => {
    expect(decodeEntities('A &amp; B &lt;3 &#39;q&#x27; &rsquo; &nbsp;x &unknown; &#0; &#xD800; &amp')).toBe(`A & B <3 'q' ’  x &unknown; ${String.fromCodePoint(0xfffd)} ${String.fromCodePoint(0xfffd)} &amp`)
  })

  it('strips bidi and zero-width characters, including ones produced by entities', () => {
    const rlo = String.fromCodePoint(0x202e)
    const { text } = htmlToText(`<p>safe${rlo}text &#x202E;here &#8203;now</p>`)
    expect(text).toBe('safetext here now')
  })

  it('keeps literal "<" in text and drops an unterminated tag', () => {
    expect(htmlToText('a < b and 1<2').text).toBe('a < b and 1<2')
    expect(htmlToText('<p>before</p><div class="never closed').text).toBe('before')
  })

  it('truncates at maxChars and says so', () => {
    const r = htmlToText(`<p>${'word '.repeat(1000)}</p>`, { maxChars: 50 })
    expect(r.truncated).toBe(true)
    expect(r.text.length).toBeLessThanOrEqual(50)
  })

  it('handles 1 MB of "<" characters in linear time', () => {
    const big = '<'.repeat(1024 * 1024)
    const ms = timed(() => expect(htmlToText(big, { maxChars: 2_000_000 }).text.length).toBe(1024 * 1024))
    expect(htmlToText(big).truncated).toBe(true) // default cap 500 000 characters
    expect(ms).toBeLessThan(3000)
    const g = growth((n) => '<'.repeat(n), 200_000)
    expect(g.large / g.small).toBeLessThan(12)
  })

  it('handles deep nesting and pathological tag soup in linear time', () => {
    const deep = '<div>'.repeat(200_000) + 'x' + '</div>'.repeat(200_000)
    expect(timed(() => expect(htmlToText(deep).text).toBe('x'))).toBeLessThan(3000)
    for (const make of [
      (n: number) => '<a'.repeat(n), // unterminated tags
      (n: number) => '<a title="'.repeat(n), // unterminated quotes
      (n: number) => '<!--'.repeat(n), // unterminated comments
      (n: number) => '<script>'.repeat(n), // unterminated raw text
      (n: number) => '&#x'.repeat(n) + '&amp'.repeat(n), // broken entities
      (n: number) => '</'.repeat(n),
    ]) {
      const g = growth(make, 50_000)
      expect(g.large).toBeLessThan(3000)
      expect(g.large / g.small).toBeLessThan(12)
    }
  })

  it('never executes anything: handlers and javascript: URLs are just dropped markup', () => {
    expect(htmlToText('<img src=x onerror="globalThis.__pwned=1"><a href="javascript:alert(1)">ok</a>').text).toBe('ok')
    expect((globalThis as Record<string, unknown>).__pwned).toBeUndefined()
  })
})

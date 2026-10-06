/**
 * Invisible and bidirectional control character stripping.
 *
 * Remote text (CVE titles, vendor names, policy sentences quoted as
 * evidence, dispute statements) is shown to people who make decisions from
 * it. Bidi overrides, zero-width characters and Unicode tag characters can
 * make that text display differently from what it contains (the "Trojan
 * Source" pattern), so every human-readable string from a source passes
 * through `stripInvisible` before it is stored or quoted.
 *
 * The character set is expressed as numeric code point ranges, not as a
 * regex literal: an escape sequence typed into a regex literal is one editor
 * round-trip away from becoming the invisible character itself.
 */

/** Inclusive code point ranges that are removed. Exported for documentation and tests. */
export const INVISIBLE_CODE_POINT_RANGES: ReadonlyArray<readonly [number, number]> = [
  // Sorted ascending and non-overlapping: isInvisibleCodePoint relies on it.
  [0x0000, 0x0008], // C0 controls before TAB
  [0x000b, 0x000c], // VT, FF (TAB, LF, CR are kept)
  [0x000e, 0x001f], // remaining C0 controls
  [0x007f, 0x009f], // DEL and C1 controls
  [0x00ad, 0x00ad], // SOFT HYPHEN (invisible unless at a line break)
  [0x034f, 0x034f], // COMBINING GRAPHEME JOINER
  [0x061c, 0x061c], // ARABIC LETTER MARK
  [0x115f, 0x1160], // HANGUL CHOSEONG / JUNGSEONG FILLER
  [0x180b, 0x180e], // MONGOLIAN FREE VARIATION SELECTORS, VOWEL SEPARATOR
  [0x200b, 0x200f], // ZWSP, ZWNJ, ZWJ, LRM, RLM
  [0x2028, 0x202e], // LINE/PARAGRAPH SEPARATOR, LRE, RLE, PDF, LRO, RLO
  [0x2060, 0x2064], // WORD JOINER, FUNCTION APPLICATION, INVISIBLE TIMES / SEPARATOR / PLUS
  [0x2066, 0x2069], // LRI, RLI, FSI, PDI
  [0x3164, 0x3164], // HANGUL FILLER
  [0xfe00, 0xfe0f], // VARIATION SELECTORS 1-16
  [0xfeff, 0xfeff], // ZERO WIDTH NO-BREAK SPACE / BOM
  [0xffa0, 0xffa0], // HALFWIDTH HANGUL FILLER
  [0xe0000, 0xe007f], // TAG characters
  [0xe0100, 0xe01ef], // VARIATION SELECTORS SUPPLEMENT
]

/** True when the code point is one `stripInvisible` removes (lone surrogates aside). */
export function isInvisibleCodePoint(cp: number): boolean {
  for (const [lo, hi] of INVISIBLE_CODE_POINT_RANGES) {
    if (cp < lo) return false
    if (cp <= hi) return true
  }
  return false
}

/** Cheap pre-filter on a UTF-16 code unit: could this unit start something we remove? */
function isCandidateUnit(c: number): boolean {
  if (c < 0x20) return c !== 0x09 && c !== 0x0a && c !== 0x0d
  if (c < 0x7f) return false
  if (c <= 0x9f) return true
  if (c < 0x00ad) return false
  if (c >= 0xd800 && c <= 0xdfff) return true // surrogates: tag characters live in plane 14; lone surrogates are dropped
  return isInvisibleCodePoint(c)
}

/**
 * Remove bidi controls, zero-width characters, tag characters, C0/C1 controls
 * (except tab, LF, CR) and lone surrogates. `removed` counts removed code
 * points. Idempotent: lone surrogates are dropped rather than kept, so a
 * removal can never join two halves into a new character.
 */
export function stripInvisible(s: string): { text: string; removed: number } {
  const len = s.length
  let i = 0
  while (i < len && !isCandidateUnit(s.charCodeAt(i))) i++
  if (i === len) return { text: s, removed: 0 }

  let out = ''
  let removed = 0
  let chunkStart = 0
  while (i < len) {
    const c = s.charCodeAt(i)
    let width = 1
    let drop: boolean
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < len ? s.charCodeAt(i + 1) : -1
      if (d >= 0xdc00 && d <= 0xdfff) {
        width = 2
        const cp = (c - 0xd800) * 0x400 + (d - 0xdc00) + 0x10000
        drop = isInvisibleCodePoint(cp) // tag characters and supplementary variation selectors
      } else {
        drop = true // lone high surrogate
      }
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      drop = true // lone low surrogate
    } else {
      drop = isCandidateUnit(c)
    }
    if (drop) {
      if (i > chunkStart) out += s.slice(chunkStart, i)
      removed++
      chunkStart = i + width
    }
    i += width
  }
  if (removed === 0) return { text: s, removed: 0 }
  if (chunkStart < len) out += s.slice(chunkStart)
  return { text: out, removed }
}

/** `stripInvisible(s).text`. */
export function cleanText(s: string): string {
  return stripInvisible(s).text
}

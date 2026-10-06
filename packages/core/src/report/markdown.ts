/** Markdown rendering of report blocks. All text passes through mdInline/mdCell. */

import type { Block } from './document.ts'
import { mdCell, mdInline } from './escape.ts'

export function renderMarkdown(blocks: Block[]): string {
  const out: string[] = []
  for (const b of blocks) {
    switch (b.t) {
      case 'h1':
        out.push(`# ${mdInline(b.text)}`)
        break
      case 'h2':
        out.push(`## ${mdInline(b.text)}`)
        break
      case 'h3':
        out.push(`### ${mdInline(b.text)}`)
        break
      case 'p':
        out.push(mdInline(b.text))
        break
      case 'kv':
        out.push(['| Field | Value |', '|---|---|', ...b.rows.map(([k, v]) => `| ${mdCell(k)} | ${mdCell(v)} |`)].join('\n'))
        break
      case 'table':
        if (b.rows.length === 0) {
          out.push('_None._')
          break
        }
        out.push(
          [`| ${b.head.map(mdCell).join(' | ')} |`, `|${b.head.map(() => '---').join('|')}|`, ...b.rows.map((r) => `| ${b.head.map((_, i) => mdCell(r[i] ?? '')).join(' | ')} |`)].join('\n'),
        )
        break
      case 'list':
        if (b.items.length) out.push(b.items.map((i) => `- ${mdInline(i)}`).join('\n'))
        break
      case 'rule':
        out.push('---')
        break
    }
  }
  return `${out.join('\n\n')}\n`
}

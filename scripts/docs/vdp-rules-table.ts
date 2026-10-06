/**
 * Prints the VDP phrase rules, the negation model's word lists and the
 * structural rules as Markdown, from the data the assessor actually runs
 * (packages/core/src/vdp/assess.ts). docs/methodology.md pastes this output;
 * re-run it after changing a rule so the document cannot drift from the code.
 *
 *   node scripts/docs/vdp-rules-table.ts
 */

import {
  VDP_COORDINATION_QUALIFIERS,
  VDP_INTERSTITIAL_MARKERS,
  VDP_LEGAL_CONDITION_EXCLUSIONS,
  VDP_NEGATIONS,
  VDP_RULES,
  VDP_SCOPE_QUALIFIERS,
  VDP_STRUCTURAL_RULES,
} from '../../packages/core/src/vdp/assess.ts'

/** A table cell: pipes escaped, newlines flattened. */
function cell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')
}

/** A phrase in code style. Leading or trailing spaces are significant, so they are shown as a visible middle dot. */
function phrase(p: string): string {
  const shown = p.replace(/^ /, '·').replace(/ $/, '·')
  return shown.includes('`') ? cell(JSON.stringify(shown)) : `\`${cell(shown)}\``
}

function group(g: readonly string[]): string {
  return g.map(phrase).join(', ')
}

const NAMED_LISTS: [string, readonly string[]][] = [
  ['VDP_NEGATIONS', VDP_NEGATIONS],
  ['VDP_SCOPE_QUALIFIERS', VDP_SCOPE_QUALIFIERS],
  ['VDP_COORDINATION_QUALIFIERS', VDP_COORDINATION_QUALIFIERS],
  ['VDP_LEGAL_CONDITION_EXCLUSIONS', VDP_LEGAL_CONDITION_EXCLUSIONS],
]

/** A list by name when it equals one of the named lists, otherwise its phrases. */
function listOrName(xs: readonly string[] | undefined): string {
  if (!xs || xs.length === 0) return '(none)'
  for (const [name, list] of NAMED_LISTS) {
    if (list.length === xs.length && list.every((p, i) => p === xs[i])) return `\`${name}\``
  }
  return group(xs)
}

const lines: string[] = []
lines.push('### Phrase rules (`VDP_RULES`)')
lines.push('')
lines.push('A rule matches a sentence when every "all of" group has at least one phrase present (word-start match) and no')
lines.push('"none of" phrase is present. Groups are separated by **AND**; phrases inside a group are alternatives. For a rule')
lines.push('with negations, the clause around the first group\'s match is then checked: a negation marker there turns the match')
lines.push('into a CONTRADICTED finding with rule id `<rule>.NEGATED`, unless a qualifier is also in that clause, in which case')
lines.push('the sentence is ignored for that rule.')
lines.push('')
lines.push('| Rule id | Criterion | Effect | Precedence | What it means | All of (each group) | None of | Negations | Qualifiers |')
lines.push('|---|---|---|---|---|---|---|---|---|')
for (const r of VDP_RULES) {
  const allOf = r.allOf.map((g) => `(${group(g)})`).join(' **AND** ')
  lines.push(
    `| \`${r.id}\` | ${r.criterion} | ${r.effect} | ${r.precedence} | ${cell(r.description)} | ${allOf} | ${listOrName(r.noneOf)} | ${listOrName(r.negations)} | ${listOrName(r.qualifiers)} |`,
  )
}
lines.push('')
lines.push('### Negation model word lists')
lines.push('')
lines.push('Negations and qualifiers are matched as substrings of the clause (padded with a space at each end), so `n\'t` matches')
lines.push('"isn\'t" and `not·` matches "cannot ". A `·` marks a significant leading or trailing space.')
lines.push('')
lines.push('| List | Role | Phrases |')
lines.push('|---|---|---|')
lines.push(`| \`VDP_NEGATIONS\` | negation markers for the permissive rules | ${group(VDP_NEGATIONS)} |`)
lines.push(`| \`VDP_SCOPE_QUALIFIERS\` | a negated clause that limits scope is a scope statement, not a refusal | ${group(VDP_SCOPE_QUALIFIERS)} |`)
lines.push(`| \`VDP_COORDINATION_QUALIFIERS\` | a negated disclosure clause with a coordination window is coordinated disclosure, not a ban | ${group(VDP_COORDINATION_QUALIFIERS)} |`)
lines.push(`| \`VDP_LEGAL_CONDITION_EXCLUSIONS\` | legal action conditioned on not following the policy (or a "will not pursue" commitment) is not a contradiction | ${group(VDP_LEGAL_CONDITION_EXCLUSIONS)} |`)
lines.push(`| \`VDP_INTERSTITIAL_MARKERS\` | a page under the word floor containing one of these is UNREADABLE, not TOO_SHORT | ${group(VDP_INTERSTITIAL_MARKERS)} |`)
lines.push('')
lines.push('### Structural rules (`VDP_STRUCTURAL_RULES`)')
lines.push('')
lines.push('These rules read security.txt fields, the outcome of the policy fetch, or dates. They do not match phrases.')
lines.push('')
lines.push('| Rule id | Criterion | State | What it means |')
lines.push('|---|---|---|---|')
for (const r of VDP_STRUCTURAL_RULES) {
  lines.push(`| \`${r.id}\` | ${r.criterion} | ${r.state} | ${cell(r.description)} |`)
}
lines.push('')
lines.push(`${VDP_RULES.length} phrase rules, ${VDP_STRUCTURAL_RULES.length} structural rules.`)

console.log(lines.join('\n'))

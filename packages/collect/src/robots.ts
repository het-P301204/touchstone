/**
 * robots.txt evaluation (RFC 9309), used before fetching a policy page.
 *
 * The group for our product token is used when present, else the "*" group.
 * The longest matching rule wins; on a tie, Allow wins. "*" matches any
 * sequence and a trailing "$" anchors the end. Matching is a linear
 * two-pointer walk with single backtrack point per "*" (no regex), so a
 * hostile robots.txt cannot cause catastrophic backtracking.
 */

type Rule = { allow: boolean; pattern: string }

/** Paths longer than this are not evaluated: the fetch is treated as disallowed (fail closed). */
export const ROBOTS_MAX_PATH = 512
/** Rules beyond this count are ignored. */
export const ROBOTS_MAX_RULES = 1_000
/** Total character comparisons allowed per evaluation; exceeding it is treated as disallowed. */
export const ROBOTS_COMPARISON_BUDGET = 2_000_000

class BudgetExceeded extends Error {}

/** Glob match with "*" and a trailing "$". Iterative, O(n*m) worst case, no recursion. */
export function robotsPatternMatches(pattern: string, path: string, budget: { left: number } = { left: Number.POSITIVE_INFINITY }): boolean {
  let p = pattern
  let anchored = false
  if (p.endsWith('$')) {
    anchored = true
    p = p.slice(0, -1)
  }
  let pi = 0
  let si = 0
  let starP = -1
  let starS = 0
  while (si < path.length) {
    if (--budget.left < 0) throw new BudgetExceeded()
    if (pi < p.length && p[pi] === '*') {
      starP = pi++
      starS = si
    } else if (pi < p.length && p[pi] === path[si]) {
      pi++
      si++
    } else if (pi >= p.length && !anchored) {
      return true // prefix match
    } else if (starP >= 0) {
      pi = starP + 1
      si = ++starS
    } else {
      return false
    }
  }
  while (pi < p.length && p[pi] === '*') pi++
  return pi >= p.length
}

export function parseRobots(text: string, productToken: string): Rule[] {
  const token = productToken.toLowerCase()
  const groups: { agents: string[]; rules: Rule[] }[] = []
  let current: { agents: string[]; rules: Rule[] } | null = null
  let lastWasAgent = false
  for (const raw of text.split(/\r\n|\r|\n/).slice(0, 5_000)) {
    const line = raw.replace(/#.*$/, '').trim()
    if (line.length === 0) continue
    const colon = line.indexOf(':')
    if (colon < 0) continue
    const key = line.slice(0, colon).trim().toLowerCase()
    const value = line.slice(colon + 1).trim()
    if (key === 'user-agent') {
      if (!current || !lastWasAgent) {
        current = { agents: [], rules: [] }
        groups.push(current)
      }
      current.agents.push(value.toLowerCase())
      lastWasAgent = true
    } else if ((key === 'allow' || key === 'disallow') && current) {
      lastWasAgent = false
      if (value.length === 0) continue // "Disallow:" with no value allows everything
      if (current.rules.length < ROBOTS_MAX_RULES) current.rules.push({ allow: key === 'allow', pattern: value.slice(0, 500) })
    } else {
      lastWasAgent = false
    }
  }
  // Our product token must match exactly (case-insensitive); an empty or prefix-only User-agent does not apply.
  const mine = groups.filter((g) => g.agents.some((a) => a.length > 0 && a !== '*' && a === token))
  const chosen = mine.length > 0 ? mine : groups.filter((g) => g.agents.includes('*'))
  return chosen.flatMap((g) => g.rules).slice(0, ROBOTS_MAX_RULES)
}

export function robotsAllows(text: string, path: string, productToken: string): boolean {
  if (path === '/robots.txt') return true
  if (path.length > ROBOTS_MAX_PATH) return false
  let best: Rule | null = null
  const budget = { left: ROBOTS_COMPARISON_BUDGET }
  for (const r of parseRobots(text, productToken)) {
    let hit: boolean
    try {
      hit = robotsPatternMatches(r.pattern, path, budget)
    } catch (err) {
      if (err instanceof BudgetExceeded) return false
      throw err
    }
    if (!hit) continue
    if (!best || r.pattern.length > best.pattern.length || (r.pattern.length === best.pattern.length && r.allow && !best.allow)) best = r
  }
  return best ? best.allow : true
}

/**
 * CSAF 2.0 advisory normalization.
 *
 * Only what the timeliness and high-impact metrics need is read: tracking id,
 * title, initial release date, the CVE ids the advisory lists, and the
 * severity the advisory itself states. Severity is
 * `document.aggregate_severity.text` when it maps to a known level, otherwise
 * the highest CVSS baseSeverity in `vulnerabilities[].scores[]`, otherwise
 * UNKNOWN. Nothing is inferred from prose.
 */

import type { Advisory, Severity } from '../model/index.ts'
import { cleanText } from '../util/sanitize.ts'
import { CVE_ID_PATTERN, DEMO_ID_PATTERN, severityFromScore, severityRank } from './cve.ts'
import { arr, isObject, isoDate, num, own, str } from './json.ts'

/** aggregate_severity.text vocabulary (case-insensitive) mapped to a level. Exported for documentation. */
export const CSAF_SEVERITY_WORDS: Record<string, Severity> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  important: 'HIGH',
  medium: 'MEDIUM',
  moderate: 'MEDIUM',
  low: 'LOW',
  none: 'NONE',
  informational: 'NONE',
}

function severityWord(text: string): Severity | null {
  const k = text.trim().toLowerCase()
  return Object.hasOwn(CSAF_SEVERITY_WORDS, k) ? CSAF_SEVERITY_WORDS[k]! : null
}

function scoreSeverity(cvss: unknown): Severity | null {
  if (!isObject(cvss)) return null
  const s = str(cvss, 'baseSeverity')
  if (s) {
    const up = s.toUpperCase()
    if (up === 'CRITICAL' || up === 'HIGH' || up === 'MEDIUM' || up === 'LOW' || up === 'NONE') return up
  }
  const score = num(cvss, 'baseScore')
  return score !== undefined && score >= 0 && score <= 10 ? severityFromScore(score) : null
}

export function normalizeCsafAdvisory(
  json: unknown,
  ctx: { vendorId: string; snapshotId: string; url: string; synthetic: boolean },
): { ok: true; advisory: Advisory } | { ok: false; error: string } {
  if (!isObject(json)) return { ok: false, error: 'advisory is not a JSON object' }
  const doc = own(json, 'document')
  if (!isObject(doc)) return { ok: false, error: 'document missing' }
  const version = str(doc, 'csaf_version')
  if (version !== '2.0') return { ok: false, error: `unsupported csaf_version ${JSON.stringify(String(version ?? '').slice(0, 10))}` }
  const tracking = own(doc, 'tracking')
  const id = str(tracking, 'id')
  if (!id || id.trim().length === 0) return { ok: false, error: 'document.tracking.id missing' }
  const published = isoDate(own(tracking, 'initial_release_date'))
  if (!published) return { ok: false, error: 'document.tracking.initial_release_date missing or invalid' }
  const title = cleanText(str(doc, 'title') ?? '').replace(/\s+/g, ' ').trim().slice(0, 300)

  const cveIds: string[] = []
  let maxScore: Severity | null = null
  for (const v of arr(json, 'vulnerabilities', 5_000)) {
    const cve = str(v, 'cve')?.trim()
    if (cve && (CVE_ID_PATTERN.test(cve) || (ctx.synthetic && DEMO_ID_PATTERN.test(cve))) && !cveIds.includes(cve)) cveIds.push(cve)
    for (const s of arr(v, 'scores', 500)) {
      for (const key of ['cvss_v3', 'cvss_v2', 'cvss_v4']) {
        const sev = scoreSeverity(own(s, key))
        if (sev && (maxScore === null || severityRank(sev) > severityRank(maxScore))) maxScore = sev
      }
    }
  }

  const aggregate = str(own(doc, 'aggregate_severity'), 'text')
  const fromText = aggregate ? severityWord(aggregate) : null
  const severity: Severity = fromText ?? maxScore ?? 'UNKNOWN'

  return {
    ok: true,
    advisory: {
      id: cleanText(id).trim().slice(0, 120),
      vendorId: ctx.vendorId,
      url: ctx.url,
      title,
      publishedAt: published,
      severity,
      cveIds: cveIds.sort(),
      snapshotId: ctx.snapshotId,
      synthetic: ctx.synthetic,
    },
  }
}

/**
 * List queries over the published bundle: the signatory directory and the
 * CVE list. Pure functions over loaded data; no I/O.
 *
 * Ordering rule: a vendor or record without a measurable value is never
 * ranked as if it scored 0. Nulls sort last in both directions, and the
 * response says so.
 */
import { cleanText } from '../../../packages/core/src/util/sanitize.ts'
import type { Dispute, DimensionId, GoalStatus, RunSummary, SecurityCommitmentGoal, VendorCategory, VendorSummary } from '../../../packages/core/src/model/index.ts'
import type { CnaFieldStatus, CveRow } from './bundle.ts'

export const VENDOR_CATEGORIES: VendorCategory[] = [
  'ENTERPRISE_SOFTWARE',
  'CLOUD',
  'NETWORKING',
  'SECURITY',
  'INFRASTRUCTURE',
  'PUBLIC_SECTOR',
  'EDUCATION',
  'DEVELOPER_TOOLS',
  'HARDWARE',
  'OTHER',
]

export const SIGNATORY_SORTS = ['name', 'coverage', 'vdp', 'cve_quality', 'cve_timeliness', 'cves'] as const
export type SignatorySort = (typeof SIGNATORY_SORTS)[number]

export type SignatoryRow = {
  id: string
  name: string
  category: VendorCategory
  signatoryStatus: VendorSummary['vendor']['signatoryStatus']
  signedOn: string | null
  synthetic: boolean
  coverage: { percent: number; observedSlots: number; totalSlots: number }
  dimensions: Record<DimensionId, { value: number | null; status: GoalStatus } | null>
  statusCounts: Record<GoalStatus, number>
  cveCount: number
  advisoryCount: number
  anomalyCount: number
  activeDisputes: number
}

export type SignatoryFilter = {
  category?: VendorCategory[]
  status?: string[]
  coverageMin?: number
  coverageMax?: number
  q?: string
  synthetic?: boolean
  sort: SignatorySort
  order: 'asc' | 'desc'
}

/** Case-folded, invisible-stripped, whitespace-collapsed text for search. */
export function searchKey(s: string): string {
  return cleanText(s).normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim()
}

export function signatoryRow(v: VendorSummary, activeDisputes: number): SignatoryRow {
  const dim = (d: DimensionId) => {
    const f = v.dimensions.find((x) => x.dimension === d)
    return f ? { value: f.value, status: f.status } : null
  }
  return {
    id: v.vendor.id,
    name: v.vendor.canonicalName,
    category: v.vendor.category,
    signatoryStatus: v.vendor.signatoryStatus,
    signedOn: v.vendor.signedOn ?? null,
    synthetic: v.vendor.synthetic,
    coverage: { percent: v.coverage.percent, observedSlots: v.coverage.observedSlots, totalSlots: v.coverage.totalSlots },
    dimensions: { VDP: dim('VDP'), CVE_QUALITY: dim('CVE_QUALITY'), CVE_TIMELINESS: dim('CVE_TIMELINESS') },
    statusCounts: v.statusCounts,
    cveCount: v.cveCount,
    advisoryCount: v.advisoryCount,
    anomalyCount: v.anomalies.length,
    activeDisputes,
  }
}

const sortValue = (r: SignatoryRow, sort: SignatorySort): number | string | null => {
  switch (sort) {
    case 'name':
      return r.name.toLowerCase()
    case 'coverage':
      return r.coverage.percent
    case 'vdp':
      return r.dimensions.VDP?.value ?? null
    case 'cve_quality':
      return r.dimensions.CVE_QUALITY?.value ?? null
    case 'cve_timeliness':
      return r.dimensions.CVE_TIMELINESS?.value ?? null
    case 'cves':
      return r.cveCount
  }
}

export function querySignatories(summary: RunSummary, disputeCounts: Map<string, number>, f: SignatoryFilter): SignatoryRow[] {
  const q = f.q ? searchKey(f.q) : ''
  const rows = summary.vendors
    .filter((v) => {
      if (f.category?.length && !f.category.includes(v.vendor.category)) return false
      if (f.status?.length && !f.status.includes(v.vendor.signatoryStatus)) return false
      if (f.coverageMin !== undefined && v.coverage.percent < f.coverageMin) return false
      if (f.coverageMax !== undefined && v.coverage.percent > f.coverageMax) return false
      if (f.synthetic !== undefined && v.vendor.synthetic !== f.synthetic) return false
      if (q) {
        const names = [v.vendor.canonicalName, v.vendor.id, ...v.vendor.aliases.map((a) => a.value)]
        if (!names.some((n) => searchKey(n).includes(q))) return false
      }
      return true
    })
    .map((v) => signatoryRow(v, disputeCounts.get(v.vendor.id) ?? 0))
  const dir = f.order === 'desc' ? -1 : 1
  rows.sort((a, b) => {
    const x = sortValue(a, f.sort)
    const y = sortValue(b, f.sort)
    // Unmeasured values sort last whichever way the list is ordered.
    if (x === null && y !== null) return 1
    if (y === null && x !== null) return -1
    if (x !== null && y !== null && x !== y) return (x < y ? -1 : 1) * dir
    return a.name.localeCompare(b.name) || a.id.localeCompare(b.id)
  })
  return rows
}

export type CveFilter = {
  vendor?: string
  year?: number
  severity?: string[]
  cwe?: string
  product?: string
  completeness?: ('COMPLETE' | 'MISSING_CWE' | 'MISSING_CPE' | 'MISSING_BOTH' | 'ENRICHED_ONLY')[]
}

export function queryCves(rows: CveRow[], f: CveFilter): CveRow[] {
  const product = f.product ? searchKey(f.product) : ''
  const cwe = f.cwe ? normalizeCwe(f.cwe) : ''
  return rows.filter((r) => {
    if (f.vendor && !r.vendorIds.includes(f.vendor)) return false
    if (f.year !== undefined && r.year !== f.year) return false
    if (f.severity?.length && !f.severity.includes(r.severity)) return false
    if (cwe && !r.cnaCwes.some((c) => c.toUpperCase() === cwe)) return false
    if (product && !r.products.some((p) => searchKey(p).includes(product))) return false
    if (f.completeness?.length) {
      const hit = f.completeness.some((c) => (c === 'ENRICHED_ONLY' ? r.enrichedOnly : r.cnaFieldStatus === (c as CnaFieldStatus)))
      if (!hit) return false
    }
    return true
  })
}

/** "79", "cwe-79", "CWE-79" -> "CWE-79"; placeholders like NVD-CWE-noinfo stay as written (upper-cased). */
export function normalizeCwe(s: string): string {
  const t = s.trim().toUpperCase()
  if (/^\d{1,5}$/.test(t)) return `CWE-${t}`
  return t
}

/* ------------------------------------------------------------- goal overlay */

export const ACTIVE_DISPUTE: Dispute['status'][] = ['OPEN', 'UNDER_REVIEW']

/**
 * Which goals an active dispute overlays. The observation itself is never
 * changed: the goal keeps its original status and gains a DISPUTED display
 * state alongside it.
 *   GOAL      -> that goal
 *   METRIC    -> the goal(s) whose metrics include it
 *   EVIDENCE  -> the goal(s) citing that evidence item
 *   CVE       -> the goal(s) citing evidence about that record
 *   IDENTITY  -> every goal measured from attributed CVE records
 */
export function disputedGoalIds(
  d: Dispute,
  goals: { goalId: string; metrics: { metricId: string }[]; evidenceIds: string[] }[],
  evidenceSubjects: Map<string, string>,
): string[] {
  switch (d.target.kind) {
    case 'GOAL':
      return goals.some((g) => g.goalId === d.target.id) ? [d.target.id] : []
    case 'METRIC':
      return goals.filter((g) => g.metrics.some((m) => m.metricId === d.target.id)).map((g) => g.goalId)
    case 'EVIDENCE':
      return goals.filter((g) => g.evidenceIds.includes(d.target.id)).map((g) => g.goalId)
    case 'CVE':
      return goals.filter((g) => g.evidenceIds.some((e) => evidenceSubjects.get(e) === d.target.id)).map((g) => g.goalId)
    case 'IDENTITY':
      return goals.filter((g) => g.metrics.some((m) => m.metricId.startsWith('cve.') || m.metricId.startsWith('g3.'))).map((g) => g.goalId)
  }
}

export function goalDefinitionMap(goals: SecurityCommitmentGoal[]): Map<string, SecurityCommitmentGoal> {
  return new Map(goals.map((g) => [g.id, g]))
}

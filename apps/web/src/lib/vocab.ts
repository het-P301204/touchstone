/**
 * Labels for engine enums and helpers that read the published shapes.
 */
import type {
  AliasKind,
  DimensionId,
  DisputeReason,
  GoalSummary,
  MetricDefinition,
  MetricValue,
  RunSummary,
  VendorCategory,
  VendorSummary,
} from '@touchstone/core/model'
import { NOT_MEASURED, days, num, pct } from './format.ts'
import { VDP_CRITERION_LABELS } from './core.ts'

export const CATEGORY_LABEL: Record<VendorCategory, string> = {
  ENTERPRISE_SOFTWARE: 'Enterprise software',
  CLOUD: 'Cloud',
  NETWORKING: 'Networking',
  SECURITY: 'Security vendors',
  INFRASTRUCTURE: 'Infrastructure',
  PUBLIC_SECTOR: 'Public sector',
  EDUCATION: 'Education',
  DEVELOPER_TOOLS: 'Developer tools',
  HARDWARE: 'Hardware',
  OTHER: 'Other',
}

/** Leaderboard filter groups (brief: all, enterprise, cloud, networking, software, infrastructure, public sector, security vendors). */
export const CATEGORY_FILTERS: { id: string; label: string; categories: VendorCategory[] | null }[] = [
  { id: 'all', label: 'All', categories: null },
  { id: 'enterprise', label: 'Enterprise', categories: ['ENTERPRISE_SOFTWARE'] },
  { id: 'cloud', label: 'Cloud', categories: ['CLOUD'] },
  { id: 'networking', label: 'Networking', categories: ['NETWORKING'] },
  { id: 'software', label: 'Software', categories: ['ENTERPRISE_SOFTWARE', 'DEVELOPER_TOOLS', 'EDUCATION'] },
  { id: 'infrastructure', label: 'Infrastructure', categories: ['INFRASTRUCTURE', 'HARDWARE'] },
  { id: 'public', label: 'Public sector', categories: ['PUBLIC_SECTOR'] },
  { id: 'security', label: 'Security vendors', categories: ['SECURITY'] },
]

export const DIMENSION_LABEL: Record<DimensionId, string> = {
  VDP: 'VDP',
  CVE_QUALITY: 'CVE record quality',
  CVE_TIMELINESS: 'CVE timeliness',
}

export const ALIAS_KIND_LABEL: Record<AliasKind, string> = {
  LEGAL_NAME: 'Legal name',
  BRAND: 'Brand',
  SUBSIDIARY: 'Subsidiary',
  SIGNATORY_LISTING: 'Signatory listing',
  CNA_SHORT_NAME: 'CNA short name',
  CNA_ORG_ID: 'CNA org id',
  CPE_VENDOR: 'CPE vendor',
  AFFECTED_VENDOR: 'Affected vendor',
  ADVISORY_DOMAIN: 'Advisory domain',
  GITHUB_ORG: 'GitHub org',
}

export const DISPUTE_REASON_LABEL: Record<DisputeReason, string> = {
  INCORRECT_PRODUCT_MAPPING: 'Incorrect product mapping',
  INCORRECT_VENDOR_ATTRIBUTION: 'Incorrect vendor attribution',
  INCORRECT_CVE_MAPPING: 'Incorrect CVE mapping',
  OUTDATED_SOURCE: 'Outdated source',
  MISSING_SOURCE: 'Missing source',
  METHODOLOGY_ERROR: 'Methodology error',
}

export const GAP_LABEL: Record<string, string> = {
  NOT_PROVIDED: 'Not provided',
  PLACEHOLDER: 'Placeholder',
  MALFORMED: 'Malformed',
  NOT_FOUND: 'Not found',
  PARSER_FAILURE: 'Parser failure',
  NOT_APPLICABLE: 'Not applicable',
  NO_ELIGIBLE_RECORDS: 'No eligible records',
  NO_SOURCE: 'No machine-readable source',
  SOURCE_FAILED: 'Source unavailable',
  BELOW_MINIMUM_SAMPLE: 'Below minimum sample',
}

export function criterionLabel(c: string): string {
  return (VDP_CRITERION_LABELS as Record<string, string>)[c] ?? c
}

/** Label a coverage slot id ("vdp.criterion.X" or a metric id). */
export function slotLabel(slot: string, defs: MetricDefinition[]): string {
  if (slot.startsWith('vdp.criterion.')) return `VDP: ${criterionLabel(slot.slice('vdp.criterion.'.length))}`
  return defs.find((d) => d.id === slot)?.name ?? slot
}

export function defOf(summary: Pick<RunSummary, 'metricDefinitions'>, metricId: string): MetricDefinition | undefined {
  return summary.metricDefinitions.find((d) => d.id === metricId)
}

/** Find a metric value (and its goal) on a vendor summary. */
export function metricOf(v: Pick<VendorSummary, 'goals'>, metricId: string): { goal: GoalSummary; metric: MetricValue } | undefined {
  for (const goal of v.goals) {
    const metric = goal.metrics.find((m) => m.metricId === metricId)
    if (metric) return { goal, metric }
  }
  return undefined
}

export function dimensionOf(v: VendorSummary, dim: DimensionId) {
  return v.dimensions.find((d) => d.dimension === dim)
}

/** "Not measured: below minimum sample" — a missing value always says why, never 0 or a bare dash. */
export function notMeasured(m: Pick<MetricValue, 'gap'> | undefined): string {
  return m?.gap ? `Not measured: ${(GAP_LABEL[m.gap] ?? m.gap).toLowerCase()}` : 'Not measured'
}

/** A metric's value, or the reason it has none. */
export function metricText(m: Pick<MetricValue, 'value' | 'gap'> | undefined, def?: Pick<MetricDefinition, 'unit'>): string {
  if (!m) return 'Not reported in this run'
  return m.value === null ? notMeasured(m) : formatMetric(m.value, def)
}

/** Format a metric value by unit. */
export function formatMetric(value: number | null, def?: Pick<MetricDefinition, 'unit'>): string {
  if (value === null) return NOT_MEASURED
  switch (def?.unit) {
    case 'PERCENT':
      return pct(value)
    case 'DAYS':
      return days(value)
    case 'COUNT':
      return num(value)
    case 'RATIO':
      return num(value, 2)
    default:
      return num(value, 1)
  }
}

export function vendorName(summary: Pick<RunSummary, 'vendors'>, vendorId: string): string {
  return summary.vendors.find((v) => v.vendor.id === vendorId)?.vendor.canonicalName ?? vendorId
}

/** Words the product never uses about a vendor. Exported for the vocabulary test. */
export const BANNED_WORDS = ['compliant', 'non-compliant', 'secure', 'insecure', 'failed', 'fails']

/** Label for a metric breakdown key ("gap.NOT_PROVIDED", "reason.AMBIGUOUS_VENDOR", "missing_cwe"). */
export function breakdownLabel(key: string): string {
  const bare = key.replace(/^(gap|reason|not_eligible)\./, '')
  if (GAP_LABEL[bare]) return GAP_LABEL[bare]
  const s = bare.replace(/_/g, ' ').toLowerCase()
  return s.charAt(0).toUpperCase() + s.slice(1)
}

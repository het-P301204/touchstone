import type { CveRecord, Severity, VendorDetail } from '@touchstone/core/model'

const SEV_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']

/** Highest severity stated in the CNA container, else in any ADP container, else UNKNOWN. */
export function severityOf(c: CveRecord): { severity: Severity; from: 'CNA' | 'ADP' | null } {
  const pick = (list: { severity: Severity }[]) => list.map((x) => x.severity).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0]
  const cna = pick(c.cna.cvss)
  if (cna) return { severity: cna, from: 'CNA' }
  const adp = pick(c.adp.flatMap((a) => a.cvss))
  if (adp) return { severity: adp, from: 'ADP' }
  return { severity: 'UNKNOWN', from: null }
}

export type Completeness = 'COMPLETE' | 'ENRICHED_ONLY' | 'MISSING_CWE' | 'MISSING_CPE' | 'MISSING_BOTH' | 'PLACEHOLDER_CWE' | 'MALFORMED_CPE'

export const COMPLETENESS_LABEL: Record<Completeness, string> = {
  COMPLETE: 'CWE + CPE in CNA',
  ENRICHED_ONLY: 'Completed only by ADP',
  MISSING_CWE: 'CNA CWE not provided',
  MISSING_CPE: 'CNA CPE not provided',
  MISSING_BOTH: 'Neither in CNA',
  PLACEHOLDER_CWE: 'Placeholder CWE',
  MALFORMED_CPE: 'Malformed CPE',
}

/**
 * Field completeness of one record's CNA container (display classification;
 * the published metric additionally checks eligibility and CPE namespace).
 */
export function completenessOf(c: CveRecord): Completeness {
  const cweUsable = c.cna.cwes.some((w) => w.id && !w.placeholder)
  const cwePlaceholder = !cweUsable && c.cna.cwes.some((w) => w.placeholder)
  const cpeOk = c.cna.cpes.some((p) => p.wellFormed)
  const cpeMalformed = !cpeOk && c.cna.cpes.length > 0
  if (cweUsable && cpeOk) return 'COMPLETE'
  const adpCwe = c.adp.some((a) => a.cwes.some((w) => w.id && !w.placeholder))
  const adpCpe = c.adp.some((a) => a.cpes.some((p) => p.wellFormed))
  if ((cweUsable || adpCwe) && (cpeOk || adpCpe)) return 'ENRICHED_ONLY'
  if (cwePlaceholder) return 'PLACEHOLDER_CWE'
  if (cpeMalformed) return 'MALFORMED_CPE'
  if (!cweUsable && !cpeOk) return 'MISSING_BOTH'
  return cweUsable ? 'MISSING_CPE' : 'MISSING_CWE'
}

export type CveRow = { record: CveRecord; vendorId: string }

/** Every attributed record across vendor details (a record appears once per vendor detail that carries it). */
export function allCves(details: VendorDetail[]): CveRow[] {
  const out: CveRow[] = []
  const seen = new Set<string>()
  for (const d of details) {
    for (const c of d.cves) {
      const key = `${d.vendorId}:${c.id}:${c.sourceHash}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push({ record: c, vendorId: d.vendorId })
    }
  }
  return out
}

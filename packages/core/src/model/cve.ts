/**
 * Normalized CVE record and vendor advisory.
 *
 * The central distinction: the Secure by Design Pledge (Goal 6) asks the
 * MANUFACTURER to include accurate CWE and CPE fields in its CVE records.
 * In CVE JSON 5.x the manufacturer's own data lives in `containers.cna`
 * (when the manufacturer is the CNA, or supplied the data to one), while
 * third parties add data in `containers.adp[]` (for example CISA-ADP
 * "Vulnrichment") and NVD adds its own analysis. A record can look complete
 * on NVD because someone else enriched it. TOUCHSTONE credits only
 * CNA-supplied fields toward the pledge metric and reports enrichment
 * separately.
 */

import type { Confidence } from './vendor.ts'

/** Why a field has no usable value. Missing data is a first-class state. */
export type FieldGap =
  | 'NOT_PROVIDED' // the field is absent or empty in the source
  | 'PLACEHOLDER' // present but a placeholder, e.g. NVD-CWE-noinfo, NVD-CWE-Other
  | 'MALFORMED' // present but unparseable, e.g. a CPE that is not CPE 2.3
  | 'NOT_FOUND' // the record itself was not found in the source
  | 'PARSER_FAILURE' // the parser threw on this record
  | 'NOT_APPLICABLE' // the methodology excludes the field for this record

export type CweRef = {
  /** As written in the source, e.g. "CWE-79", "NVD-CWE-noinfo". */
  raw: string
  /** Normalized "CWE-<n>" or null when not a CWE identifier. */
  id: string | null
  placeholder: boolean
}

export type CpeRef = {
  raw: string
  /** Parsed CPE 2.3 fields when well-formed. */
  part?: 'a' | 'o' | 'h'
  vendor?: string
  product?: string
  wellFormed: boolean
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN'

export type CvssRef = {
  version: string // "3.1", "4.0", ...
  baseScore: number
  severity: Severity
  provider: 'CNA' | 'ADP' | 'NVD'
}

/** Data contributed by one container (the CNA, or one ADP provider). */
export type ContainerData = {
  provider: string // "CNA" or the ADP shortName, e.g. "CISA-ADP"
  cwes: CweRef[]
  cpes: CpeRef[]
  cvss: CvssRef[]
}

export type CveState = 'PUBLISHED' | 'REJECTED'

export type CveRecord = {
  /** "CVE-YYYY-NNNN+" for real data; "DEMO-YYYY-NNNN+" for synthetic demo data. */
  id: string
  state: CveState
  assigner: { orgId: string; shortName: string }
  dateReserved?: string
  datePublished?: string
  dateUpdated?: string
  /** containers.cna.datePublic when present. */
  datePublic?: string
  title?: string
  /** containers.cna.affected[] vendor/product pairs as written. */
  affected: { vendor: string; product: string }[]
  cna: ContainerData
  adp: ContainerData[]
  /** Schema dataVersion, e.g. "5.1". */
  dataVersion: string
  snapshotId: string
  /** sha256 of the canonical JSON of the source record. */
  sourceHash: string
  synthetic: boolean
}

/** How a CVE record came to be attributed to a vendor. */
export type AttributionRule =
  | 'ASSIGNER_IS_VENDOR_CNA' // assigner orgId/shortName is an alias of the vendor
  | 'AFFECTED_VENDOR_AND_CPE' // cna.affected vendor alias AND a CPE in the vendor's namespace
  | 'AFFECTED_VENDOR_ONLY' // cna.affected vendor alias without corroborating CPE

export type Attribution = {
  cveId: string
  vendorId: string
  rule: AttributionRule
  confidence: Confidence
  /** The aliases that matched, for the evidence trail. */
  matched: { kind: string; value: string }[]
}

/** A record that could not be attributed to exactly one vendor. */
export type AttributionExclusion = {
  cveId: string
  reason: 'AMBIGUOUS_VENDOR' | 'IDENTITY_CONFLICT' | 'FREE_TEXT_ONLY' | 'REJECTED_RECORD' | 'DUPLICATE_CONFLICT'
  candidateVendorIds: string[]
  note: string
}

export type Advisory = {
  /** Vendor's tracking id, e.g. CSAF document.tracking.id. */
  id: string
  vendorId: string
  url: string
  title: string
  /** CSAF tracking.initial_release_date. */
  publishedAt: string
  /** Highest severity the advisory itself states; UNKNOWN if not stated. */
  severity: Severity
  cveIds: string[]
  snapshotId: string
  synthetic: boolean
}

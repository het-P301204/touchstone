/**
 * Vendor identity. A vendor appears under many names: legal name, brand,
 * subsidiary, CVE CNA short name, CPE vendor namespace, advisory domain,
 * GitHub organisation. TOUCHSTONE keeps every link between a name and a
 * canonical vendor as an explicit, evidenced mapping and never merges two
 * identities silently.
 */

export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW'

export type AliasKind =
  | 'LEGAL_NAME'
  | 'BRAND'
  | 'SUBSIDIARY'
  | 'SIGNATORY_LISTING' // the exact string on the CISA signer list
  | 'CNA_SHORT_NAME' // cveMetadata.assignerShortName
  | 'CNA_ORG_ID' // cveMetadata.assignerOrgId (UUID)
  | 'CPE_VENDOR' // the vendor field of a CPE 2.3 name
  | 'AFFECTED_VENDOR' // containers.cna.affected[].vendor string
  | 'ADVISORY_DOMAIN'
  | 'GITHUB_ORG'

export type IdentityEvidence = {
  /** Plain statement of why this name belongs to this vendor. */
  statement: string
  /** Where the statement can be checked. */
  url?: string
  snapshotId?: string
}

export type Alias = {
  kind: AliasKind
  value: string
  confidence: Confidence
  evidence: IdentityEvidence[]
}

export type SignatoryStatus =
  | 'LISTED' // present on the latest successful signer-list snapshot
  | 'NOT_LISTED' // absent from the latest successful snapshot
  | 'UNKNOWN' // no successful signer-list snapshot available

export type VendorCategory =
  | 'ENTERPRISE_SOFTWARE'
  | 'CLOUD'
  | 'NETWORKING'
  | 'SECURITY'
  | 'INFRASTRUCTURE'
  | 'PUBLIC_SECTOR'
  | 'EDUCATION'
  | 'DEVELOPER_TOOLS'
  | 'HARDWARE'
  | 'OTHER'

export type Vendor = {
  /** URL-safe slug, e.g. "northwind-systems". */
  id: string
  canonicalName: string
  aliases: Alias[]
  signatoryStatus: SignatoryStatus
  /** Date the vendor appears to have signed, when a source states it. Never guessed. */
  signedOn?: string
  category: VendorCategory
  /** Free-text industry label, only when sourced. */
  industry?: string
  /** Size band, only when sourced; otherwise absent (not "unknown" text). */
  sizeBand?: 'SMALL' | 'MEDIUM' | 'LARGE'
  region?: string
  /** Domains TOUCHSTONE may fetch public policy documents from. */
  domains: string[]
  /** Optional CSAF provider-metadata.json URL. */
  csafProviderUrl?: string
  /** Optional explicit VDP policy URL (when not discoverable from security.txt). */
  vdpPolicyUrl?: string
  /** Self-reported pledge progress statements: claims, never evidence. */
  claims: VendorClaim[]
  /** DEMO vendors are synthetic. The UI must label them as such. */
  synthetic: boolean
}

/** A vendor's own public statement about pledge progress. Shown as a claim. */
export type VendorClaim = {
  goalId: string
  summary: string
  url?: string
  publishedOn?: string
}

/**
 * A detected collision: one name that resolves to more than one vendor, or
 * one vendor whose aliases conflict. Records involved are excluded from
 * metrics until the conflict is resolved by an explicit registry decision.
 */
export type IdentityConflict = {
  id: string
  kind: 'NAME_COLLISION' | 'CNA_SHARED' | 'CPE_NAMESPACE_SHARED'
  value: string
  aliasKind: AliasKind
  vendorIds: string[]
  affectedRecordIds: string[]
  note: string
}

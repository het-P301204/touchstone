/**
 * The fictional vendor cast of the demo dataset, one scenario each.
 *
 * Every name is invented; every URL uses the reserved .example TLD. The
 * generator (generate.ts) turns these specs into raw source documents: CVE
 * JSON 5.1 records, CSAF 2.0 advisories, security.txt files, policy pages and
 * signer-list pages. SCENARIOS.md is written from the `scenario` and
 * `expected` fields.
 */

import type { VendorCategory } from '../../packages/core/src/model/index.ts'

export type CpeQuality = { good: number; wrongNamespace: number; malformed: number }

export type VdpProfile =
  | 'STRONG'
  | 'STRONG_ALT' // strong, different wording (safe harbor via "safe harbor ... good faith", disclosure via "coordinated disclosure")
  | 'WEAK_NO_SAFE_HARBOR'
  | 'PROHIBITIVE'
  | 'NONE'
  | 'NARROWING' // strong until NARROWING_FROM, then scope and testing limited to web properties
  | 'PLATFORM' // policy hosted on a known disclosure platform
  | 'UNDATED_EXPIRED' // policy without a date; security.txt Expires fixed in the past from 2026-04-06
  | 'OLD_NO_STXT' // no security.txt; policy states an update older than the window

export type VendorSpec = {
  id: string
  name: string
  legalName: string
  /** Exactly as printed on the (fictional) signer list. */
  listing: string
  category: VendorCategory
  domain: string
  /** The vendor's own CNA, or null when its records come from a third-party CNA. */
  cna: { shortName: string } | null
  /** CPE vendor namespaces registered for this vendor. */
  cpeVendors: string[]
  /** Names used for the vendor in cna.affected[].vendor. */
  affectedNames: string[]
  products: string[]
  /** CPE part used for products. */
  cpePart: 'a' | 'o' | 'h'
  /** First dataset version on which the vendor is listed as a signatory (default: all). */
  listedFrom?: string
  signedOn?: string
  /** Records over the whole generated timeline (2023-10 .. 2026-09). */
  records: number
  /** Share of records whose CNA container carries a real CWE / a placeholder CWE (rest: none). */
  cwe: { real: number; placeholder: number }
  /** Share of records whose CNA container carries CPEs, and their quality. */
  cpe: { rate: number; quality: CpeQuality }
  /** Probability CISA-ADP adds a CWE / CPE when the CNA did not (after 30 days). */
  adpEnrichment: { cwe: number; cpe: number }
  /** Write CPEs via cpeApplicability (5.1.1 style) instead of affected[].cpes. */
  cpeApplicability?: boolean
  csaf: boolean
  /** Advisory timing: share of high-impact CVEs published within a day of the advisory. */
  timelyShare: number
  /** High-impact advisories issued without a CVE. */
  advisoriesWithoutCve?: number
  vdp: VdpProfile
  /** Snapshot age, in days before the version date, for this vendor's VDP and CSAF sources (stale source). */
  staleDays?: number
  /** Dataset version in which the policy fetch FAILS and the previous snapshot is carried. */
  policyFetchFailsIn?: string
  /** Shift the CWE mix over time away from memory-safety classes (Goal 3 signal). */
  classShift?: boolean
  scenario: string
  expected: string[]
  industry?: string
  sizeBand?: 'SMALL' | 'MEDIUM' | 'LARGE'
  region?: string
}

const GOOD: CpeQuality = { good: 1, wrongNamespace: 0, malformed: 0 }

export const NARROWING_FROM = '2026-07-06'
export const COPPERLEAF_EXPIRES = '2026-02-01T00:00:00Z'

export const VENDORS: VendorSpec[] = [
  {
    id: 'northwind-systems', name: 'Northwind Systems', legalName: 'Northwind Systems, Inc.', listing: 'Northwind Systems',
    category: 'ENTERPRISE_SOFTWARE', domain: 'northwind.example', cna: { shortName: 'northwind' }, cpeVendors: ['northwind'],
    affectedNames: ['Northwind Systems'], products: ['Ledger Suite', 'Northwind Gateway', 'Northwind Agent'], cpePart: 'a',
    signedOn: '2024-05-08', records: 54, cwe: { real: 1, placeholder: 0 }, cpe: { rate: 1, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    cpeApplicability: true, csaf: true, timelyShare: 0.95, vdp: 'STRONG', classShift: true, sizeBand: 'LARGE', region: 'North America',
    scenario: 'Complete vendor: own CNA, CWE and CPE on every record, CSAF feed with timely CVEs, strong VDP, memory-safety share falling over time.',
    expected: ['Goal 5 VERIFIED: 8/8 criteria MET, 4/4 pledge elements', 'Goal 6 VERIFIED: CWE 100%, CPE 100%, namespace 100%, complete records 100%', 'CVE timeliness high', 'Goal 3 class-share signal present (memory-safety share falls)'],
  },
  {
    id: 'halcyon-cloud', name: 'Halcyon Cloud', legalName: 'Halcyon Cloud LLC', listing: 'Halcyon Cloud, Inc.',
    category: 'CLOUD', domain: 'halcyon.example', cna: { shortName: 'halcyon' }, cpeVendors: ['halcyon'],
    affectedNames: ['Halcyon Cloud'], products: ['Halcyon Compute', 'Halcyon Object Store', 'Halcyon IAM'], cpePart: 'a',
    signedOn: '2024-05-08', records: 36, cwe: { real: 0.55, placeholder: 0 }, cpe: { rate: 1, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.9, vdp: 'STRONG_ALT', sizeBand: 'LARGE',
    scenario: 'Missing CWE: about 45% of CNA containers carry no CWE (some only a free-text problem type). Listed as "Halcyon Cloud, Inc." (suffix stripped for matching). security.txt is PGP-signed.',
    expected: ['Goal 6 PARTIAL: CWE coverage about 55%, gap NOT_PROVIDED', 'CPE coverage 100%', 'Goal 5 VERIFIED'],
  },
  {
    id: 'brightwater-networks', name: 'Brightwater Networks', legalName: 'Brightwater Networks Corporation', listing: 'Brightwater Networks',
    category: 'NETWORKING', domain: 'brightwater.example', cna: { shortName: 'brightwater' }, cpeVendors: ['brightwater'],
    affectedNames: ['Brightwater Networks'], products: ['Riverline Router', 'Brightwater OS', 'Estuary Switch'], cpePart: 'o',
    signedOn: '2024-05-08', records: 36, cwe: { real: 0.95, placeholder: 0 }, cpe: { rate: 0.35, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.3, advisoriesWithoutCve: 3, vdp: 'STRONG',
    scenario: 'Missing CPE: CNA CPEs are drawn with probability 0.35, which for this seed gave 9 of 36 records (25%); the rest carry no CPE. CVE issuance lags advisories (most CVEs 5-45 days after the advisory); three high-impact advisories list no CVE.',
    expected: ['Goal 6 PARTIAL: CPE coverage about 25% (20-30% across versions), gap NOT_PROVIDED', 'CVE timeliness low; latency median > 1 day', 'high_impact_with_cve below 100%', 'LATENCY_OUTLIER possible'],
  },
  {
    id: 'cobalt-ridge-software', name: 'Cobalt Ridge Software', legalName: 'Cobalt Ridge Software Ltd', listing: 'Cobalt Ridge Software',
    category: 'DEVELOPER_TOOLS', domain: 'cobaltridge.example', cna: { shortName: 'cobaltridge' }, cpeVendors: ['cobalt_ridge'],
    affectedNames: ['Cobalt Ridge Software'], products: ['Forge CI', 'Ridge Package Registry'], cpePart: 'a',
    signedOn: '2024-05-08', records: 30, cwe: { real: 0.97, placeholder: 0 }, cpe: { rate: 1, quality: { good: 0.5, wrongNamespace: 0.3, malformed: 0.2 } }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.85, vdp: 'STRONG_ALT',
    scenario: 'Mixed CPE quality: half the CPEs use the registered namespace cobalt_ridge, about 30% an unregistered namespace (cobaltridge), about 20% are malformed (CPE 2.2 URIs or truncated 2.3 strings).',
    expected: ['cve.cpe_namespace_consistency well below 100%', 'malformed CPEs counted as MALFORMED, not as provided', 'Goal 6 PARTIAL'],
  },
  {
    id: 'lanternfish-security', name: 'Lanternfish Security', legalName: 'Lanternfish Security, Inc.', listing: 'Lanternfish Security',
    category: 'SECURITY', domain: 'lanternfish.example', cna: { shortName: 'lanternfish' }, cpeVendors: ['lanternfish'],
    affectedNames: ['Lanternfish Security'], products: ['Lanternfish EDR', 'Lanternfish Console'], cpePart: 'a',
    signedOn: '2024-05-08', records: 36, cwe: { real: 0.5, placeholder: 0.46 }, cpe: { rate: 1, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.9, vdp: 'STRONG',
    scenario: 'Placeholder CWE user: about 46% of CNA containers state NVD-CWE-noinfo.',
    expected: ['Methodology 1.0.0 (2025-10-06 .. 2026-04-06): CWE coverage about 96%', 'Methodology 1.1.0 (2026-07-06, 2026-10-06): CWE coverage about 50%, gap PLACEHOLDER; complete records fall accordingly', 'The drop is a methodology change, not a vendor change: earlier runs keep their figures'],
  },
  {
    id: 'quillmark-labs', name: 'Quillmark Labs', legalName: 'Quillmark Labs GmbH', listing: 'Quillmark Labs',
    category: 'DEVELOPER_TOOLS', domain: 'quillmark.example', cna: { shortName: 'quillmark' }, cpeVendors: ['quillmark'],
    affectedNames: ['Quillmark Labs'], products: ['Quillmark Editor', 'Quillmark Sync'], cpePart: 'a', region: 'Europe',
    signedOn: '2024-06-20', records: 24, cwe: { real: 0.95, placeholder: 0 }, cpe: { rate: 0.95, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.85, vdp: 'STRONG',
    scenario: 'Duplicate CVEs: three record ids are also served by a bulk mirror with different content (DUPLICATE_CONFLICT, both copies excluded); two more are mirrored byte-identically (collapsed, not excluded).',
    expected: ['cve.duplicate_conflicts = 3 once those records are in the snapshot', 'excluded records listed with reason DUPLICATE_CONFLICT'],
  },
  {
    id: 'summit-peak-software', name: 'Summit Peak Software', legalName: 'Summit Peak Software Inc', listing: 'Summit Peak Software',
    category: 'ENTERPRISE_SOFTWARE', domain: 'summitpeak.example', cna: { shortName: 'summitpeak' }, cpeVendors: ['summit_peak'],
    affectedNames: ['Summit Peak Software', 'Summit'], products: ['Summit Scheduler', 'Summit Directory'], cpePart: 'a',
    signedOn: '2024-05-08', records: 18, cwe: { real: 0.95, placeholder: 0 }, cpe: { rate: 0.9, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.9, vdp: 'STRONG',
    scenario: 'Ambiguous attribution (with Summit Analytics): both vendors appear as "Summit" in affected[].vendor. Records from a third-party CNA naming only "Summit" fit both vendors.',
    expected: ['Records naming only "Summit" excluded as AMBIGUOUS_VENDOR, candidates summit-analytics and summit-peak-software', 'Own-CNA records attributed normally'],
  },
  {
    id: 'summit-analytics', name: 'Summit Analytics', legalName: 'Summit Analytics Corp.', listing: 'Summit Analytics',
    category: 'CLOUD', domain: 'summitanalytics.example', cna: { shortName: 'summitanalytics' }, cpeVendors: ['summit_analytics'],
    affectedNames: ['Summit Analytics', 'Summit'], products: ['Summit Insight', 'Summit Pipeline'], cpePart: 'a',
    signedOn: '2024-08-14', records: 16, cwe: { real: 0.9, placeholder: 0 }, cpe: { rate: 0.9, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.85, vdp: 'STRONG_ALT',
    scenario: 'Ambiguous attribution (with Summit Peak Software). See summit-peak-software.',
    expected: ['Same AMBIGUOUS_VENDOR exclusions as summit-peak-software'],
  },
  {
    id: 'ferrous-industrial', name: 'Ferrous Industrial', legalName: 'Ferrous Industrial AG', listing: 'Ferrous Industrial',
    category: 'INFRASTRUCTURE', domain: 'ferrous.example', cna: { shortName: 'ferrous' }, cpeVendors: ['ferrous', 'kestrel'],
    affectedNames: ['Ferrous Industrial'], products: ['Foundry PLC', 'Ferrous HMI'], cpePart: 'o', region: 'Europe',
    signedOn: '2024-05-08', records: 22, cwe: { real: 0.9, placeholder: 0 }, cpe: { rate: 0.95, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.8, vdp: 'STRONG',
    scenario: 'Alias collision after an acquisition: Ferrous acquired the Kestrel controller line and registered the CPE namespace "kestrel", which Kestrel Controls still uses.',
    expected: ['IdentityConflict CPE_NAMESPACE_SHARED on "kestrel" (ferrous-industrial, kestrel-controls)', 'Ferrous own-CNA records attributed (ASSIGNER_IS_VENDOR_CNA)'],
  },
  {
    id: 'kestrel-controls', name: 'Kestrel Controls', legalName: 'Kestrel Controls, Inc.', listing: 'Kestrel Controls',
    category: 'HARDWARE', domain: 'kestrel.example', cna: null, cpeVendors: ['kestrel'],
    affectedNames: ['Kestrel Controls'], products: ['Kestrel RTU', 'Kestrel Gateway'], cpePart: 'o',
    signedOn: '2024-09-30', records: 16, cwe: { real: 0.85, placeholder: 0 }, cpe: { rate: 0.6, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.7, vdp: 'STRONG',
    scenario: 'Alias collision (with Ferrous Industrial). Kestrel is not a CNA: its records come from a third-party CNA. Records whose CNA CPE uses the shared "kestrel" namespace are excluded as IDENTITY_CONFLICT; records without a CPE are attributed with MEDIUM confidence (AFFECTED_VENDOR_ONLY).',
    expected: ['About 60% of records excluded as IDENTITY_CONFLICT', 'Remaining records AFFECTED_VENDOR_ONLY (MEDIUM)', 'Goal 6 sample may fall below the minimum'],
  },
  {
    id: 'copperleaf-learning', name: 'Copperleaf Learning', legalName: 'Copperleaf Learning LLC', listing: 'Copperleaf Learning',
    category: 'EDUCATION', domain: 'copperleaf.example', cna: null, cpeVendors: ['copperleaf'],
    affectedNames: ['Copperleaf Learning'], products: ['Copperleaf Classroom', 'Copperleaf Gradebook'], cpePart: 'a', sizeBand: 'SMALL',
    signedOn: '2024-05-08', records: 14, cwe: { real: 0.9, placeholder: 0 }, cpe: { rate: 0.85, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: false, timelyShare: 0, vdp: 'UNDATED_EXPIRED',
    scenario: 'Expired security.txt: Expires 2026-02-01; the policy states no date. Records from a third-party CNA, attributed by affected vendor + CPE (AFFECTED_VENDOR_AND_CPE). No CSAF feed.',
    expected: ['2025-10-06, 2026-01-06: CURRENT MET (security.txt valid)', '2026-04-06 onward: CURRENT NOT_MET (VDP.CURRENT.EXPIRED), security.txt warning EXPIRED', 'Timeliness NOT_VERIFIED (no advisory source)'],
  },
  {
    id: 'tessellate-data', name: 'Tessellate Data', legalName: 'Tessellate Data Corporation', listing: 'Tessellate Data',
    category: 'ENTERPRISE_SOFTWARE', domain: 'tessellate.example', cna: { shortName: 'tessellate' }, cpeVendors: ['tessellate'],
    affectedNames: ['Tessellate Data'], products: ['Tessellate Warehouse', 'Tessellate Connect'], cpePart: 'a',
    signedOn: '2024-05-08', records: 22, cwe: { real: 0.95, placeholder: 0 }, cpe: { rate: 0.95, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.9, vdp: 'WEAK_NO_SAFE_HARBOR',
    scenario: 'Weak VDP: the policy authorizes testing, gives a channel and allows coordinated disclosure, but makes no commitment about legal action.',
    expected: ['Goal 5 PARTIAL: safe harbor NOT_MET (VDP.NO_MATCH)', '3/4 pledge elements MET'],
  },
  {
    id: 'gravelpoint-civic', name: 'Gravelpoint Civic Software', legalName: 'Gravelpoint Civic Software, Inc.', listing: 'Gravelpoint Civic Software',
    category: 'PUBLIC_SECTOR', domain: 'gravelpoint.example', cna: null, cpeVendors: ['gravelpoint'],
    affectedNames: ['Gravelpoint Civic Software', 'Gravelpoint'], products: ['Permit Desk', 'Civic Records'], cpePart: 'a',
    signedOn: '2024-05-08', records: 14, cwe: { real: 0.9, placeholder: 0 }, cpe: { rate: 0.8, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.8, vdp: 'PROHIBITIVE',
    scenario: 'VDP with prohibitive language: testing requires prior written permission, legal action is reserved, disclosure is forbidden without written consent.',
    expected: ['TESTING_AUTHORIZED, GOOD_FAITH_SAFE_HARBOR, PUBLIC_DISCLOSURE_ALLOWED CONTRADICTED, each with a quoted ProhibitiveFinding', 'Goal 5 PARTIAL or NOT_VERIFIED; reporting channel MET'],
  },
  {
    id: 'orchard-lane-robotics', name: 'Orchard Lane Robotics', legalName: 'Orchard Lane Robotics Ltd.', listing: 'Orchard Lane Robotics',
    category: 'HARDWARE', domain: 'orchardlane.example', cna: null, cpeVendors: ['orchard_lane'],
    affectedNames: ['Orchard Lane Robotics'], products: ['Picker Arm Controller', 'Orchard Fleet Manager'], cpePart: 'h',
    signedOn: '2024-05-08', records: 12, cwe: { real: 0.85, placeholder: 0 }, cpe: { rate: 0.3, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: false, timelyShare: 0, vdp: 'NONE',
    scenario: 'No VDP at all: security.txt returns 404, no policy URL is known. No CSAF feed. Third-party CNA records.',
    expected: ['All VDP criteria NOT_MET (not UNKNOWN: the sources were read and nothing exists)', 'Goal 5 NOT_VERIFIED', 'Timeliness NOT_VERIFIED'],
  },
  {
    id: 'saltmarsh-software', name: 'Saltmarsh Software', legalName: 'Saltmarsh Software Inc.', listing: 'Saltmarsh Software',
    category: 'ENTERPRISE_SOFTWARE', domain: 'saltmarsh.example', cna: { shortName: 'saltmarsh' }, cpeVendors: ['saltmarsh'],
    affectedNames: ['Saltmarsh Software'], products: ['Saltmarsh ERP', 'Tidewater Portal'], cpePart: 'a',
    signedOn: '2024-05-08', records: 26, cwe: { real: 0.95, placeholder: 0 }, cpe: { rate: 0.95, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: false, timelyShare: 0, vdp: 'OLD_NO_STXT',
    scenario: 'No CSAF feed: timeliness cannot be measured. No security.txt; the policy states it was last updated in 2023.',
    expected: ['cve.timely_issuance not measurable; CVE_TIMELINESS NOT_VERIFIED', 'CURRENT NOT_MET (VDP.CURRENT.POLICY_OLD)', 'CVE quality measured normally'],
  },
  {
    id: 'ember-oak-devices', name: 'Ember & Oak Devices', legalName: 'Ember & Oak Devices, Inc.', listing: 'Ember & Oak Devices',
    category: 'HARDWARE', domain: 'emberoak.example', cna: { shortName: 'emberoak' }, cpeVendors: ['ember_and_oak'],
    affectedNames: ['Ember & Oak Devices'], products: ['Hearth Thermostat', 'Oak Hub'], cpePart: 'o',
    signedOn: '2024-05-08', records: 20, cwe: { real: 0.95, placeholder: 0 }, cpe: { rate: 0.95, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.85, vdp: 'NARROWING',
    scenario: 'VDP scope narrows between 2026-04-06 and 2026-07-06: the policy stops covering devices and authorizes testing of web properties only. The ampersand in the name exercises entity decoding on the signer page.',
    expected: ['2026-07-06: VdpChange with SCOPE_DEFINED MET -> PARTIAL and TESTING_AUTHORIZED MET -> PARTIAL; review recommended (pledge criterion changed)', 'textHash changes'],
  },
  {
    id: 'palisade-mobile', name: 'Palisade Mobile', legalName: 'Palisade Mobile Ltd', listing: 'Palisade Mobile',
    category: 'SECURITY', domain: 'palisade.example', cna: { shortName: 'palisade' }, cpeVendors: ['palisade'],
    affectedNames: ['Palisade Mobile'], products: ['Palisade MDM', 'Palisade Shield'], cpePart: 'a',
    signedOn: '2024-05-08', records: 20, cwe: { real: 0.9, placeholder: 0 }, cpe: { rate: 0.9, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.85, vdp: 'STRONG', staleDays: 52,
    scenario: 'Stale source: the vendor’s security.txt, policy and CSAF sources were last fetched 52 days before each version date (not refreshed this cycle).',
    expected: ['Freshness STALE for VENDOR_VDP, SECURITY_TXT and VENDOR_ADVISORY sources of this vendor', 'Figures still computed, labelled with source age'],
  },
  {
    id: 'wrenfield-software', name: 'Wrenfield Software', legalName: 'Wrenfield Software, Inc.', listing: 'Wrenfield Software',
    category: 'DEVELOPER_TOOLS', domain: 'wrenfield.example', cna: { shortName: 'wrenfield' }, cpeVendors: ['wrenfield'],
    affectedNames: ['Wrenfield Software'], products: ['Wrenfield IDE', 'Wrenfield Build Cache'], cpePart: 'a',
    signedOn: '2024-05-08', records: 20, cwe: { real: 0.95, placeholder: 0 }, cpe: { rate: 0.95, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.9, vdp: 'STRONG', policyFetchFailsIn: '2026-10-06',
    scenario: 'Source failure: in 2026-10-06 the policy fetch FAILED (timeout). The run records the FAILED snapshot and substitutes the 2026-07-06 snapshot explicitly (substitutedBy); the observation is labelled carriedFromSnapshotId.',
    expected: ['2026-10-06: policy snapshot FAILED with substitutedBy; VdpObservation.carriedFromSnapshotId set', 'Freshness for the policy source AGING/STALE (age from last success, not last attempt)', 'Criteria unchanged from 2026-07-06'],
  },
  {
    id: 'tinderbox-studio', name: 'Tinderbox Studio', legalName: 'Tinderbox Studio LLC', listing: 'Tinderbox Studio',
    category: 'DEVELOPER_TOOLS', domain: 'tinderbox.example', cna: { shortName: 'tinderbox' }, cpeVendors: ['tinderbox'],
    affectedNames: ['Tinderbox Studio'], products: ['Tinderbox Engine'], cpePart: 'a', sizeBand: 'SMALL',
    signedOn: '2024-11-12', records: 4, cwe: { real: 1, placeholder: 0 }, cpe: { rate: 1, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 1, vdp: 'STRONG_ALT',
    scenario: 'Below minimum sample: at most 3 eligible records in any window (minimumEligibleRecords = 5).',
    expected: ['CVE metrics value null with gap BELOW_MINIMUM_SAMPLE (never 0, never 100)', 'Goal 5 measured normally'],
  },
  {
    id: 'larkspur-cloud', name: 'Larkspur Cloud Services', legalName: 'Larkspur Cloud Services, Inc.', listing: 'Larkspur Cloud Services',
    category: 'CLOUD', domain: 'larkspur.example', cna: { shortName: 'larkspur' }, cpeVendors: ['larkspur'],
    affectedNames: ['Larkspur Cloud Services'], products: ['Larkspur Functions', 'Larkspur Queue', 'Larkspur Console'], cpePart: 'a',
    signedOn: '2024-05-08', records: 40, cwe: { real: 0.15, placeholder: 0 }, cpe: { rate: 0.1, quality: GOOD }, adpEnrichment: { cwe: 0.95, cpe: 0.95 },
    csaf: true, timelyShare: 0.9, vdp: 'STRONG',
    scenario: 'Heavy CISA-ADP enrichment: the CNA container rarely carries CWE (15%) or CPE (10%); CISA-ADP adds both about 30 days after publication. The records look complete on aggregators.',
    expected: ['CNA-only CWE coverage about 15%, CPE about 10%: Goal 6 PARTIAL/NOT_VERIFIED', 'cve.enriched_only high (most records)', 'Records published < 30 days before a version have no ADP container yet'],
  },
  {
    id: 'foxglove-identity', name: 'Foxglove Identity', legalName: 'Foxglove Identity, Inc.', listing: 'Foxglove Identity',
    category: 'SECURITY', domain: 'foxglove.example', cna: { shortName: 'foxglove' }, cpeVendors: ['foxglove'],
    affectedNames: ['Foxglove Identity'], products: ['Foxglove SSO', 'Foxglove Vault'], cpePart: 'a',
    listedFrom: '2026-01-06', signedOn: '2025-12-10', records: 18, cwe: { real: 0.95, placeholder: 0 }, cpe: { rate: 0.95, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.9, vdp: 'STRONG',
    scenario: 'Late signer: absent from the 2025-10-06 signer page, listed from 2026-01-06.',
    expected: ['2025-10-06: signatoryStatus NOT_LISTED', '2026-01-06 onward: LISTED'],
  },
  {
    id: 'basalt-infrastructure', name: 'Basalt Infrastructure', legalName: 'Basalt Infrastructure Corp', listing: 'Basalt Infrastructure',
    category: 'INFRASTRUCTURE', domain: 'basalt.example', cna: { shortName: 'basalt' }, cpeVendors: ['basalt'],
    affectedNames: ['Basalt Infrastructure'], products: ['Basalt Hypervisor', 'Basalt Storage Array'], cpePart: 'a',
    signedOn: '2024-05-08', records: 28, cwe: { real: 0.97, placeholder: 0 }, cpe: { rate: 0.97, quality: GOOD }, adpEnrichment: { cwe: 0, cpe: 0 },
    csaf: true, timelyShare: 0.9, vdp: 'PLATFORM', classShift: true,
    scenario: 'Policy hosted on a known disclosure platform (disclosure-platform.example), linked from security.txt Policy:.',
    expected: ['POLICY_DISCOVERABLE MET via VDP.DISCOVERABLE.STXT; policy.host is the platform', 'Goal 5 VERIFIED'],
  },
]

/** Fictional names that pad the signer list (signatories outside the registry). */
export const FILLER_SIGNATORIES: string[] = [
  'Amberline Analytics', 'Arbor Vale Health IT', 'Bellwether Mesh', 'Birchgate Payments', 'Bluefen Robotics', 'Calder Point Labs',
  'Canopy Ledger', 'Cinderpath Games', 'Clearbrook Telematics', 'Coldharbor Data', 'Driftwood Logistics Software', 'Dunmore Signal',
  'Eastmere Systems', 'Fallowfield AgriTech', 'Fernbank Learning', 'Flintlock Devices', 'Glasswing Observability', 'Greyhaven Identity',
  'Harrowgate Retail Cloud', 'Heathrow Lane Media', 'Ironbark Compute', 'Juniper Hollow Software', 'Kittiwake Security', 'Lowmoor Utilities Software',
  'Marram Health', 'Millbrook Fintech', 'Moorland Mapping', 'Nettlebed Networks', 'Oakhurst Civic', 'Pebblecreek Studios',
  'Quarrystone Storage', 'Redwater Sensors', 'Rushmere Cloud', 'Saffron Hill Software', 'Sloeberry Apps', 'Stonechat Systems',
  'Thornbury Telecom', 'Umberfield Labs', 'Westerly Automation', 'Yarrowby Software',
]

/** Third-party CNA used for vendors that are not CNAs (fictional). */
export const THIRD_PARTY_CNA = { shortName: 'DEMO-CC', name: 'Example Coordination Center' }

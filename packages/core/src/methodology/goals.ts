/**
 * The seven Secure by Design Pledge goals, as structured data.
 *
 * Pledge text is quoted verbatim from https://www.cisa.gov/securebydesign/pledge
 * (checked 2026-10-06). The verification mode of each goal is a property of
 * the public evidence boundary, not of any vendor:
 *
 *   G5 VDP                 PUBLICLY_MEASURABLE   (a public policy can be read)
 *   G6 CVEs                PUBLICLY_MEASURABLE   (CVE records and advisories are public)
 *   G3 Vulnerability class PARTIALLY_MEASURABLE  (disclosed-CWE mix is a signal, not the outcome)
 *   G1, G2, G4, G7         NOT_EXTERNALLY_VERIFIABLE
 *
 * The UI, API and reports read goals from here; no goal text is hard-coded
 * anywhere else.
 */

import type { SecurityCommitmentGoal } from '../model/index.ts'

export const PLEDGE_SOURCE_URL = 'https://www.cisa.gov/securebydesign/pledge'

export const GOALS: SecurityCommitmentGoal[] = [
  {
    id: 'G1',
    number: 1,
    name: 'Multi-factor authentication',
    shortName: 'MFA',
    pledgeText:
      "Within one year of signing the pledge, demonstrate actions taken to measurably increase the use of multi-factor authentication across the manufacturer's products.",
    description: 'Increase use of MFA across the manufacturer’s products.',
    verificationMode: 'NOT_EXTERNALLY_VERIFIABLE',
    evidenceRequirements: [
      { id: 'G1.R1', description: 'MFA adoption rate across customer accounts, over time', publiclyAvailable: false },
      { id: 'G1.R2', description: 'Scope of products and account types the rate covers', publiclyAvailable: false },
      { id: 'G1.R3', description: 'Independent audit or attestation of the measurement', publiclyAvailable: false },
    ],
    methodology: {
      summary:
        'Adoption of MFA is measured inside the vendor’s own telemetry. No public source reports it in a form that a third party can check.',
      metricIds: [],
      statusRule: 'Always NOT_EXTERNALLY_VERIFIABLE. A vendor statement is shown as a claim, never as evidence.',
      evidenceNeeded: [
        'Independently audited adoption rate',
        'Scoped customer and employee coverage',
        'Measurement methodology',
        'Time period and baseline',
      ],
      limitations: ['Product documentation can show that MFA is available; it cannot show that it is used.'],
    },
  },
  {
    id: 'G2',
    number: 2,
    name: 'Default passwords',
    shortName: 'Default passwords',
    pledgeText:
      "Within one year of signing the pledge, demonstrate measurable progress towards reducing default passwords across the manufacturers' products.",
    description: 'Reduce default passwords across products.',
    verificationMode: 'NOT_EXTERNALLY_VERIFIABLE',
    evidenceRequirements: [
      { id: 'G2.R1', description: 'Inventory of products and their credential provisioning model', publiclyAvailable: false },
      { id: 'G2.R2', description: 'Share of shipped units or deployments with unique or no default credentials', publiclyAvailable: false },
    ],
    methodology: {
      summary:
        'Verifying default credentials would require testing products or devices. TOUCHSTONE does no testing of vendor products or infrastructure, so it does not measure this goal.',
      metricIds: [],
      statusRule: 'Always NOT_EXTERNALLY_VERIFIABLE.',
      evidenceNeeded: [
        'Product inventory with credential provisioning model',
        'Independent product testing results',
        'Time period and baseline',
      ],
      limitations: ['CVE records citing hard-coded credentials (CWE-798) show past defects, not current defaults.'],
    },
  },
  {
    id: 'G3',
    number: 3,
    name: 'Reducing entire classes of vulnerability',
    shortName: 'Vulnerability classes',
    pledgeText:
      "Within one year of signing the pledge, demonstrate actions taken towards enabling a significant measurable reduction in the prevalence of one or more vulnerability classes across the manufacturer's products.",
    description: 'Reduce the prevalence of one or more vulnerability classes.',
    verificationMode: 'PARTIALLY_MEASURABLE',
    evidenceRequirements: [
      { id: 'G3.R1', description: 'CWE distribution of the vendor’s own published CVE records over time', publiclyAvailable: true },
      { id: 'G3.R2', description: 'Prevalence of the class in shipped code, including undisclosed defects', publiclyAvailable: false },
    ],
    methodology: {
      summary:
        'TOUCHSTONE reports the share of the vendor’s disclosed CVE records in each tracked weakness class, per year. That is a signal about disclosed vulnerabilities only; it cannot show prevalence in shipped code.',
      metricIds: ['g3.class_share_trend'],
      statusRule:
        'PARTIAL when both trend periods have at least the minimum number of records with a usable CWE; otherwise NOT_VERIFIED. Never VERIFIED: the disclosed mix cannot establish a reduction in prevalence.',
      evidenceNeeded: [
        'Defect data that includes vulnerabilities found and fixed before release',
        'Class definitions mapped to code-level controls (for example memory-safe language adoption)',
      ],
      limitations: [
        'Disclosure volume, product mix and CWE assignment practice all move the share without any change in prevalence.',
        'Only records with a CNA-supplied CWE contribute.',
      ],
    },
  },
  {
    id: 'G4',
    number: 4,
    name: 'Security patches',
    shortName: 'Patch installation',
    pledgeText:
      'Within one year of signing the pledge, demonstrate actions taken to measurably increase the installation of security patches by customers.',
    description: 'Increase customer installation of security patches.',
    verificationMode: 'NOT_EXTERNALLY_VERIFIABLE',
    evidenceRequirements: [
      { id: 'G4.R1', description: 'Patch installation rates across the customer base, over time', publiclyAvailable: false },
    ],
    methodology: {
      summary:
        'Patch installation happens inside customer environments. Public sources do not give enough evidence to measure customer installation behaviour independently.',
      metricIds: [],
      statusRule: 'Always NOT_EXTERNALLY_VERIFIABLE.',
      evidenceNeeded: ['Installation telemetry with methodology', 'Independent attestation', 'Time period and baseline'],
      limitations: ['Internet-wide scan data would require scanning third-party assets, which TOUCHSTONE does not do.'],
    },
  },
  {
    id: 'G5',
    number: 5,
    name: 'Vulnerability disclosure policy',
    shortName: 'VDP',
    pledgeText:
      'Within one year of signing the pledge, publish a vulnerability disclosure policy (VDP) that authorizes testing by members of the public on products offered by the manufacturer, commits to not recommending or pursuing legal action against anyone engaging in good faith efforts to follow the VDP, provides a clear channel to report vulnerabilities, and allows for public disclosure of vulnerabilities in line with coordinated vulnerability disclosure best practices and international standards.',
    description: 'Publish a VDP with the four elements the pledge names.',
    verificationMode: 'PUBLICLY_MEASURABLE',
    evidenceRequirements: [
      { id: 'G5.R1', description: 'A discoverable public policy document', publiclyAvailable: true },
      { id: 'G5.R2', description: 'Authorization of testing by the public', publiclyAvailable: true },
      { id: 'G5.R3', description: 'Good-faith legal safe harbor', publiclyAvailable: true },
      { id: 'G5.R4', description: 'A clear reporting channel', publiclyAvailable: true },
      { id: 'G5.R5', description: 'Public disclosure allowed in line with coordinated disclosure', publiclyAvailable: true },
    ],
    methodology: {
      summary:
        'TOUCHSTONE reads the vendor’s public policy (found via security.txt, the vendor registry, or the vendor domain) and assesses eight criteria. Each determination quotes the sentence that supports it. A security.txt file on its own is not counted as a VDP.',
      metricIds: ['vdp.criteria_met', 'vdp.pledge_elements_met'],
      statusRule:
        'VERIFIED when all four pledge-required elements are MET and none is CONTRADICTED. PARTIAL when a policy was found and at least one pledge element is MET. NOT_VERIFIED when no policy was found or no pledge element is MET. DATA_ERROR when the policy could not be retrieved and no earlier snapshot exists.',
      evidenceNeeded: [],
      limitations: [
        'Criteria are assessed with documented phrase rules over the policy text. Unusual wording can be missed; every determination carries its quote so it can be checked and disputed.',
        'TOUCHSTONE reads a policy; it does not test whether the vendor honours it.',
      ],
    },
  },
  {
    id: 'G6',
    number: 6,
    name: 'CVEs',
    shortName: 'CVE transparency',
    pledgeText:
      "Demonstrate transparency in vulnerability reporting by including accurate Common Weakness Enumeration (CWE) and Common Platform Enumeration (CPE) fields in every Common Vulnerabilities and Exposures (CVE) record for the manufacturer's products. Additionally, issue CVEs in a timely manner for, at minimum, all critical or high impact vulnerabilities (whether discovered internally or by a third party) that either require actions by a customer to patch or have evidence of active exploitation.",
    description: 'CWE and CPE in every CVE record; timely CVEs for critical and high impact vulnerabilities.',
    verificationMode: 'PUBLICLY_MEASURABLE',
    evidenceRequirements: [
      { id: 'G6.R1', description: 'CVE records for the vendor’s products, with the CNA container', publiclyAvailable: true },
      { id: 'G6.R2', description: 'Vendor advisories stating severity and CVE ids, with release dates', publiclyAvailable: true },
    ],
    methodology: {
      summary:
        'Two measured dimensions. Record quality: the share of eligible CVE records whose CNA-supplied data includes a valid CWE and a well-formed CPE in the vendor’s namespace. Issuance timeliness: for critical and high advisories, whether a CVE record exists and how long after the advisory it was published.',
      metricIds: [
        'cve.cwe_coverage',
        'cve.cpe_coverage',
        'cve.cpe_namespace_consistency',
        'cve.complete_records',
        'cve.enriched_only',
        'cve.timely_issuance',
        'cve.high_impact_with_cve',
        'cve.publication_latency',
      ],
      statusRule:
        'DATA_ERROR when the CVE source failed with no earlier snapshot. VERIFIED when every eligible record is complete (the pledge says "every") AND every high-impact advisory has a CVE published within the methodology tolerance, over at least the minimum number of high-impact advisories. PARTIAL when either dimension has evidence but falls short (including timeliness measured on fewer advisories than the minimum). When neither dimension can be measured: NOT_VERIFIED when the records are below the minimum sample (or there are none) AND there are no high-impact advisories to measure (no advisory feed, or none in the window); DATA_ERROR when a source or mapping problem prevents measurement (for example no CPE vendor namespace is registered, so completeness cannot be checked).',
      evidenceNeeded: [],
      limitations: [
        'Third-party enrichment (CISA-ADP, NVD) is reported but not credited to the vendor.',
        'A vulnerability that was never disclosed cannot be counted.',
        'Timeliness needs a machine-readable advisory feed (CSAF). Without one, timeliness is NOT_VERIFIED, not zero.',
      ],
    },
  },
  {
    id: 'G7',
    number: 7,
    name: 'Evidence of intrusions',
    shortName: 'Intrusion evidence',
    pledgeText:
      "Within one year of signing the pledge, demonstrate a measurable increase in the ability for customers to gather evidence of cybersecurity intrusions affecting the manufacturer's products.",
    description: 'Increase customers’ ability to gather intrusion evidence.',
    verificationMode: 'NOT_EXTERNALLY_VERIFIABLE',
    evidenceRequirements: [
      { id: 'G7.R1', description: 'Logging capabilities available to customers, by product and tier, over time', publiclyAvailable: false },
      { id: 'G7.R2', description: 'Whether those capabilities are enabled and retained by default', publiclyAvailable: false },
    ],
    methodology: {
      summary:
        'Logging features are sometimes documented publicly, but documentation does not show availability by licence tier, default configuration, or change over time in a comparable way.',
      metricIds: [],
      statusRule: 'Always NOT_EXTERNALLY_VERIFIABLE.',
      evidenceNeeded: [
        'Per-product logging capability inventory with licence tier',
        'Default retention and enablement',
        'Change log over the pledge year',
      ],
      limitations: ['Counting documentation pages would measure documentation, not capability.'],
    },
  },
]

export const goalById = (id: string): SecurityCommitmentGoal | undefined => GOALS.find((g) => g.id === id)

export const OBSERVABLE_GOAL_IDS = GOALS.filter((g) => g.verificationMode !== 'NOT_EXTERNALLY_VERIFIABLE').map((g) => g.id)
export const UNVERIFIABLE_GOAL_IDS = GOALS.filter((g) => g.verificationMode === 'NOT_EXTERNALLY_VERIFIABLE').map((g) => g.id)

/**
 * Methodology versions. A published figure never changes without the
 * methodology version changing: every run records the version it used, and
 * the regression suite pins the expected output of each version over the
 * demo dataset (tests/regression). Changing a parameter or a formula without
 * adding a version here fails that suite.
 */

import type { MethodologyParameters, MethodologyVersion } from '../model/index.ts'

const BASE: MethodologyParameters = {
  cveWindowDays: 730,
  placeholderCweCountsAsPopulated: true,
  timelinessToleranceDays: 1,
  highImpactSeverities: ['CRITICAL', 'HIGH'],
  minimumEligibleRecords: 5,
  minimumRecordsPerTrendPeriod: 10,
  vdpCurrentWithinDays: 730,
  freshnessHours: {
    CISA_PLEDGE: [24 * 7, 24 * 30],
    CVE_PROGRAM: [24, 24 * 7],
    NVD: [24, 24 * 7],
    VENDOR_ADVISORY: [24 * 2, 24 * 14],
    VENDOR_VDP: [24 * 7, 24 * 45],
    SECURITY_TXT: [24 * 7, 24 * 45],
  },
  unusualBelowPercentile: 10,
  latencyOutlierFactor: 2,
  latencyOutlierMinDays: 7,
}

export const METHODOLOGY_VERSIONS: MethodologyVersion[] = [
  {
    version: '1.0.0',
    releasedOn: '2025-09-15',
    changes: ['Initial methodology: VDP (8 criteria), CVE record quality (CNA-supplied CWE and CPE), CVE issuance timeliness, Goal 3 class-share signal.'],
    parameters: BASE,
    parserVersion: '1.0.0',
    scoringVersion: '1.0.0',
  },
  {
    version: '1.1.0',
    releasedOn: '2026-06-15',
    changes: [
      'NVD-CWE-noinfo and NVD-CWE-Other no longer count as a populated CWE. They state that no weakness was identified, so they cannot satisfy "accurate CWE". Expected effect: CWE coverage and complete-record figures fall for vendors that use placeholders; runs made under 1.0.0 keep their 1.0.0 figures.',
    ],
    parameters: { ...BASE, placeholderCweCountsAsPopulated: false },
    parserVersion: '1.0.0',
    scoringVersion: '1.1.0',
  },
]

export const CURRENT_METHODOLOGY_VERSION = '1.1.0'

export function methodologyVersion(version: string): MethodologyVersion {
  const found = METHODOLOGY_VERSIONS.find((m) => m.version === version)
  if (!found) throw new Error(`Unknown methodology version ${version}`)
  return found
}

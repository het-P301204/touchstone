/**
 * A small, hand-built cohort for end-to-end run tests (executeRun runs the
 * real identity module over it). Fictional vendors, .example URLs.
 *
 *   northwind    complete records (10/10), all VDP criteria MET, timely advisories
 *   halcyon      placeholder-CWE user: 6 records (2 real, 2 placeholder, 1 none, 1 malformed)
 *   brightwater  no CSAF feed (timeliness NOT_VERIFIED); VDP without safe harbor
 *   sparrow      below minimum sample (2 records); no VDP observation
 *   quill/quarry share the affected-vendor name "Shared Labs": that record is AMBIGUOUS_VENDOR
 *   duplicate    DEMO-2026-0999 appears twice with different content (DUPLICATE_CONFLICT)
 */

import type { RunInputs, Vendor } from '../../src/model/index.ts'
import { cpe, container, daysAgo, makeAdvisory, makeCve, makeInputs, makeVdp, makeVendor, placeholderFixture } from './builders.ts'

export function cohortVendors(): Vendor[] {
  return [
    makeVendor('northwind', { cna: 'northwind-cna', cpeVendor: 'northwind', category: 'NETWORKING', claims: [{ goalId: 'G1', summary: 'MFA enabled by default for new tenants.' }] }),
    makeVendor('halcyon', { cna: 'halcyon-cna', cpeVendor: 'halcyon', category: 'CLOUD' }),
    makeVendor('brightwater', { cna: 'brightwater-cna', cpeVendor: 'brightwater', category: 'NETWORKING', csaf: false }),
    makeVendor('sparrow', { cna: 'sparrow-cna', cpeVendor: 'sparrow', category: 'CLOUD' }),
    makeVendor('quill', { cna: 'quill-cna', cpeVendor: 'quill', affected: 'Shared Labs', category: 'DEVELOPER_TOOLS' }),
    makeVendor('quarry', { cna: 'quarry-cna', cpeVendor: 'quarry', affected: 'Shared Labs', category: 'DEVELOPER_TOOLS' }),
  ]
}

export function cohortInputs(methodologyVersion = '1.1.0'): RunInputs {
  const vendors = cohortVendors()
  const halcyon = vendors.find((v) => v.id === 'halcyon')!
  const cves = [
    ...Array.from({ length: 10 }, (_, i) =>
      makeCve(`DEMO-2026-01${String(i).padStart(2, '0')}`, { cna: 'northwind-cna', cwes: ['CWE-79'], cpes: [cpe('northwind')], datePublished: daysAgo(40 + i * 10) }),
    ),
    ...placeholderFixture(halcyon),
    ...Array.from({ length: 6 }, (_, i) =>
      makeCve(`DEMO-2026-03${String(i).padStart(2, '0')}`, {
        cna: 'brightwater-cna',
        cwes: i < 3 ? ['CWE-787'] : [],
        cpes: [cpe('brightwater')],
        adp: i >= 3 ? [container('CISA-ADP', ['CWE-787'])] : [],
      }),
    ),
    makeCve('DEMO-2026-0401', { cna: 'sparrow-cna', cwes: ['CWE-79'], cpes: [cpe('sparrow')] }),
    makeCve('DEMO-2026-0402', { cna: 'sparrow-cna', cwes: ['CWE-79'], cpes: [cpe('sparrow')] }),
    ...Array.from({ length: 5 }, (_, i) => makeCve(`DEMO-2026-05${String(i).padStart(2, '0')}`, { cna: 'quill-cna', cwes: ['CWE-89'], cpes: [cpe('quill')] })),
    ...Array.from({ length: 5 }, (_, i) => makeCve(`DEMO-2026-06${String(i).padStart(2, '0')}`, { cna: 'quarry-cna', cwes: ['CWE-89'], cpes: [cpe('other')] })),
    makeCve('DEMO-2026-0700', { cna: 'unregistered-cna', affected: [{ vendor: 'Shared Labs', product: 'Widget' }], cwes: ['CWE-20'] }),
    makeCve('DEMO-2026-0999', { cna: 'northwind-cna', cwes: ['CWE-79'], cpes: [cpe('northwind')], sourceHash: 'hash-a' }),
    makeCve('DEMO-2026-0999', { cna: 'northwind-cna', cwes: ['CWE-20'], cpes: [cpe('northwind')], sourceHash: 'hash-b' }),
  ]
  const advisories = [
    makeAdvisory('northwind', 'NW-2026-01', { cveIds: ['DEMO-2026-0100'], publishedDaysAgo: 40 }),
    makeAdvisory('northwind', 'NW-2026-02', { cveIds: ['DEMO-2026-0101'], publishedDaysAgo: 50 }),
    makeAdvisory('halcyon', 'HC-2026-01', { cveIds: ['DEMO-2026-1001'], publishedDaysAgo: 45 }),
    makeAdvisory('quill', 'QL-2026-01', { cveIds: ['DEMO-2026-0500'], publishedDaysAgo: 35 }),
  ]
  const vdp = [
    makeVdp('northwind'),
    makeVdp('halcyon', { SCOPE_DEFINED: 'PARTIAL' }),
    makeVdp('brightwater', { GOOD_FAITH_SAFE_HARBOR: 'NOT_MET', TESTING_AUTHORIZED: 'NOT_MET' }),
    makeVdp('quill', { PUBLIC_DISCLOSURE_ALLOWED: 'CONTRADICTED' }),
    makeVdp('quarry', {}, { default: 'NOT_MET', found: false }),
  ]
  const previousVdp = [makeVdp('halcyon', {}, { textHash: 'text-halcyon-old', observedAt: daysAgo(92) })]
  return makeInputs({ vendors, cves, advisories, vdp, previousVdp, methodologyVersion })
}

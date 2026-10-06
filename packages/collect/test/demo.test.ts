import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { DEMO_DATASET_VERSIONS, loadDemoInputs, resolveDemoRoot } from '../src/demo.ts'
import { attributeCves, detectIdentityConflicts } from '../../core/src/identity/index.ts'
import { cweFieldGap } from '../../core/src/normalize/cve.ts'
import { build, DATASET_VERSIONS } from '../../../scripts/demo/generate.ts'

const demoRoot = fileURLToPath(new URL('../../../fixtures/demo/', import.meta.url))
const repoRoot = fileURLToPath(new URL('../../../', import.meta.url))
const load = (v: string) => loadDemoInputs({ root: demoRoot, datasetVersion: v, methodologyVersion: v >= '2026-06-15' ? '1.1.0' : '1.0.0', history: [] })
const latest = load('2026-10-06')
const crit = (vendorId: string, c: string, inputs = latest) => inputs.vdp.find((o) => o.vendorId === vendorId)!.criteria.find((x) => x.criterion === c)!

describe('demo generator', () => {
  it('is deterministic and matches the committed fixtures byte for byte', () => {
    const a = build()
    const b = build()
    expect([...a.keys()]).toEqual([...b.keys()])
    for (const [path, content] of a) {
      expect(b.get(path)).toBe(content)
      const onDisk = `${demoRoot}${path}`
      expect(existsSync(onDisk), path).toBe(true)
      expect(readFileSync(onDisk, 'utf8') === content, `${path} differs: run node scripts/demo/generate.ts`).toBe(true)
    }
    expect(DATASET_VERSIONS).toEqual(DEMO_DATASET_VERSIONS)
  })

  it('stays synthetic: .example URLs, DEMO ids, fictional vendors flagged synthetic', () => {
    const registry = JSON.parse(readFileSync(`${demoRoot}registry/vendors.json`, 'utf8')) as { synthetic: boolean; domains: string[] }[]
    expect(registry.length).toBeGreaterThanOrEqual(20)
    expect(registry.every((v) => v.synthetic && v.domains.every((d) => d.endsWith('.example')))).toBe(true)
    for (const s of latest.snapshots) expect(new URL(s.url).hostname.endsWith('.example'), s.url).toBe(true)
    expect(latest.cves.every((c) => /^DEMO-\d{4}-\d{4,}$/.test(c.id) && c.synthetic)).toBe(true)
  })
})

describe('loadDemoInputs', () => {
  it('accepts the repository root or fixtures/demo', () => {
    expect(resolveDemoRoot(repoRoot)).toBe(resolveDemoRoot(demoRoot))
  })

  it('produces deterministic RunInputs for every version', () => {
    for (const v of DEMO_DATASET_VERSIONS) {
      const a = load(v)
      expect(JSON.stringify(load(v))).toBe(JSON.stringify(a))
      expect(a.mode).toBe('DEMO')
      expect(a.asOf).toBe(`${v}T12:00:00Z`)
      expect(a.vendors.length).toBe(22)
      expect(a.vdp.length).toBe(22)
    }
  })

  it('covers the attribution scenarios', () => {
    const conflicts = detectIdentityConflicts(latest.vendors)
    expect(conflicts.map((c) => [c.kind, c.value, c.vendorIds])).toEqual([['CPE_NAMESPACE_SHARED', 'kestrel', ['ferrous-industrial', 'kestrel-controls']]])
    const { attributions, exclusions } = attributeCves(latest.cves, latest.vendors, conflicts)
    const reasons = new Set(exclusions.map((e) => e.reason))
    expect([...reasons].sort()).toEqual(['AMBIGUOUS_VENDOR', 'DUPLICATE_CONFLICT', 'FREE_TEXT_ONLY', 'IDENTITY_CONFLICT', 'REJECTED_RECORD'])
    expect(exclusions.filter((e) => e.reason === 'DUPLICATE_CONFLICT').every((e) => e.candidateVendorIds.includes('quillmark-labs'))).toBe(true)
    expect(exclusions.filter((e) => e.reason === 'AMBIGUOUS_VENDOR').every((e) => e.candidateVendorIds.join() === 'summit-analytics,summit-peak-software')).toBe(true)
    expect(exclusions.filter((e) => e.reason === 'IDENTITY_CONFLICT').every((e) => e.candidateVendorIds.includes('kestrel-controls'))).toBe(true)
    const rules = new Set(attributions.map((a) => a.rule))
    expect([...rules].sort()).toEqual(['AFFECTED_VENDOR_AND_CPE', 'AFFECTED_VENDOR_ONLY', 'ASSIGNER_IS_VENDOR_CNA'])
    const tinder = attributions.filter((a) => a.vendorId === 'tinderbox-studio').length
    expect(tinder).toBeLessThan(5)
  })

  it('a legacy-format record is rejected by the normalizer and the snapshot says why', () => {
    const rejected = latest.snapshots.filter((s) => s.status === 'REJECTED')
    expect(rejected).toHaveLength(1)
    expect(rejected[0]!.error).toMatch(/legacy CVE JSON/)
    expect(load('2025-10-06').snapshots.some((s) => s.status === 'REJECTED')).toBe(false)
  })

  it('placeholder CWEs: counted under 1.0.0 parameters, not under 1.1.0', () => {
    const lantern = latest.cves.filter((c) => c.assigner.shortName === 'lanternfish')
    const placeholders = lantern.filter((c) => cweFieldGap(c.cna.cwes, false) === 'PLACEHOLDER').length
    expect(placeholders / lantern.length).toBeGreaterThan(0.3)
    expect(lantern.filter((c) => cweFieldGap(c.cna.cwes, true) !== null).length).toBeLessThan(placeholders)
  })

  it('heavy CISA-ADP enrichment: CNA containers sparse, ADP containers fill them for older records only', () => {
    const lark = latest.cves.filter((c) => c.assigner.shortName === 'larkspur')
    const cnaCwe = lark.filter((c) => c.cna.cwes.some((x) => x.id)).length
    const adpCwe = lark.filter((c) => c.adp.some((a) => a.provider === 'CISA-ADP' && a.cwes.some((x) => x.id))).length
    expect(cnaCwe / lark.length).toBeLessThan(0.3)
    expect(adpCwe / lark.length).toBeGreaterThan(0.5)
    const recent = lark.filter((c) => Date.parse(latest.asOf) - Date.parse(c.datePublished!) < 30 * 86_400_000)
    expect(recent.every((c) => c.adp.length === 0)).toBe(true)
  })

  it('signatory status comes from the signer page; the count mismatch is reported', () => {
    expect(load('2025-10-06').vendors.find((v) => v.id === 'foxglove-identity')!.signatoryStatus).toBe('NOT_LISTED')
    expect(latest.vendors.every((v) => v.signatoryStatus === 'LISTED')).toBe(true)
    const jan = load('2026-01-06')
    expect(jan.signatoryList!.declaredCount).toBe(jan.signatoryList!.parsedCount + 1)
    expect(jan.signatoryList!.warnings[0]).toMatch(/^COUNT_MISMATCH/)
  })

  it('VDP scenarios: strong, weak, prohibitive, none, expired, narrowing, carried after failure', () => {
    expect(latest.vdp.find((o) => o.vendorId === 'northwind-systems')!.criteria.every((c) => c.state === 'MET')).toBe(true)
    expect(crit('tessellate-data', 'GOOD_FAITH_SAFE_HARBOR').state).toBe('NOT_MET')
    expect(crit('gravelpoint-civic', 'TESTING_AUTHORIZED').state).toBe('CONTRADICTED')
    expect(latest.vdp.find((o) => o.vendorId === 'gravelpoint-civic')!.prohibitive.length).toBe(3)
    expect(latest.vdp.find((o) => o.vendorId === 'orchard-lane-robotics')!.criteria.every((c) => c.state === 'NOT_MET')).toBe(true)
    expect(crit('copperleaf-learning', 'CURRENT', load('2026-01-06')).state).toBe('MET')
    expect(crit('copperleaf-learning', 'CURRENT').state).toBe('NOT_MET')
    expect(crit('saltmarsh-software', 'CURRENT').ruleId).toBe('VDP.CURRENT.POLICY_OLD')
    expect(crit('ember-oak-devices', 'SCOPE_DEFINED', load('2026-04-06')).state).toBe('MET')
    const july = load('2026-07-06')
    expect(crit('ember-oak-devices', 'SCOPE_DEFINED', july).state).toBe('PARTIAL')
    expect(crit('ember-oak-devices', 'TESTING_AUTHORIZED', july).state).toBe('PARTIAL')
    const prev = july.previousVdp.find((o) => o.vendorId === 'ember-oak-devices')!
    expect(prev.policy.textHash).not.toBe(july.vdp.find((o) => o.vendorId === 'ember-oak-devices')!.policy.textHash)
    expect(crit('basalt-infrastructure', 'POLICY_DISCOVERABLE').ruleId).toBe('VDP.DISCOVERABLE.STXT')
  })

  it('source failure: FAILED snapshot with substitutedBy, observation carried and labelled', () => {
    const failed = latest.snapshots.filter((s) => s.status === 'FAILED')
    expect(failed).toHaveLength(1)
    expect(failed[0]!.sourceId).toBe('vendor.wrenfield-software.vdp')
    const sub = latest.snapshots.find((s) => s.id === failed[0]!.substitutedBy)!
    expect(sub.status).toBe('OK')
    expect(sub.fetchedAt.startsWith('2026-07-06')).toBe(true)
    const obs = latest.vdp.find((o) => o.vendorId === 'wrenfield-software')!
    expect(obs.carriedFromSnapshotId).toBe(sub.id)
    expect(obs.observedAt).toBe(sub.fetchedAt)
  })

  it('stale sources are visible as old fetch times', () => {
    const palisade = latest.snapshots.filter((s) => s.sourceId.startsWith('vendor.palisade-mobile.'))
    expect(palisade.length).toBeGreaterThan(0)
    for (const s of palisade) expect(Date.parse(latest.asOf) - Date.parse(s.fetchedAt)).toBeGreaterThan(45 * 86_400_000)
  })

  it('no CSAF feed: no advisories for those vendors', () => {
    for (const id of ['saltmarsh-software', 'copperleaf-learning', 'orchard-lane-robotics']) expect(latest.advisories.some((a) => a.vendorId === id)).toBe(false)
    expect(latest.advisories.some((a) => a.vendorId === 'northwind-systems')).toBe(true)
  })
})

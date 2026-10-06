/**
 * A minimal, type-checked published bundle for API and CLI tests.
 *
 * Every object here is typed against packages/core/src/model/publish.ts, so
 * the compiler keeps this fixture in step with the published shapes. All
 * vendors are fictional and flagged synthetic.
 *
 * `writeBundle(dir)` writes the layout the API loads:
 *   index.json, runs/<runId>/summary.json, runs/<runId>/vendors/<vendorId>.json,
 *   history.json, inputs/<datasetVersion>.json, disputes.json, notebook.json
 * `writeDemoFixtures(dir)` writes a tiny raw-snapshot manifest for the DEMO refresh FETCH stage.
 */
import { createHash } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { GOALS } from '../../../../packages/core/src/methodology/goals.ts'
import { methodologyVersion } from '../../../../packages/core/src/methodology/versions.ts'
import type {
  CveRecord,
  Dispute,
  EvidenceItem,
  GoalAssessment,
  GoalStatus,
  HistorySeries,
  MetricDefinition,
  NotebookEntry,
  RunIndex,
  RunInputs,
  RunManifest,
  RunSummary,
  Vendor,
  VendorCategory,
  VendorDetail,
  VendorSummary,
} from '../../../../packages/core/src/model/index.ts'

export const RUN_1 = 'TS-2026-07-06-a1a1'
export const RUN_2 = 'TS-2026-10-06-b2b2'
export const DATASET_1 = '2026-07-06'
export const DATASET_2 = '2026-10-06'
export const OUTPUTS_HASH: Record<string, string> = { [DATASET_1]: 'a'.repeat(64), [DATASET_2]: 'b'.repeat(64) }
export const INPUTS_HASH: Record<string, string> = { [DATASET_1]: 'c'.repeat(64), [DATASET_2]: 'd'.repeat(64) }

export const NORTHWIND = 'northwind-systems'
export const HALCYON = 'halcyon-cloud'
export const BRIGHTWATER = 'brightwater-networks'

function vendor(id: string, name: string, category: VendorCategory, aliases: string[] = []): Vendor {
  return {
    id,
    canonicalName: name,
    aliases: [
      { kind: 'LEGAL_NAME', value: name, confidence: 'HIGH', evidence: [{ statement: 'Fictional demo registry entry.' }] },
      ...aliases.map((value) => ({ kind: 'BRAND' as const, value, confidence: 'HIGH' as const, evidence: [{ statement: 'Fictional demo registry entry.' }] })),
    ],
    signatoryStatus: 'LISTED',
    category,
    domains: [`${id}.example`],
    claims: [],
    synthetic: true,
  }
}

export const VENDORS: Record<string, Vendor> = {
  [NORTHWIND]: vendor(NORTHWIND, 'Northwind Systems', 'ENTERPRISE_SOFTWARE', ['Northwind']),
  [HALCYON]: vendor(HALCYON, 'Halcyon Cloud', 'CLOUD'),
  [BRIGHTWATER]: vendor(BRIGHTWATER, 'Brightwater Networks', 'NETWORKING'),
}

export const METRICS: MetricDefinition[] = [
  {
    id: 'vdp.criteria_met',
    name: 'VDP criteria met',
    goalId: 'G5',
    dimension: 'VDP',
    unit: 'PERCENT',
    formula: 'criteria MET / 8',
    eligibility: 'All vendors',
    direction: 'HIGHER_IS_STRONGER_EVIDENCE',
    coverageSlot: false,
  },
  {
    id: 'cve.complete_records',
    name: 'Complete CVE records',
    goalId: 'G6',
    dimension: 'CVE_QUALITY',
    unit: 'PERCENT',
    formula: 'records with CNA CWE and CNA CPE / eligible records',
    eligibility: 'Published records in the window',
    direction: 'HIGHER_IS_STRONGER_EVIDENCE',
    coverageSlot: false,
  },
  {
    id: 'cve.cwe_coverage',
    name: 'CWE coverage',
    goalId: 'G6',
    unit: 'PERCENT',
    formula: 'records with CNA CWE / eligible records',
    eligibility: 'Published records in the window',
    direction: 'HIGHER_IS_STRONGER_EVIDENCE',
    coverageSlot: true,
  },
]

function cve(id: string, opts: { cwe?: string[]; cpe?: boolean; adpCwe?: string[]; cnaSeverity?: 'HIGH' | 'CRITICAL'; adpSeverity?: 'CRITICAL'; product: string; published: string }): CveRecord {
  return {
    id,
    state: 'PUBLISHED',
    assigner: { orgId: '00000000-0000-4000-8000-000000000001', shortName: 'northwind' },
    datePublished: opts.published,
    title: `Example flaw in ${opts.product}`,
    affected: [{ vendor: 'Northwind Systems', product: opts.product }],
    cna: {
      provider: 'CNA',
      cwes: (opts.cwe ?? []).map((raw) => ({ raw, id: raw.startsWith('CWE-') ? raw : null, placeholder: raw.startsWith('NVD-') })),
      cpes: opts.cpe ? [{ raw: `cpe:2.3:a:northwind:${opts.product}:1.0:*:*:*:*:*:*:*`, part: 'a', vendor: 'northwind', product: opts.product, wellFormed: true }] : [],
      cvss: opts.cnaSeverity ? [{ version: '3.1', baseScore: 8.1, severity: opts.cnaSeverity, provider: 'CNA' }] : [],
    },
    adp: opts.adpCwe || opts.adpSeverity
      ? [
          {
            provider: 'CISA-ADP',
            cwes: (opts.adpCwe ?? []).map((raw) => ({ raw, id: raw, placeholder: false })),
            cpes: [],
            cvss: opts.adpSeverity ? [{ version: '3.1', baseScore: 9.8, severity: opts.adpSeverity, provider: 'ADP' }] : [],
          },
        ]
      : [],
    dataVersion: '5.1',
    snapshotId: 'SN-000000000001',
    sourceHash: createHash('sha256').update(id).digest('hex'),
    synthetic: true,
  }
}

export const CVES: Record<string, CveRecord[]> = {
  [NORTHWIND]: [
    cve('DEMO-2026-0001', { cwe: ['CWE-79'], cpe: true, cnaSeverity: 'HIGH', product: 'gateway', published: '2026-03-02T00:00:00Z' }),
    cve('DEMO-2026-0002', { cpe: true, adpCwe: ['CWE-787'], adpSeverity: 'CRITICAL', product: 'console', published: '2026-05-10T00:00:00Z' }),
  ],
  [HALCYON]: [cve('DEMO-2025-0003', { cwe: ['NVD-CWE-noinfo'], product: 'object-store', published: '2025-11-20T00:00:00Z' })],
  [BRIGHTWATER]: [],
}

const STATUS_COUNTS = (s: Partial<Record<GoalStatus, number>>): Record<GoalStatus, number> => ({
  VERIFIED: 0,
  PARTIAL: 0,
  NOT_VERIFIED: 0,
  NOT_EXTERNALLY_VERIFIABLE: 0,
  DATA_ERROR: 0,
  ...s,
})

function evidence(vendorId: string, n: number, metricId: string, subject: string): EvidenceItem {
  return {
    id: `EV-${createHash('sha256').update(`${vendorId}${n}`).digest('hex').slice(0, 10)}`,
    vendorId,
    metricId,
    sourceId: 'cve.record',
    snapshotId: 'SN-000000000001',
    subject,
    collectedAt: '2026-10-06T00:00:00Z',
    extracted: { cwe: 'CWE-79' },
    interpretation: 'SUPPORTS',
    reading: 'CNA container lists CWE-79.',
    confidence: 'HIGH',
    methodologyVersion: '1.1.0',
  }
}

function goals(vendorId: string, vdp: number | null, quality: number | null, ev: EvidenceItem[]): GoalAssessment[] {
  return GOALS.map((g): GoalAssessment => {
    if (g.verificationMode === 'NOT_EXTERNALLY_VERIFIABLE') {
      return { vendorId, goalId: g.id, status: 'NOT_EXTERNALLY_VERIFIABLE', statusReason: 'Not externally verifiable.', metrics: [], evidenceIds: [], claimCount: 0 }
    }
    if (g.id === 'G5') {
      return {
        vendorId,
        goalId: 'G5',
        status: vdp === null ? 'NOT_VERIFIED' : 'VERIFIED',
        statusReason: vdp === null ? 'Evidence incomplete: no policy text could be read.' : 'Evidence supports the VDP measurement.',
        metrics: [
          {
            metricId: 'vdp.criteria_met',
            value: vdp,
            ...(vdp === null ? { gap: 'SOURCE_FAILED' as const } : { numerator: 6, denominator: 8 }),
            confidence: 'HIGH',
            confidenceReasons: [],
            evidenceIds: [],
            query: 'vdp criteria',
            calculation: vdp === null ? 'not measurable' : '6 / 8 = 75.00%',
          },
        ],
        evidenceIds: [],
        claimCount: 0,
      }
    }
    if (g.id === 'G6') {
      return {
        vendorId,
        goalId: 'G6',
        status: quality === null ? 'NOT_VERIFIED' : 'PARTIAL',
        statusReason: quality === null ? 'Evidence incomplete: below minimum sample.' : 'Evidence supports part of the measurement.',
        metrics: [
          {
            metricId: 'cve.complete_records',
            value: quality,
            ...(quality === null ? { gap: 'BELOW_MINIMUM_SAMPLE' as const } : { numerator: 1, denominator: 2 }),
            confidence: 'HIGH',
            confidenceReasons: [],
            evidenceIds: ev.map((e) => e.id),
            query: 'cve records',
            calculation: quality === null ? 'not measurable' : '1 / 2 = 50.00%',
          },
          { metricId: 'cve.cwe_coverage', value: quality, confidence: 'HIGH', confidenceReasons: [], evidenceIds: [], query: 'cwe', calculation: '' },
        ],
        evidenceIds: ev.map((e) => e.id),
        claimCount: 0,
      }
    }
    return { vendorId, goalId: g.id, status: 'NOT_VERIFIED', statusReason: 'Evidence incomplete.', metrics: [], evidenceIds: [], claimCount: 0 }
  })
}

type VendorSpec = { id: string; vdp: number | null; quality: number | null; coverage: number }

function vendorParts(runId: string, spec: VendorSpec): { summary: VendorSummary; detail: VendorDetail } {
  const records = CVES[spec.id] ?? []
  const ev = records.map((r, i) => evidence(spec.id, i, 'cve.complete_records', r.id))
  const gs = goals(spec.id, spec.vdp, spec.quality, ev)
  const counts: Partial<Record<GoalStatus, number>> = {}
  for (const g of gs) counts[g.status] = (counts[g.status] ?? 0) + 1
  return {
    summary: {
      vendor: VENDORS[spec.id]!,
      goals: gs.map(({ evidenceIds, ...rest }) => ({ ...rest, evidenceCount: evidenceIds.length })),
      dimensions: [
        { dimension: 'VDP', value: spec.vdp, metricId: 'vdp.criteria_met', status: spec.vdp === null ? 'NOT_VERIFIED' : 'VERIFIED' },
        { dimension: 'CVE_QUALITY', value: spec.quality, metricId: 'cve.complete_records', status: spec.quality === null ? 'NOT_VERIFIED' : 'PARTIAL' },
        { dimension: 'CVE_TIMELINESS', value: null, metricId: 'cve.timely_issuance', status: 'NOT_VERIFIED' },
      ],
      coverage: {
        percent: spec.coverage,
        observedSlots: Math.round((spec.coverage / 100) * 14),
        totalSlots: 14,
        sourcesEvaluated: 3,
        evidenceBackedMeasurements: ev.length,
        unverifiableGoals: 4,
        unobserved: [],
      },
      benchmarks: [],
      anomalies: [],
      vdpChanges: [],
      cveCount: records.length,
      advisoryCount: 0,
      rankingNotes: {},
      statusCounts: STATUS_COUNTS(counts),
    },
    detail: {
      runId,
      vendorId: spec.id,
      goals: gs,
      evidence: ev,
      cves: records,
      attributions: records.map((r) => ({ cveId: r.id, vendorId: spec.id, rule: 'ASSIGNER_IS_VENDOR_CNA', confidence: 'HIGH', matched: [{ kind: 'CNA_SHORT_NAME', value: 'northwind' }] })),
      exclusions:
        spec.id === NORTHWIND
          ? [{ cveId: 'DEMO-2026-0009', reason: 'AMBIGUOUS_VENDOR', candidateVendorIds: [NORTHWIND, HALCYON], note: 'Two vendors share the affected name.' }]
          : [],
      advisories: [],
    },
  }
}

function manifest(runId: string, datasetVersion: string, methodology: string): RunManifest {
  return {
    runId,
    mode: 'DEMO',
    datasetVersion,
    asOf: `${datasetVersion}T00:00:00Z`,
    methodologyVersion: methodology,
    parserVersion: '1.0.0',
    scoringVersion: methodology,
    inputsHash: INPUTS_HASH[datasetVersion]!,
    outputsHash: OUTPUTS_HASH[datasetVersion]!,
    snapshotIds: ['SN-000000000001'],
    stages: [{ stage: 'FETCH', status: 'OK', detail: 'fixture' }],
    qualityChecks: [{ id: 'QC1', question: 'All numbers finite?', passed: true, detail: '' }],
  }
}

const RUNS: { runId: string; datasetVersion: string; vendors: VendorSpec[] }[] = [
  {
    runId: RUN_1,
    datasetVersion: DATASET_1,
    vendors: [
      { id: NORTHWIND, vdp: 75, quality: 40, coverage: 71.43 },
      { id: HALCYON, vdp: null, quality: null, coverage: 21.43 },
    ],
  },
  {
    runId: RUN_2,
    datasetVersion: DATASET_2,
    vendors: [
      { id: NORTHWIND, vdp: 75, quality: 50, coverage: 78.57 },
      { id: HALCYON, vdp: null, quality: null, coverage: 28.57 },
      { id: BRIGHTWATER, vdp: 12.5, quality: null, coverage: 7.14 },
    ],
  },
]

export function buildRun(i: number): { summary: RunSummary; details: VendorDetail[]; inputs: RunInputs } {
  const r = RUNS[i]!
  const parts = r.vendors.map((v) => vendorParts(r.runId, v))
  const m = manifest(r.runId, r.datasetVersion, '1.1.0')
  return {
    summary: {
      manifest: m,
      methodology: methodologyVersion('1.1.0'),
      goals: GOALS,
      metricDefinitions: METRICS,
      vendors: parts.map((p) => p.summary),
      cohort: [],
      freshness: [{ sourceId: 'cisa.signers', title: 'CISA signer list', family: 'CISA_PLEDGE', lastSuccessAt: `${r.datasetVersion}T00:00:00Z`, state: 'CURRENT' }],
      sources: [],
      snapshots: [
        { id: 'SN-000000000001', sourceId: 'cve.record', url: 'https://cve.example/x', fetchedAt: `${r.datasetVersion}T00:00:00Z`, status: 'OK', parserVersion: '1.0.0' },
        { id: 'SN-000000000002', sourceId: 'vendor.halcyon.vdp', url: 'https://halcyon-cloud.example/vdp', fetchedAt: `${r.datasetVersion}T00:00:00Z`, status: 'FAILED', error: 'timeout', parserVersion: '1.0.0', substitutedBy: 'SN-000000000003' },
      ],
      identityConflicts: [],
      exclusionCount: 1,
      signatoryList: { declaredCount: r.vendors.length, parsedCount: r.vendors.length },
    },
    details: parts.map((p) => p.detail),
    inputs: {
      mode: 'DEMO',
      datasetVersion: r.datasetVersion,
      asOf: m.asOf,
      methodologyVersion: '1.1.0',
      vendors: r.vendors.map((v) => VENDORS[v.id]!),
      cves: r.vendors.flatMap((v) => CVES[v.id] ?? []),
      advisories: [],
      vdp: [],
      previousVdp: [],
      snapshots: [],
      sources: [],
      history: [],
    },
  }
}

export const HISTORY: HistorySeries[] = [
  {
    vendorId: NORTHWIND,
    metricId: 'cve.complete_records',
    points: [
      { runId: RUN_1, datasetVersion: DATASET_1, methodologyVersion: '1.1.0', value: 40 },
      { runId: RUN_2, datasetVersion: DATASET_2, methodologyVersion: '1.1.0', value: 50 },
    ],
  },
  {
    vendorId: HALCYON,
    metricId: 'cve.complete_records',
    points: [
      { runId: RUN_1, datasetVersion: DATASET_1, methodologyVersion: '1.1.0', value: null },
      { runId: RUN_2, datasetVersion: DATASET_2, methodologyVersion: '1.1.0', value: null },
    ],
  },
]

export const SEED_DISPUTES: Dispute[] = [
  {
    id: 'DSP-0001',
    vendorId: NORTHWIND,
    target: { kind: 'GOAL', id: 'G5' },
    runId: RUN_2,
    reason: 'OUTDATED_SOURCE',
    submitterRole: 'VENDOR',
    statement: 'Our policy was revised after this snapshot.',
    evidenceUrls: [],
    status: 'OPEN',
    createdAt: '2026-10-06T09:00:00Z',
    history: [{ at: '2026-10-06T09:00:00Z', from: null, to: 'OPEN', actor: 'submitter', note: 'Submitted.' }],
    synthetic: true,
  },
  {
    id: 'DSP-0002',
    vendorId: HALCYON,
    target: { kind: 'METRIC', id: 'cve.complete_records' },
    runId: RUN_1,
    reason: 'INCORRECT_PRODUCT_MAPPING',
    submitterRole: 'RESEARCHER',
    statement: 'The registry should list both CPE namespaces.',
    evidenceUrls: ['https://research.example/notes/cpe'],
    status: 'CORRECTED',
    createdAt: '2026-07-06T10:00:00Z',
    history: [
      { at: '2026-07-06T10:00:00Z', from: null, to: 'OPEN', actor: 'submitter', note: 'Submitted.' },
      { at: '2026-07-06T16:00:00Z', from: 'OPEN', to: 'UNDER_REVIEW', actor: 'reviewer', note: 'Checking.' },
      { at: '2026-10-06T08:00:00Z', from: 'UNDER_REVIEW', to: 'CORRECTED', actor: 'reviewer', note: 'Corrected in the later run.', correctedInRunId: RUN_2 },
    ],
    synthetic: true,
  },
  {
    // Illegal history (OPEN -> CONFIRMED skips review): the store must refuse this seed.
    id: 'DSP-0003',
    vendorId: HALCYON,
    target: { kind: 'GOAL', id: 'G6' },
    runId: RUN_2,
    reason: 'METHODOLOGY_ERROR',
    submitterRole: 'OTHER',
    statement: 'Illegal history seed.',
    evidenceUrls: [],
    status: 'CONFIRMED',
    createdAt: '2026-10-06T11:00:00Z',
    history: [
      { at: '2026-10-06T11:00:00Z', from: null, to: 'OPEN', actor: 'submitter', note: 'Submitted.' },
      { at: '2026-10-06T12:00:00Z', from: 'OPEN', to: 'CONFIRMED', actor: 'reviewer', note: 'Skipped review.' },
    ],
    synthetic: true,
  },
]

export const SEED_NOTEBOOK: NotebookEntry[] = [
  {
    id: 'NB-0001',
    title: 'Third-party enrichment hides gaps',
    observation: 'ADP containers supply CWE values the CNA did not.',
    createdAt: '2026-10-06T09:00:00Z',
    tags: ['cve-quality'],
    synthetic: true,
  },
]

const write = (path: string, value: unknown) => {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(value))
}

export type BundleOptions = {
  /** Override the outputsHash published for a dataset version (index and summary), to simulate a mismatch. */
  outputsHash?: Record<string, string>
  /** Leave out inputs/ (a run that cannot be reproduced). */
  withoutInputs?: boolean
}

export function writeBundle(dir: string, opts: BundleOptions = {}): RunIndex {
  const runs = RUNS.map((_, i) => buildRun(i))
  for (const r of runs) {
    const override = opts.outputsHash?.[r.summary.manifest.datasetVersion]
    if (override) r.summary.manifest.outputsHash = override
    write(join(dir, 'runs', r.summary.manifest.runId, 'summary.json'), r.summary)
    for (const d of r.details) write(join(dir, 'runs', r.summary.manifest.runId, 'vendors', `${d.vendorId}.json`), d)
    if (!opts.withoutInputs) write(join(dir, 'inputs', `${r.summary.manifest.datasetVersion}.json`), r.inputs)
  }
  const index: RunIndex = {
    mode: 'DEMO',
    latestRunId: RUN_2,
    builtFrom: 'apps/api/test/fixtures/bundle.ts (synthetic test data)',
    runs: runs.map((r) => ({
      runId: r.summary.manifest.runId,
      datasetVersion: r.summary.manifest.datasetVersion,
      asOf: r.summary.manifest.asOf,
      methodologyVersion: r.summary.manifest.methodologyVersion,
      mode: 'DEMO',
      outputsHash: r.summary.manifest.outputsHash,
      inputsHash: r.summary.manifest.inputsHash,
    })),
  }
  write(join(dir, 'index.json'), index)
  write(join(dir, 'history.json'), HISTORY)
  write(join(dir, 'disputes.json'), SEED_DISPUTES)
  write(join(dir, 'notebook.json'), SEED_NOTEBOOK)
  return index
}

/** Raw demo fixtures for the DEMO refresh FETCH stage: one OK file (sha256 recorded) and one FAILED source. */
export function writeDemoFixtures(dir: string, opts: { corrupt?: boolean } = {}): void {
  for (const version of [DATASET_1, DATASET_2]) {
    const content = `<html><body><h2>3 Companies</h2></body></html>`
    const file = join(dir, version, 'cisa', 'signers.html')
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, opts.corrupt ? `${content}tampered` : content)
    write(join(dir, version, 'manifest.json'), {
      snapshots: [
        { sourceId: 'cisa.signers', url: 'https://cisa.example/signers', fetchedAt: `${version}T00:00:00Z`, status: 'OK', file: `${version}/cisa/signers.html`, sha256: createHash('sha256').update(content).digest('hex') },
        { sourceId: 'vendor.halcyon.vdp', url: 'https://halcyon-cloud.example/vdp', fetchedAt: `${version}T00:00:00Z`, status: 'FAILED' },
      ],
    })
  }
}

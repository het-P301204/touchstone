/**
 * Publishes the demo dataset.
 *
 *   node scripts/build-demo.ts           regenerate apps/web/public/data and fixtures/demo/expected
 *   node scripts/build-demo.ts --check   regenerate in memory; exit 1 if any published file differs
 *
 * For each quarterly dataset version, in order:
 *   raw demo snapshots (fixtures/demo/<version>/)  -> loadDemoInputs (real normalizers)
 *   -> executeRun (methodology in force on that date) -> splitForPublication -> JSON files.
 * Each run's history is built from the runs before it, so historical baselines
 * and trend lines come from the same pipeline the API uses.
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { loadDemoInputs, DEMO_DATASET_VERSIONS } from '../packages/collect/src/demo.ts'
import { executeRun } from '../packages/core/src/run/run.ts'
import { splitForPublication, historySeries } from '../packages/core/src/publish/split.ts'
import { METHODOLOGY_VERSIONS, methodologyVersion } from '../packages/core/src/methodology/versions.ts'
import type { Dispute, HistoricalPoint, NotebookEntry, RunIndex, RunOutput } from '../packages/core/src/model/index.ts'

const root = fileURLToPath(new URL('../', import.meta.url))
const demoRoot = join(root, 'fixtures', 'demo')
const outRoot = join(root, 'apps', 'web', 'public', 'data')
const expectedRoot = join(demoRoot, 'expected')
const check = process.argv.includes('--check')

/** The methodology version in force on a dataset date: the latest released on or before it. */
function methodologyFor(datasetVersion: string): string {
  const eligible = METHODOLOGY_VERSIONS.filter((m) => m.releasedOn <= datasetVersion)
  const latest = eligible[eligible.length - 1]
  if (!latest) throw new Error(`No methodology version released by ${datasetVersion}`)
  return latest.version
}

function toHistory(out: RunOutput): HistoricalPoint[] {
  return out.vendors.map((v) => {
    const metrics: Record<string, number | null> = {}
    for (const g of v.goals) for (const m of g.metrics) metrics[m.metricId] = m.value
    const vdpCriteria: Record<string, string> = {}
    for (const c of v.vdp?.criteria ?? []) vdpCriteria[c.criterion] = c.state
    return {
      runId: out.manifest.runId,
      datasetVersion: out.manifest.datasetVersion,
      asOf: out.manifest.asOf,
      methodologyVersion: out.manifest.methodologyVersion,
      vendorId: v.vendor.id,
      metrics,
      vdpCriteria,
    }
  })
}

const files = new Map<string, string>()
const put = (path: string, value: unknown, pretty = false) =>
  files.set(path, (pretty ? JSON.stringify(value, null, 2) : JSON.stringify(value)) + '\n')

const outputs: RunOutput[] = []
let history: HistoricalPoint[] = []
for (const datasetVersion of DEMO_DATASET_VERSIONS) {
  const version = methodologyFor(datasetVersion)
  const inputs = loadDemoInputs({ root: demoRoot, datasetVersion, methodologyVersion: version, history })
  const out = executeRun(inputs)
  const { summary, vendors } = splitForPublication(out, methodologyVersion(version))
  const runDir = join(outRoot, 'runs', out.manifest.runId)
  put(join(runDir, 'summary.json'), summary)
  for (const [vendorId, detail] of Object.entries(vendors)) put(join(runDir, 'vendors', `${vendorId}.json`), detail)
  put(join(outRoot, 'inputs', `${datasetVersion}.json`), inputs)
  put(join(expectedRoot, `${out.manifest.runId}.manifest.json`), out.manifest, true)
  outputs.push(out)
  history = [...history, ...toHistory(out)]
}

const latest = outputs[outputs.length - 1]
if (!latest) throw new Error('No demo dataset versions')

const index: RunIndex = {
  mode: 'DEMO',
  latestRunId: latest.manifest.runId,
  builtFrom: 'scripts/build-demo.ts over fixtures/demo (synthetic data)',
  runs: outputs.map((o) => ({
    runId: o.manifest.runId,
    datasetVersion: o.manifest.datasetVersion,
    asOf: o.manifest.asOf,
    methodologyVersion: o.manifest.methodologyVersion,
    mode: o.manifest.mode,
    outputsHash: o.manifest.outputsHash,
    inputsHash: o.manifest.inputsHash,
  })),
}
put(join(outRoot, 'index.json'), index, true)
put(join(outRoot, 'history.json'), historySeries(outputs))
put(join(outRoot, 'disputes.json'), seedDisputes(outputs), true)
put(join(outRoot, 'notebook.json'), seedNotebook(latest), true)

/**
 * Synthetic disputes, one per workflow outcome, attached to findings the demo
 * actually produces so every one of them can be opened from a vendor profile.
 */
function seedDisputes(runs: RunOutput[]): Dispute[] {
  const run = runs[runs.length - 1]!
  const prev = runs[runs.length - 2] ?? run
  const disputes: Dispute[] = []
  const at = (d: string, hhmm: string) => `${d}T${hhmm}:00Z`
  const d0 = run.manifest.datasetVersion
  const p0 = prev.manifest.datasetVersion

  const excluded = run.exclusions.find((e) => e.reason === 'AMBIGUOUS_VENDOR' && e.candidateVendorIds.length > 0)
  if (excluded) {
    disputes.push({
      id: 'DSP-0001',
      vendorId: excluded.candidateVendorIds[0]!,
      target: { kind: 'CVE', id: excluded.cveId },
      runId: run.manifest.runId,
      reason: 'INCORRECT_VENDOR_ATTRIBUTION',
      submitterRole: 'VENDOR',
      statement:
        'This record names our product line, but the affected component ships only in the other vendor’s appliance. We ask that it be attributed to them, not left unattributed.',
      evidenceUrls: ['https://psirt.example/advisories/attribution-note'],
      status: 'OPEN',
      createdAt: at(d0, '09:12'),
      history: [{ at: at(d0, '09:12'), from: null, to: 'OPEN', actor: 'submitter', note: 'Submitted.' }],
      synthetic: true,
    })
  }

  const changed = run.vendors.find((v) => v.vdpChanges.length > 0)
  if (changed) {
    disputes.push({
      id: 'DSP-0002',
      vendorId: changed.vendor.id,
      target: { kind: 'GOAL', id: 'G5' },
      runId: run.manifest.runId,
      reason: 'OUTDATED_SOURCE',
      submitterRole: 'VENDOR',
      statement: 'Our policy was revised after this snapshot; the narrower scope was temporary during a site migration.',
      evidenceUrls: [],
      status: 'UNDER_REVIEW',
      createdAt: at(d0, '11:40'),
      history: [
        { at: at(d0, '11:40'), from: null, to: 'OPEN', actor: 'submitter', note: 'Submitted.' },
        { at: at(d0, '15:05'), from: 'OPEN', to: 'UNDER_REVIEW', actor: 'reviewer', note: 'Scheduled a re-fetch of the policy for the next run.' },
      ],
      synthetic: true,
    })
  }

  const lowCpe = [...prev.vendors]
    .filter((v) => v.goals.some((g) => g.metrics.some((m) => m.metricId === 'cve.cpe_namespace_consistency' && m.value !== null && m.value < 100)))
    .map((v) => v.vendor.id)[0]
  if (lowCpe) {
    disputes.push({
      id: 'DSP-0003',
      vendorId: lowCpe,
      target: { kind: 'METRIC', id: 'cve.cpe_namespace_consistency' },
      runId: prev.manifest.runId,
      reason: 'INCORRECT_PRODUCT_MAPPING',
      submitterRole: 'RESEARCHER',
      statement: 'Several CPEs use the vendor’s pre-acquisition namespace. The registry should list both namespaces with the acquisition as evidence.',
      evidenceUrls: ['https://research.example/notes/cpe-namespaces'],
      status: 'CORRECTED',
      createdAt: at(p0, '10:00'),
      history: [
        { at: at(p0, '10:00'), from: null, to: 'OPEN', actor: 'submitter', note: 'Submitted.' },
        { at: at(p0, '16:20'), from: 'OPEN', to: 'UNDER_REVIEW', actor: 'reviewer', note: 'Checking the acquisition announcement.' },
        {
          at: at(d0, '08:30'),
          from: 'UNDER_REVIEW',
          to: 'CORRECTED',
          actor: 'reviewer',
          note: 'Registry decision recorded. The original run is unchanged; the corrected figure appears in the later run.',
          correctedInRunId: run.manifest.runId,
        },
      ],
      synthetic: true,
    })
  }

  const anyVendor = run.vendors.find((v) => v.goals.some((g) => g.goalId === 'G6' && g.status === 'PARTIAL'))
  if (anyVendor) {
    disputes.push({
      id: 'DSP-0004',
      vendorId: anyVendor.vendor.id,
      target: { kind: 'METRIC', id: 'cve.cwe_coverage' },
      runId: run.manifest.runId,
      reason: 'METHODOLOGY_ERROR',
      submitterRole: 'VENDOR',
      statement: 'NVD shows a CWE for these records, so CWE coverage should be 100%.',
      evidenceUrls: [],
      status: 'DISMISSED',
      createdAt: at(d0, '13:15'),
      history: [
        { at: at(d0, '13:15'), from: null, to: 'OPEN', actor: 'submitter', note: 'Submitted.' },
        {
          at: at(d0, '17:45'),
          from: 'OPEN',
          to: 'DISMISSED',
          actor: 'reviewer',
          note: 'The CWE on those records was added by a third party (ADP enrichment), not supplied in the CNA container. The pledge metric credits the manufacturer’s own record data; enrichment is reported separately.',
        },
      ],
      synthetic: true,
    })
  }
  return disputes
}

function seedNotebook(run: RunOutput): NotebookEntry[] {
  const conflict = run.identityConflicts[0]
  const entries: NotebookEntry[] = [
    {
      id: 'NB-0001',
      title: 'Third-party enrichment hides gaps in vendor records',
      observation:
        'One vendor’s records look complete on NVD, but most CWE values come from an ADP container, not the CNA container. Crediting them would measure the enricher, not the manufacturer.',
      resolution: 'Methodology credits CNA-supplied fields only and reports enrichment as its own metric (cve.enriched_only).',
      createdAt: `${run.manifest.datasetVersion}T09:00:00Z`,
      tags: ['cve-quality', 'methodology'],
      synthetic: true,
    },
    {
      id: 'NB-0002',
      title: 'Placeholder CWEs are not weaknesses',
      observation: 'Under methodology 1.0.0, NVD-CWE-noinfo counted as a populated CWE. It states that no weakness was identified.',
      resolution: 'Methodology 1.1.0 stops counting placeholders. Runs made under 1.0.0 keep their published figures.',
      createdAt: '2026-06-15T09:00:00Z',
      tags: ['methodology', 'versioning'],
      synthetic: true,
    },
  ]
  if (conflict) {
    entries.push({
      id: 'NB-0003',
      vendorId: conflict.vendorIds[0],
      title: `Identity conflict on ${conflict.aliasKind} "${conflict.value}"`,
      observation: conflict.note,
      resolution: 'Records using the shared name stay excluded until a registry decision cites evidence for one vendor.',
      createdAt: `${run.manifest.datasetVersion}T10:30:00Z`,
      tags: ['identity'],
      synthetic: true,
    })
  }
  return entries
}

// ------------------------------------------------------------------ write / check

function listFiles(dir: string): string[] {
  if (!existsSync(dir)) return []
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => join(e.parentPath, e.name))
}

if (check) {
  const problems: string[] = []
  for (const [path, content] of files) {
    if (!existsSync(path)) problems.push(`missing: ${relative(root, path)}`)
    else if (readFileSync(path, 'utf8') !== content) problems.push(`differs: ${relative(root, path)}`)
  }
  for (const path of [...listFiles(join(outRoot, 'runs')), ...listFiles(join(outRoot, 'inputs')), ...listFiles(expectedRoot)]) {
    if (!files.has(path)) problems.push(`stale: ${relative(root, path)}`)
  }
  if (problems.length) {
    console.error(`Published demo data is out of date (${problems.length} problems). Run: npm run demo:build`)
    for (const p of problems.slice(0, 20)) console.error(`  ${p}`)
    process.exit(1)
  }
  console.log(`demo data up to date: ${files.size} files, ${outputs.length} runs`)
} else {
  for (const dir of [join(outRoot, 'runs'), join(outRoot, 'inputs'), expectedRoot]) rmSync(dir, { recursive: true, force: true })
  for (const [path, content] of files) {
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, content)
  }
  for (const o of outputs) {
    console.log(`${o.manifest.runId}  ${o.manifest.datasetVersion}  methodology ${o.manifest.methodologyVersion}  ${o.vendors.length} vendors  outputs ${o.manifest.outputsHash.slice(0, 12)}`)
  }
  console.log(`wrote ${files.size} files to ${relative(root, outRoot)}`)
}

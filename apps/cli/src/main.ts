#!/usr/bin/env node
/**
 * TOUCHSTONE command line.
 *
 *   touchstone --version
 *   touchstone run --dataset demo --version <datasetVersion> [--methodology x.y.z] [--out <dir>] [--format text|json]
 *   touchstone reproduce <runId> [--data <dir>]
 *   touchstone export <vendorId> --format md|csv|json|pdf [--out <file>] [--run <runId>] [--data <dir>]
 *   touchstone methodology [--version [x.y.z]]
 *   touchstone goals [--format text|json]
 *   touchstone collect --live --vendor <id> --registry <file> --out <dir>
 *
 * Exit codes: 0 ok; 1 usage, input or engine error; 3 reproduce: outputsHash did not match.
 *
 * Only `collect --live` makes network requests. Every other command reads
 * local files (the bundled demo fixtures or a published data directory) and
 * writes only to --out. All data-derived text is stripped of control,
 * escape and bidi characters before it reaches the terminal.
 */
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { GOALS } from '../../../packages/core/src/methodology/goals.ts'
import { CURRENT_METHODOLOGY_VERSION, METHODOLOGY_VERSIONS } from '../../../packages/core/src/methodology/versions.ts'
import type {
  Dispute,
  HistoricalPoint,
  HistorySeries,
  RunIndex,
  RunInputs,
  RunOutput,
  RunSummary,
  VendorDetail,
} from '../../../packages/core/src/model/index.ts'
import { colorEnabled, jsonSafe, pad, style, term, termDocument, wrapText } from './terminal.ts'
import type { Style } from './terminal.ts'

export const CLI_VERSION = '0.1.0'
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const DEFAULT_DATA = join(REPO_ROOT, 'apps', 'web', 'public', 'data')
const DEFAULT_FIXTURES = join(REPO_ROOT, 'fixtures', 'demo')
const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/
const VENDOR_ID_RE = /^[a-z0-9][a-z0-9-]{0,99}$/
const SEMVER_RE = /^\d{1,4}\.\d{1,4}\.\d{1,4}$/
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/

export const EXIT = { OK: 0, ERROR: 1, NOT_REPRODUCED: 3 } as const

/** Thrown for anything that should exit 1 with a one-line message. */
class CliError extends Error {
  readonly detail: string[]
  constructor(message: string, detail: string[] = []) {
    super(message)
    this.detail = detail
  }
}

const HELP = `TOUCHSTONE ${CLI_VERSION}: publicly observable evidence behind Secure by Design Pledge commitments

Usage
  touchstone run --dataset demo --version <datasetVersion> [--methodology x.y.z] [--out <dir>] [--format text|json]
        Run the pipeline over a bundled demo dataset version (no network).
  touchstone reproduce <runId> [--data <dir>]
        Re-execute a published run from its own inputs and methodology; compare outputsHash.
  touchstone export <vendorId> --format md|csv|json|pdf [--out <file>] [--run <runId>] [--data <dir>]
        Render a vendor evidence report from a published data directory.
  touchstone methodology [--version [x.y.z]]
        List methodology versions, or show one with its parameters.
  touchstone goals [--format text|json]
        The seven pledge goals and whether each is externally verifiable.
  touchstone collect --live --vendor <id>[,<id>...] --registry <file> --out <dir>
                   [--enumerate-nvd] [--cve <id>[,<id>...]] [--max-cves <n>]
        Collect live public sources (network) and score them locally. Refuses to
        run without --live. --enumerate-nvd lists the vendor's CVE ids from the
        NVD API by CNA org id (one request per 6.5 s without an API key).

Options
  --data <dir>     published data directory (default apps/web/public/data)
  --no-color       plain output (NO_COLOR is honoured too)
  -h, --help       this help
  -V, --version    print the version (when no command is given)

Exit codes
  0 ok    1 usage, input or engine error    3 reproduce: outputsHash differs from the published run`

type Opts = {
  command: string | null
  positional: string[]
  values: Map<string, string>
  flags: Set<string>
}

/** Options that take a value, per command. `--version` takes one for run and (optionally) methodology. */
const VALUE_OPTIONS: Record<string, string[]> = {
  run: ['--dataset', '--version', '--methodology', '--out', '--format', '--fixtures', '--data'],
  reproduce: ['--data'],
  export: ['--format', '--out', '--run', '--data'],
  methodology: ['--version'],
  goals: ['--format'],
  collect: ['--vendor', '--registry', '--out', '--cve', '--max-cves'],
}
const FLAG_OPTIONS: Record<string, string[]> = {
  collect: ['--live', '--enumerate-nvd'],
}
const COMMANDS = Object.keys(VALUE_OPTIONS)

export function parseArgs(argv: string[]): Opts {
  const o: Opts = { command: null, positional: [], values: new Map(), flags: new Set() }
  for (let i = 0; i < argv.length; i++) {
    let a = argv[i]!
    let inline: string | undefined
    const eq = a.startsWith('--') ? a.indexOf('=') : -1
    if (eq > 0) {
      inline = a.slice(eq + 1)
      a = a.slice(0, eq)
    }
    if (a === '-h' || a === '--help') {
      o.flags.add('--help')
      continue
    }
    if (a === '--no-color') {
      o.flags.add('--no-color')
      continue
    }
    if (o.command === null && !a.startsWith('-')) {
      if (!COMMANDS.includes(a)) throw new CliError(`Unknown command "${term(a)}". See --help.`)
      o.command = a
      continue
    }
    if (o.command === null && (a === '-V' || a === '--version')) {
      o.flags.add('--version')
      continue
    }
    if (a.startsWith('-')) {
      const cmd = o.command ?? ''
      if ((FLAG_OPTIONS[cmd] ?? []).includes(a)) {
        o.flags.add(a)
        continue
      }
      if (!(VALUE_OPTIONS[cmd] ?? []).includes(a)) throw new CliError(`Unknown option ${term(a)}${cmd ? ` for ${cmd}` : ''}. See --help.`)
      let v = inline
      if (v === undefined) {
        const next = argv[i + 1]
        // `methodology --version` with no value means "the current version".
        if (next === undefined || next.startsWith('-')) {
          if (cmd === 'methodology' && a === '--version') v = CURRENT_METHODOLOGY_VERSION
          else throw new CliError(`${a} needs a value.`)
        } else {
          v = next
          i++
        }
      }
      if (o.values.has(a) && a !== '--vendor') throw new CliError(`${a} given twice.`)
      o.values.set(a, o.values.has(a) ? `${o.values.get(a)},${v}` : v)
      continue
    }
    o.positional.push(a)
  }
  return o
}

/* ------------------------------------------------------------------ io */

type Io = { out: (s: string) => void; err: (s: string) => void; s: Style; stdoutIsTty: boolean }

function readJson<T>(path: string, what: string): T {
  if (!existsSync(path)) throw new CliError(`${what} not found: ${term(path)}`)
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as T
  } catch {
    throw new CliError(`${what} is not valid JSON: ${term(path)}`)
  }
}

function dataDir(o: Opts): string {
  return resolve(o.values.get('--data') ?? DEFAULT_DATA)
}

function loadIndex(dir: string): RunIndex {
  const index = readJson<RunIndex>(join(dir, 'index.json'), 'Run index')
  if (!index || !Array.isArray(index.runs)) throw new CliError(`Run index ${term(join(dir, 'index.json'))} has no runs.`)
  return index
}

function findRun(index: RunIndex, runId: string) {
  if (!RUN_ID_RE.test(runId)) throw new CliError(`"${term(runId)}" is not a run id (e.g. TS-2026-10-06-1a2b).`)
  const entry = index.runs.find((r) => r.runId === runId)
  if (!entry) throw new CliError(`Run ${term(runId)} is not in this data directory.`, [`Available: ${index.runs.map((r) => term(r.runId)).join(', ')}`])
  return entry
}

/* -------------------------------------------------------------- engine */

async function engine() {
  try {
    const [run, split, versions, demo] = await Promise.all([
      import('../../../packages/core/src/run/run.ts'),
      import('../../../packages/core/src/publish/split.ts'),
      import('../../../packages/core/src/methodology/versions.ts'),
      import('../../../packages/collect/src/demo.ts'),
    ])
    return { ...run, ...split, ...versions, ...demo }
  } catch (e) {
    throw new CliError(`The measurement engine could not be loaded: ${term(e instanceof Error ? e.message : String(e))}`)
  }
}

async function reportEngine() {
  try {
    const report = await import('../../../packages/core/src/report/vendor-report.ts')
    return report.vendorReport
  } catch (e) {
    throw new CliError(`The report generator could not be loaded: ${term(e instanceof Error ? e.message : String(e))}`)
  }
}

/** The methodology version in force on a dataset date: the latest released on or before it. */
export function methodologyFor(datasetVersion: string): string {
  const eligible = METHODOLOGY_VERSIONS.filter((m) => m.releasedOn <= datasetVersion)
  const latest = eligible[eligible.length - 1]
  if (!latest) throw new CliError(`No methodology version was released by ${term(datasetVersion)}.`)
  return latest.version
}

/** Per-vendor figures of a run, as the next run's historical baseline (same rule as scripts/build-demo.ts). */
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

/* ------------------------------------------------------------ commands */

async function cmdRun(o: Opts, io: Io): Promise<number> {
  const dataset = o.values.get('--dataset')
  if (dataset !== 'demo') {
    throw new CliError(dataset === undefined ? 'run needs --dataset demo.' : `Unknown dataset "${term(dataset)}". Only --dataset demo is supported; live sources are collected with "collect --live".`)
  }
  const version = o.values.get('--version')
  if (!version) throw new CliError('run needs --version <datasetVersion>, e.g. --version 2026-10-06.')
  const format = o.values.get('--format') ?? 'text'
  if (format !== 'text' && format !== 'json') throw new CliError('--format must be text or json.')
  const e = await engine()
  if (!e.DEMO_DATASET_VERSIONS.includes(version)) {
    throw new CliError(`Unknown demo dataset version "${term(version)}".`, [`Available: ${e.DEMO_DATASET_VERSIONS.join(', ')}`])
  }
  const requested = o.values.get('--methodology')
  if (requested !== undefined && !METHODOLOGY_VERSIONS.some((m) => m.version === requested)) {
    throw new CliError(`Unknown methodology version "${term(requested)}".`, [`Available: ${METHODOLOGY_VERSIONS.map((m) => m.version).join(', ')}`])
  }
  const methodology = requested ?? methodologyFor(version)
  const root = resolve(o.values.get('--fixtures') ?? DEFAULT_FIXTURES)

  // Earlier dataset versions run first, each with the methodology in force on its date, so this run's
  // historical baselines are the ones the published bundle was built with.
  let history: HistoricalPoint[] = []
  let out: RunOutput | null = null
  let inputs: RunInputs | null = null
  for (const v of e.DEMO_DATASET_VERSIONS) {
    const target = v === version
    const m = target ? methodology : methodologyFor(v)
    if (!target) io.err(io.s.dim(`  baseline ${v} (methodology ${m})`))
    const i = e.loadDemoInputs({ root, datasetVersion: v, methodologyVersion: m, history })
    const r = e.executeRun(i)
    if (target) {
      out = r
      inputs = i
      break
    }
    history = [...history, ...toHistory(r)]
  }
  if (!out || !inputs) throw new CliError(`Dataset ${term(version)} was not reached.`)
  const man = out.manifest

  let published: string | null = null
  const indexPath = join(dataDir(o), 'index.json')
  if (existsSync(indexPath)) {
    const index = readJson<RunIndex>(indexPath, 'Run index')
    const p = index.runs?.find((r) => r.runId === man.runId)
    if (p) published = p.outputsHash === man.outputsHash ? `matches published run ${term(p.runId)}` : `DIFFERS from published run ${term(p.runId)} (published ${term(p.outputsHash).slice(0, 16)})`
    else if (requested !== undefined && requested !== methodologyFor(version)) published = `not published: methodology ${methodology} is not the one in force on ${version} (${methodologyFor(version)})`
  }

  if (o.values.has('--out')) {
    const dir = resolve(o.values.get('--out')!, man.runId)
    const { summary, vendors } = e.splitForPublication(out, e.methodologyVersion(methodology))
    mkdirSync(join(dir, 'vendors'), { recursive: true })
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify(man, null, 2) + '\n')
    writeFileSync(join(dir, 'summary.json'), JSON.stringify(summary) + '\n')
    writeFileSync(join(dir, 'inputs.json'), JSON.stringify(inputs) + '\n')
    for (const [vendorId, detail] of Object.entries(vendors)) {
      if (!VENDOR_ID_RE.test(vendorId)) throw new CliError(`Refusing to write a vendor file for id "${term(vendorId)}".`)
      writeFileSync(join(dir, 'vendors', `${vendorId}.json`), JSON.stringify(detail) + '\n')
    }
    io.err(`Wrote ${term(dir)}`)
  }

  if (format === 'json') {
    io.out(jsonSafe(JSON.stringify({ manifest: man, published }, null, 2)))
    return EXIT.OK
  }
  const s = io.s
  io.out(`${s.bold('Run')}            ${term(man.runId)}  ${s.dim(`(${man.mode}, synthetic demo data)`)}`)
  io.out(`Dataset        ${term(man.datasetVersion)}   as of ${term(man.asOf)}`)
  io.out(`Methodology    ${term(man.methodologyVersion)}   parser ${term(man.parserVersion)}   scoring ${term(man.scoringVersion)}`)
  io.out(`Inputs hash    ${term(man.inputsHash)}`)
  io.out(`Outputs hash   ${term(man.outputsHash)}`)
  io.out(`Vendors        ${out.vendors.length}   CVE records ${out.cves.length}   evidence items ${out.evidence.length}`)
  if (published) io.out(`Published      ${published}`)
  io.out('')
  io.out(s.bold('Stages'))
  for (const st of man.stages) {
    const mark = st.status === 'OK' ? s.green(pad(st.status, 7)) : st.status === 'FAILED' ? s.red(pad(st.status, 7)) : s.yellow(pad(term(st.status), 7))
    io.out(`  ${pad(term(st.stage), 10)} ${mark} ${term(st.detail)}`)
  }
  const failed = man.qualityChecks.filter((q) => !q.passed)
  io.out('')
  io.out(`${s.bold('Quality checks')} ${man.qualityChecks.length - failed.length}/${man.qualityChecks.length} passed`)
  for (const q of failed) io.out(`  ${s.yellow('not passed')} ${term(q.question)} ${s.dim(term(q.detail))}`)
  io.out('')
  io.out(s.dim('No network calls were made: the run replays the bundled demo snapshots.'))
  return EXIT.OK
}

async function cmdReproduce(o: Opts, io: Io): Promise<number> {
  const runId = o.positional[0]
  if (!runId) throw new CliError('reproduce needs a run id, e.g. touchstone reproduce TS-2026-10-06-1a2b.')
  if (o.positional.length > 1) throw new CliError('reproduce takes one run id.')
  const dir = dataDir(o)
  const entry = findRun(loadIndex(dir), runId)
  const summary = readJson<RunSummary>(join(dir, 'runs', entry.runId, 'summary.json'), `Summary of ${term(entry.runId)}`)
  if (!DATE_RE.test(entry.datasetVersion)) throw new CliError(`Run ${term(entry.runId)} has an invalid dataset version.`)
  const inputs = readJson<RunInputs>(join(dir, 'inputs', `${entry.datasetVersion}.json`), `Inputs of ${term(entry.runId)}`)
  const e = await engine()
  const t0 = performance.now()
  const r = e.reproduceRun(inputs, summary.manifest)
  const ms = Math.round(performance.now() - t0)
  const s = io.s
  io.out(`${s.bold('Run')}              ${term(entry.runId)}   dataset ${term(entry.datasetVersion)}   methodology ${term(inputs.methodologyVersion)}`)
  io.out(`Published hash   ${term(summary.manifest.outputsHash)}`)
  io.out(`Reproduced hash  ${term(r.outputsHash)}`)
  io.out(`Inputs hash      ${term(r.inputsHash)}${r.inputsHash === summary.manifest.inputsHash ? '' : s.yellow('  (differs from the published inputsHash)')}`)
  io.out(`Time             ${ms} ms`)
  if (r.reproduced) {
    io.out(s.green('REPRODUCED') + ' identical outputs from the run’s own inputs and methodology. Nothing was fetched.')
    return EXIT.OK
  }
  io.out(s.red('NOT REPRODUCED') + ' the outputs differ from the published run.')
  for (const m of r.mismatches.slice(0, 50)) io.out(`  ${term(m)}`)
  if (r.mismatches.length > 50) io.out(`  … ${r.mismatches.length - 50} more`)
  return EXIT.NOT_REPRODUCED
}

const EXPORT_FORMATS: Record<string, 'markdown' | 'csv' | 'json' | 'pdf'> = { md: 'markdown', markdown: 'markdown', csv: 'csv', json: 'json', pdf: 'pdf' }

async function cmdExport(o: Opts, io: Io): Promise<number> {
  const vendorId = o.positional[0]
  if (!vendorId) throw new CliError('export needs a vendor id, e.g. touchstone export northwind-systems --format md.')
  if (!VENDOR_ID_RE.test(vendorId)) throw new CliError(`"${term(vendorId)}" is not a vendor id (lower-case letters, digits and hyphens).`)
  const formatRaw = (o.values.get('--format') ?? '').toLowerCase()
  const format = EXPORT_FORMATS[formatRaw]
  if (!format) throw new CliError('export needs --format md, csv, json or pdf.')
  const out = o.values.get('--out')
  if (format === 'pdf' && !out && io.stdoutIsTty) throw new CliError('A PDF is binary: pass --out <file>, or redirect stdout to a file.')
  const dir = dataDir(o)
  const index = loadIndex(dir)
  const entry = findRun(index, o.values.get('--run') ?? index.latestRunId)
  const summary = readJson<RunSummary>(join(dir, 'runs', entry.runId, 'summary.json'), `Summary of ${term(entry.runId)}`)
  if (!summary.vendors.some((v) => v.vendor.id === vendorId)) {
    throw new CliError(`Vendor ${term(vendorId)} is not in run ${term(entry.runId)}.`, [
      `Vendors: ${summary.vendors.map((v) => term(v.vendor.id)).slice(0, 40).join(', ')}`,
    ])
  }
  const detail = readJson<VendorDetail>(join(dir, 'runs', entry.runId, 'vendors', `${vendorId}.json`), `Evidence of ${vendorId}`)
  const disputesPath = join(dir, 'disputes.json')
  const disputes = existsSync(disputesPath) ? readJson<Dispute[]>(disputesPath, 'Disputes').filter((d) => d.vendorId === vendorId) : []
  const historyPath = join(dir, 'history.json')
  const history = existsSync(historyPath) ? readJson<HistorySeries[]>(historyPath, 'History').filter((h) => h.vendorId === vendorId) : []
  const vendorReport = await reportEngine()
  const body = vendorReport(summary, detail, disputes, history, format)
  if (out) {
    const path = resolve(out)
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, typeof body === 'string' ? body : new Uint8Array(body))
    io.err(`Wrote ${term(path)} (${format}, run ${term(entry.runId)})`)
    return EXIT.OK
  }
  if (typeof body !== 'string') {
    process.stdout.write(new Uint8Array(body))
    return EXIT.OK
  }
  io.out(format === 'json' ? jsonSafe(body) : termDocument(body))
  return EXIT.OK
}

function cmdMethodology(o: Opts, io: Io): number {
  const s = io.s
  const v = o.values.get('--version')
  if (v === undefined) {
    for (const m of METHODOLOGY_VERSIONS) {
      io.out(`${s.bold(m.version)}  released ${m.releasedOn}${m.version === CURRENT_METHODOLOGY_VERSION ? s.green('  (current)') : ''}`)
      for (const c of m.changes) io.out(wrapText(c, 96, '    '))
    }
    io.out('')
    io.out(s.dim('Show one with its parameters: touchstone methodology --version <x.y.z>'))
    return EXIT.OK
  }
  if (!SEMVER_RE.test(v)) throw new CliError(`"${term(v)}" is not a version like 1.1.0.`)
  const m = METHODOLOGY_VERSIONS.find((x) => x.version === v)
  if (!m) throw new CliError(`Unknown methodology version ${term(v)}.`, [`Available: ${METHODOLOGY_VERSIONS.map((x) => x.version).join(', ')}`])
  io.out(`${s.bold(`Methodology ${m.version}`)}  released ${m.releasedOn}   parser ${m.parserVersion}   scoring ${m.scoringVersion}`)
  io.out('')
  io.out(s.bold('Changes'))
  for (const c of m.changes) io.out(wrapText(c, 96, '  '))
  io.out('')
  io.out(s.bold('Parameters'))
  for (const [k, val] of Object.entries(m.parameters)) io.out(`  ${pad(k, 34)} ${JSON.stringify(val)}`)
  return EXIT.OK
}

function cmdGoals(o: Opts, io: Io): number {
  const format = o.values.get('--format') ?? 'text'
  if (format === 'json') {
    io.out(jsonSafe(JSON.stringify(GOALS, null, 2)))
    return EXIT.OK
  }
  if (format !== 'text') throw new CliError('--format must be text or json.')
  const s = io.s
  const label: Record<string, string> = {
    PUBLICLY_MEASURABLE: 'Publicly measurable',
    PARTIALLY_MEASURABLE: 'Partially measurable',
    NOT_EXTERNALLY_VERIFIABLE: 'Not externally verifiable',
  }
  for (const g of GOALS) {
    io.out(`${s.bold(g.id)}  ${pad(g.name, 44)} ${label[g.verificationMode] ?? g.verificationMode}`)
    io.out(s.dim(wrapText(`“${g.pledgeText}”`, 96, '    ')))
  }
  io.out('')
  io.out(s.dim('Not externally verifiable is a property of the public evidence boundary, never a finding about a vendor.'))
  return EXIT.OK
}

async function cmdCollect(o: Opts, io: Io): Promise<number> {
  if (!o.flags.has('--live')) {
    throw new CliError('collect makes network requests to public sources (CISA, the CVE Program, vendor sites). Re-run with --live to confirm.', [
      'Without --live nothing is fetched. To work offline, use "touchstone run --dataset demo".',
    ])
  }
  const vendors = (o.values.get('--vendor') ?? '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
  if (!vendors.length) throw new CliError('collect needs --vendor <id> (repeat it or comma-separate ids).')
  for (const v of vendors) if (!VENDOR_ID_RE.test(v)) throw new CliError(`"${term(v)}" is not a vendor id.`)
  const registry = o.values.get('--registry')
  if (!registry) throw new CliError('collect needs --registry <file> (the vendor registry JSON).')
  if (!existsSync(registry)) throw new CliError(`Registry not found: ${term(registry)}`)
  const out = o.values.get('--out')
  if (!out) throw new CliError('collect needs --out <dir> for the snapshots.')
  let collect
  try {
    collect = await import('@touchstone/collect')
  } catch (e) {
    throw new CliError(`The live collector could not be loaded: ${term(e instanceof Error ? e.message : String(e))}`)
  }
  io.err(io.s.yellow(`Collecting live public sources for ${vendors.map(term).join(', ')}. This makes network requests.`))
  const outDir = resolve(out)
  const cveList = (o.values.get('--cve') ?? '')
    .split(',')
    .map((x) => x.trim().toUpperCase())
    .filter(Boolean)
  for (const id of cveList) if (!/^CVE-\d{4}-\d{4,7}$/.test(id)) throw new CliError(`"${term(id)}" is not a CVE id.`)
  if (cveList.length && vendors.length !== 1) throw new CliError('--cve needs exactly one --vendor (the ids are attributed by the engine, not by this flag).')
  const maxRaw = o.values.get('--max-cves')
  const maxCves = maxRaw === undefined ? undefined : Number(maxRaw)
  if (maxCves !== undefined && (!Number.isInteger(maxCves) || maxCves < 1 || maxCves > 5000)) throw new CliError('--max-cves must be an integer from 1 to 5000.')
  const { errors, ...inputs } = await collect.collectLive({
    vendorIds: vendors,
    registryPath: resolve(registry),
    outDir,
    enumerateNvd: o.flags.has('--enumerate-nvd'),
    ...(cveList.length ? { cveIds: { [vendors[0]!]: cveList } } : {}),
    ...(maxCves !== undefined ? { maxCvesPerVendor: maxCves } : {}),
  })
  mkdirSync(outDir, { recursive: true })
  const inputsPath = join(outDir, 'inputs.json')
  writeFileSync(inputsPath, JSON.stringify(inputs) + '\n')
  const notOk = inputs.snapshots.filter((x) => x.status !== 'OK')
  const s = io.s
  io.out(`${s.bold('Collected')}   ${inputs.snapshots.length} snapshot(s), ${notOk.length} not OK, as of ${term(inputs.asOf)}`)
  io.out(`Vendors     ${inputs.vendors.map((v) => term(v.id)).join(', ')}`)
  io.out(`Records     ${inputs.cves.length} CVE record(s), ${inputs.advisories.length} advisory(ies), ${inputs.vdp.length} VDP observation(s)`)
  for (const x of notOk.slice(0, 20)) io.out(`  ${s.yellow(pad(term(x.status), 8))} ${term(x.sourceId)} ${term(x.url)} ${s.dim(term(x.error ?? ''))}`)
  if (errors.length) {
    io.out(s.yellow(`${errors.length} collection error(s):`))
    for (const e of errors.slice(0, 20)) io.out(`  ${term(e)}`)
  }
  io.out(`Inputs      ${term(inputsPath)}`)

  // Score the collected inputs locally, exactly as a published run would be scored.
  const e = await engine()
  const run = e.executeRun(inputs)
  const man = run.manifest
  writeFileSync(join(outDir, 'manifest.json'), `${JSON.stringify(man, null, 2)}\n`)
  io.out('')
  io.out(`${s.bold('Run')}         ${term(man.runId)}  ${s.dim(`(LIVE, methodology ${term(man.methodologyVersion)})`)}`)
  io.out(`Outputs     ${term(man.outputsHash)}`)
  for (const v of run.vendors) {
    io.out('')
    io.out(s.bold(term(v.vendor.canonicalName)))
    for (const g of v.goals) io.out(`  ${pad(term(g.goalId), 4)} ${pad(term(g.status), 26)} ${s.dim(term(g.statusReason))}`)
    for (const d of v.dimensions) io.out(`  ${pad(term(d.dimension), 15)} ${d.value === null ? s.dim('not measured') : `${d.value.toFixed(1)}`}`)
    io.out(`  Evidence coverage ${v.coverage.percent.toFixed(0)}% (${v.coverage.observedSlots}/${v.coverage.totalSlots} slots)`)
  }
  io.out('')
  io.out(s.dim('Snapshots are content-addressed under the output directory. Nothing is published automatically.'))
  return EXIT.OK
}

/* ---------------------------------------------------------------- main */

export async function main(argv: string[], io?: Partial<Io>): Promise<number> {
  const errStream = process.stderr
  const outStream = process.stdout
  let o: Opts
  try {
    o = parseArgs(argv)
  } catch (e) {
    errStream.write(`touchstone: ${e instanceof Error ? e.message : String(e)}\n`)
    return EXIT.ERROR
  }
  const color = colorEnabled(outStream, process.env, o.flags.has('--no-color'))
  const full: Io = {
    out: io?.out ?? ((s: string) => outStream.write(`${s}\n`)),
    err: io?.err ?? ((s: string) => errStream.write(`${s}\n`)),
    s: io?.s ?? style(color),
    stdoutIsTty: io?.stdoutIsTty ?? !!outStream.isTTY,
  }
  if (o.flags.has('--version') && o.command === null) {
    full.out(`touchstone ${CLI_VERSION} (methodology ${CURRENT_METHODOLOGY_VERSION})`)
    return EXIT.OK
  }
  if (o.flags.has('--help') || o.command === null) {
    ;(o.command === null && !o.flags.has('--help') ? full.err : full.out)(HELP)
    return o.flags.has('--help') ? EXIT.OK : EXIT.ERROR
  }
  try {
    switch (o.command) {
      case 'run':
        return await cmdRun(o, full)
      case 'reproduce':
        return await cmdReproduce(o, full)
      case 'export':
        return await cmdExport(o, full)
      case 'methodology':
        return cmdMethodology(o, full)
      case 'goals':
        return cmdGoals(o, full)
      case 'collect':
        return await cmdCollect(o, full)
      default:
        throw new CliError(`Unknown command ${term(o.command)}.`)
    }
  } catch (e) {
    if (e instanceof CliError) {
      full.err(`touchstone: ${e.message}`)
      for (const d of e.detail) full.err(`  ${d}`)
      return EXIT.ERROR
    }
    full.err(`touchstone: unexpected error: ${term(e instanceof Error ? e.message : String(e))}`)
    return EXIT.ERROR
  }
}

function isEntryPoint(): boolean {
  const arg = process.argv[1]
  if (arg === undefined) return false
  try {
    return realpathSync(arg) === realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return false
  }
}

const invokedDirectly = isEntryPoint()
if (invokedDirectly) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code
    },
    (e: unknown) => {
      process.stderr.write(`touchstone: ${term(e instanceof Error ? e.message : String(e))}\n`)
      process.exitCode = 1
    },
  )
}

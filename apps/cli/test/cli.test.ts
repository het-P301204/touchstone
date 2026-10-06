import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { NORTHWIND, RUN_2, buildRun, writeBundle } from '../../api/test/fixtures/bundle.ts'
import { jsonSafe, term, termDocument } from '../src/terminal.ts'

const ROOT = resolve(import.meta.dirname, '..', '..', '..')
const MAIN = join(ROOT, 'apps', 'cli', 'src', 'main.ts')
const tmp = mkdtempSync(join(tmpdir(), 'touchstone-cli-'))
afterAll(() => rmSync(tmp, { recursive: true, force: true }))

function cli(args: string[], env: Record<string, string> = {}) {
  const r = spawnSync(process.execPath, [MAIN, ...args], { cwd: ROOT, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '', ...env }, timeout: 120_000 })
  return { code: r.status, stdout: r.stdout, stderr: r.stderr }
}

const cp = (n: number) => String.fromCodePoint(n)
const ESC = cp(0x1b)
const BEL = cp(0x07)
const CSI = cp(0x9b)
const RLO = cp(0x202e)
const hasControl = (s: string) => [...s].some((ch) => {
  const c = ch.codePointAt(0)!
  return (c < 0x20 && c !== 0x0a && c !== 0x09 && c !== 0x0d) || (c >= 0x7f && c <= 0x9f) || c === 0x202e || c === 0x200b
})

const ENGINE_READY = existsSync(join(ROOT, 'packages', 'core', 'src', 'run', 'run.ts')) && existsSync(join(ROOT, 'packages', 'collect', 'src', 'demo.ts'))
const PUBLISHED = join(ROOT, 'apps', 'web', 'public', 'data')
const DEMO_PUBLISHED = existsSync(join(PUBLISHED, 'index.json'))

describe('basics', () => {
  it('prints version and help', () => {
    const v = cli(['--version'])
    expect(v.code).toBe(0)
    expect(v.stdout).toMatch(/^touchstone \d+\.\d+\.\d+ \(methodology \d+\.\d+\.\d+\)/)
    expect(cli(['-V']).code).toBe(0)
    const h = cli(['--help'])
    expect(h.code).toBe(0)
    expect(h.stdout).toContain('reproduce <runId>')
    expect(h.stdout).toContain('collect --live')
    const none = cli([])
    expect(none.code).toBe(1)
    expect(none.stderr).toContain('Usage')
  })

  it('exits 1 on usage errors with a one-line message', () => {
    expect(cli(['bogus']).code).toBe(1)
    expect(cli(['goals', '--frobnicate']).code).toBe(1)
    expect(cli(['run']).code).toBe(1)
    const ds = cli(['run', '--dataset', 'production', '--version', '2026-10-06'])
    expect(ds.code).toBe(1)
    expect(ds.stderr).toContain('Only --dataset demo is supported')
    expect(cli(['run', '--dataset', 'demo']).stderr).toContain('--version')
    expect(cli(['reproduce']).code).toBe(1)
    expect(cli(['export']).code).toBe(1)
    expect(cli(['export', NORTHWIND]).stderr).toContain('--format')
    expect(cli(['export', '../../etc/passwd', '--format', 'md']).code).toBe(1)
  })
})

describe('goals and methodology', () => {
  it('lists the seven goals with their verification mode', () => {
    const r = cli(['goals'])
    expect(r.code).toBe(0)
    for (const id of ['G1', 'G2', 'G3', 'G4', 'G5', 'G6', 'G7']) expect(r.stdout).toContain(id)
    expect(r.stdout.match(/Not externally verifiable/g)?.length).toBeGreaterThanOrEqual(4)
    expect(r.stdout).not.toMatch(/\bcompliant\b|\binsecure\b|\bfailed\b/i)
    const j = cli(['goals', '--format', 'json'])
    expect(JSON.parse(j.stdout)).toHaveLength(7)
  })

  it('lists methodology versions and shows one with parameters', () => {
    const list = cli(['methodology'])
    expect(list.code).toBe(0)
    expect(list.stdout).toContain('1.0.0')
    expect(list.stdout).toContain('1.1.0')
    const one = cli(['methodology', '--version', '1.0.0'])
    expect(one.code).toBe(0)
    expect(one.stdout).toMatch(/placeholderCweCountsAsPopulated\s+true/)
    const current = cli(['methodology', '--version'])
    expect(current.stdout).toMatch(/Methodology 1\.1\.0/)
    expect(current.stdout).toMatch(/placeholderCweCountsAsPopulated\s+false/)
    expect(cli(['methodology', '--version', '9.9.9']).code).toBe(1)
    expect(cli(['methodology', '--version', 'latest']).code).toBe(1)
  })
})

describe('collect', () => {
  it('refuses to run without --live and fetches nothing', () => {
    const r = cli(['collect', '--vendor', NORTHWIND, '--registry', 'registry.json', '--out', join(tmp, 'snap')])
    expect(r.code).toBe(1)
    expect(r.stderr).toContain('--live')
    expect(existsSync(join(tmp, 'snap'))).toBe(false)
  })

  it('validates its arguments before loading the collector', () => {
    expect(cli(['collect', '--live']).stderr).toContain('--vendor')
    expect(cli(['collect', '--live', '--vendor', 'Bad Id']).code).toBe(1)
    expect(cli(['collect', '--live', '--vendor', NORTHWIND]).stderr).toContain('--registry')
    expect(cli(['collect', '--live', '--vendor', NORTHWIND, '--registry', join(tmp, 'missing.json'), '--out', tmp]).stderr).toContain('Registry not found')
  })
})

describe('terminal safety', () => {
  it('term/termDocument/jsonSafe strip or escape control, escape and bidi characters', () => {
    expect(term(`Evil${ESC}]0;owned${BEL} Corp${RLO}`)).toBe('Evil]0;owned Corp')
    expect(term(`a${CSI}31mb\nc`)).toBe('a31mb c')
    expect(termDocument(`# T${ESC}[2J\r\nline${cp(0x200b)}2\n`)).toBe('# T[2J\nline2\n')
    const j = jsonSafe(JSON.stringify({ name: `x${RLO}y${cp(0x85)}` }))
    expect(hasControl(j)).toBe(false)
    expect(JSON.parse(j).name).toBe(`x${RLO}y${cp(0x85)}`)
  })

  it('strips control characters from bundle data echoed in error messages', () => {
    const dir = join(tmp, 'hostile')
    writeBundle(dir)
    const index = JSON.parse(readFileSync(join(dir, 'index.json'), 'utf8'))
    index.runs[0].runId = `TS-${ESC}[31mEVIL${BEL}`
    writeFileSync(join(dir, 'index.json'), JSON.stringify(index))
    const summaryPath = join(dir, 'runs', RUN_2, 'summary.json')
    const summary = JSON.parse(readFileSync(summaryPath, 'utf8'))
    summary.vendors[0].vendor.id = `evil${ESC}]0;pwned${BEL}${RLO}`
    writeFileSync(summaryPath, JSON.stringify(summary))

    const r1 = cli(['reproduce', 'TS-0000-00-00-0000', '--data', dir])
    expect(r1.code).toBe(1)
    expect(r1.stderr).toContain('EVIL')
    expect(hasControl(r1.stderr)).toBe(false)

    const r2 = cli(['export', 'not-in-run', '--format', 'md', '--data', dir])
    expect(r2.code).toBe(1)
    expect(r2.stderr).toContain('pwned')
    expect(hasControl(r2.stderr)).toBe(false)

    const r3 = cli(['reproduce', `TS-${ESC}[2J`, '--data', dir])
    expect(r3.code).toBe(1)
    expect(hasControl(r3.stderr)).toBe(false)
  })
})

describe.skipIf(!ENGINE_READY)('reproduce with the real engine', () => {
  it('exits 0 when the outputsHash matches and 3 when it does not', async () => {
    const { executeRun } = await import('../../../packages/core/src/run/run.ts')
    const inputs = buildRun(1).inputs
    const out = executeRun(inputs)
    const write = (dir: string, outputsHash: string) => {
      const m = { ...out.manifest, outputsHash }
      mkdirSync(join(dir, 'runs', m.runId), { recursive: true })
      mkdirSync(join(dir, 'inputs'), { recursive: true })
      writeFileSync(join(dir, 'index.json'), JSON.stringify({ mode: 'DEMO', latestRunId: m.runId, builtFrom: 'test', runs: [{ runId: m.runId, datasetVersion: m.datasetVersion, asOf: m.asOf, methodologyVersion: m.methodologyVersion, mode: 'DEMO', outputsHash, inputsHash: m.inputsHash }] }))
      writeFileSync(join(dir, 'runs', m.runId, 'summary.json'), JSON.stringify({ manifest: m }))
      writeFileSync(join(dir, 'inputs', `${m.datasetVersion}.json`), JSON.stringify(inputs))
      return m.runId
    }
    const good = join(tmp, 'repro-good')
    const runId = write(good, out.manifest.outputsHash)
    const ok = cli(['reproduce', runId, '--data', good])
    expect(ok.stderr).toBe('')
    expect(ok.code, ok.stdout).toBe(0)
    expect(ok.stdout).toContain('REPRODUCED')

    const bad = join(tmp, 'repro-bad')
    write(bad, '0'.repeat(64))
    const mismatch = cli(['reproduce', runId, '--data', bad])
    expect(mismatch.code).toBe(3)
    expect(mismatch.stdout).toContain('NOT REPRODUCED')
  })
})

describe.skipIf(!ENGINE_READY || !DEMO_PUBLISHED)('against the published demo bundle', () => {
  it('reproduces the latest published run (exit 0)', () => {
    const index = JSON.parse(readFileSync(join(PUBLISHED, 'index.json'), 'utf8'))
    const r = cli(['reproduce', index.latestRunId])
    expect(r.stderr).toBe('')
    expect(r.code).toBe(0)
  })

  it('run --dataset demo reproduces the published outputsHash', () => {
    const index = JSON.parse(readFileSync(join(PUBLISHED, 'index.json'), 'utf8'))
    const latest = index.runs.find((x: { runId: string }) => x.runId === index.latestRunId)
    const out = join(tmp, 'run-out')
    const r = cli(['run', '--dataset', 'demo', '--version', latest.datasetVersion, '--out', out, '--format', 'json'])
    expect(r.code).toBe(0)
    const parsed = JSON.parse(r.stdout)
    expect(parsed.manifest.outputsHash).toBe(latest.outputsHash)
    expect(parsed.published).toContain('matches published run')
    expect(existsSync(join(out, latest.runId, 'summary.json'))).toBe(true)
    expect(cli(['run', '--dataset', 'demo', '--version', '1999-01-01']).code).toBe(1)
    expect(cli(['run', '--dataset', 'demo', '--version', latest.datasetVersion, '--methodology', '7.0.0']).code).toBe(1)
  })

  it('exports every format; terminal output carries no control characters', () => {
    const index = JSON.parse(readFileSync(join(PUBLISHED, 'index.json'), 'utf8'))
    const summary = JSON.parse(readFileSync(join(PUBLISHED, 'runs', index.latestRunId, 'summary.json'), 'utf8'))
    const vendorId = summary.vendors[0].vendor.id
    for (const format of ['md', 'csv', 'json']) {
      const r = cli(['export', vendorId, '--format', format])
      expect(r.code, format).toBe(0)
      expect(hasControl(r.stdout.replace(/\r/g, ''))).toBe(false)
    }
    const pdf = join(tmp, 'report.pdf')
    const r = cli(['export', vendorId, '--format', 'pdf', '--out', pdf])
    expect(r.code).toBe(0)
    expect(readFileSync(pdf).subarray(0, 5).toString('latin1')).toBe('%PDF-')
  })
})

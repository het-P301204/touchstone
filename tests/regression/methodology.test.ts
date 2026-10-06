/**
 * Methodology regression suite (referenced by packages/core/src/methodology/versions.ts).
 *
 * 1. Each methodology version's full definition (parameters, parser and
 *    scoring versions) is pinned by fingerprint. Editing a parameter in place
 *    without adding a new version fails here: add a version instead.
 * 2. Every published demo run is re-executed from its published inputs
 *    (apps/web/public/data/inputs/<datasetVersion>.json) and must reproduce the
 *    manifest recorded in fixtures/demo/expected/<runId>.manifest.json: same
 *    runId, inputsHash and outputsHash. A formula change without a version
 *    bump changes outputsHash and fails here.
 *
 * Updating a pin is a deliberate act: bump the methodology version (or, for a
 * new dataset, run `node scripts/build-demo.ts`) and update the pin in the
 * same change, with the reason in the methodology `changes` list.
 */

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { METHODOLOGY_VERSIONS } from '../../packages/core/src/methodology/versions.ts'
import { executeRun, methodologyFingerprint, reproduceRun } from '../../packages/core/src/run/run.ts'
import type { RunIndex, RunInputs, RunManifest } from '../../packages/core/src/model/index.ts'

const root = fileURLToPath(new URL('../../', import.meta.url))
const dataRoot = join(root, 'apps', 'web', 'public', 'data')
const expectedRoot = join(root, 'fixtures', 'demo', 'expected')

/** Pinned fingerprints: methodologyFingerprint({version, parameters, parserVersion, scoringVersion}). */
const PINNED: Record<string, string> = {
  '1.0.0': '7172cc3bfba6525e',
  '1.1.0': '7bbea3abf78a5a5d',
}

describe('methodology versions are frozen', () => {
  it('every version has a pinned fingerprint, and it matches', () => {
    const actual = Object.fromEntries(METHODOLOGY_VERSIONS.map((m) => [m.version, methodologyFingerprint(m)]))
    expect(actual).toEqual(PINNED)
  })

  it('versions are unique and listed in release order', () => {
    const versions = METHODOLOGY_VERSIONS.map((m) => m.version)
    expect(new Set(versions).size).toBe(versions.length)
    const released = METHODOLOGY_VERSIONS.map((m) => m.releasedOn)
    expect(released).toEqual([...released].sort())
  })
})

const indexPath = join(dataRoot, 'index.json')
const index: RunIndex | null = existsSync(indexPath) ? (JSON.parse(readFileSync(indexPath, 'utf8')) as RunIndex) : null

describe('published demo runs reproduce their expected manifests', () => {
  it('the demo bundle is present', () => {
    expect(index, 'run `node scripts/build-demo.ts`').not.toBeNull()
    expect(index!.runs.length).toBeGreaterThan(0)
  })

  for (const r of index?.runs ?? []) {
    it(`${r.runId} (${r.datasetVersion}, methodology ${r.methodologyVersion})`, () => {
      const inputs = JSON.parse(readFileSync(join(dataRoot, 'inputs', `${r.datasetVersion}.json`), 'utf8')) as RunInputs
      const expected = JSON.parse(readFileSync(join(expectedRoot, `${r.runId}.manifest.json`), 'utf8')) as RunManifest
      expect(inputs.methodologyVersion).toBe(r.methodologyVersion)
      const rep = reproduceRun(inputs, expected)
      expect(rep.mismatches).toEqual([])
      expect(rep.reproduced).toBe(true)
      expect(rep.outputsHash).toBe(r.outputsHash)
    })
  }

  it('a parameter edited in place (no version bump) does not reproduce', () => {
    const r = index?.runs.at(-1)
    if (!r) return
    const inputs = JSON.parse(readFileSync(join(dataRoot, 'inputs', `${r.datasetVersion}.json`), 'utf8')) as RunInputs
    const expected = JSON.parse(readFileSync(join(expectedRoot, `${r.runId}.manifest.json`), 'utf8')) as RunManifest
    const m = METHODOLOGY_VERSIONS.find((x) => x.version === r.methodologyVersion)!
    const saved = m.parameters
    try {
      m.parameters = { ...saved, timelinessToleranceDays: saved.timelinessToleranceDays + 1 }
      const out = executeRun(inputs)
      expect(out.manifest.inputsHash).not.toBe(expected.inputsHash)
      expect(reproduceRun(inputs, expected).reproduced).toBe(false)
    } finally {
      m.parameters = saved
    }
  })
})

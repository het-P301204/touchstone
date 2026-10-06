/**
 * Reproduce a published run in the browser: fetch the run's own inputs,
 * execute the engine on them, and compare the hashes with the manifest.
 * The engine and the inputs are loaded only when asked for.
 */
import type { RunIndexEntry, RunManifest } from '@touchstone/core/model'
import { getSource } from '../data/source.ts'

export type ReproduceResult = {
  reproduced: boolean
  outputsHash: string
  inputsHash: string
  expectedOutputsHash: string
  expectedInputsHash: string
  mismatches: string[]
  inputBytes: number
  fetchMs: number
  runMs: number
}

export type ReproducePhase = 'fetching' | 'loading-engine' | 'running'

export async function reproduceInBrowser(entry: RunIndexEntry, manifest: RunManifest, onPhase: (p: ReproducePhase) => void): Promise<ReproduceResult> {
  const src = await getSource()
  onPhase('fetching')
  const t0 = performance.now()
  const inputs = await src.inputs(entry.runId, entry.datasetVersion)
  const fetchMs = performance.now() - t0
  const inputBytes = new Blob([JSON.stringify(inputs)]).size
  onPhase('loading-engine')
  const { reproduceRun } = await import('../../../../packages/core/src/run/run.ts')
  onPhase('running')
  // Yield a frame so the "running" state paints before the synchronous engine run.
  await new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)))
  const t1 = performance.now()
  const res = reproduceRun(inputs, manifest)
  const runMs = performance.now() - t1
  return {
    ...res,
    expectedOutputsHash: manifest.outputsHash,
    expectedInputsHash: manifest.inputsHash,
    inputBytes,
    fetchMs,
    runMs,
  }
}

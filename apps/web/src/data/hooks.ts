/**
 * Data hooks over the DataSource, with one shared in-memory cache so a
 * summary or vendor file is fetched once per session no matter how many
 * views read it.
 */
import { useSyncExternalStore } from 'react'
import type { HistorySeries, NotebookEntry, RunIndex, RunSummary, VendorDetail } from '@touchstone/core/model'
import { getSource } from './source.ts'
import type { DataSource, DisputeView } from './source.ts'
import { useUi } from '../state/ui.ts'

export type Loadable<T> = { status: 'loading' } | { status: 'ready'; data: T } | { status: 'error'; error: Error }

type Entry = { state: Loadable<unknown> }

const cache = new Map<string, Entry>()
const listeners = new Set<() => void>()
let version = 0

function notify() {
  version++
  for (const l of listeners) l()
}

function subscribe(l: () => void) {
  listeners.add(l)
  return () => listeners.delete(l)
}

const LOADING: Loadable<never> = { status: 'loading' }

function ensure<T>(key: string, loader: (src: DataSource) => Promise<T>): Loadable<T> {
  const hit = cache.get(key)
  if (hit) return hit.state as Loadable<T>
  const entry: Entry = { state: LOADING }
  cache.set(key, entry)
  getSource()
    .then((src) => loader(src))
    .then(
      (data) => {
        entry.state = { status: 'ready', data }
        notify()
      },
      (error: unknown) => {
        entry.state = { status: 'error', error: error instanceof Error ? error : new Error(String(error)) }
        notify()
      },
    )
  return LOADING
}

/** Drop cached entries whose key starts with `prefix` (all when omitted) and re-render readers. */
export function invalidate(prefix = ''): void {
  for (const key of [...cache.keys()]) if (key.startsWith(prefix)) cache.delete(key)
  notify()
}

export function useLoad<T>(key: string | null, loader: (src: DataSource) => Promise<T>): Loadable<T> {
  useSyncExternalStore(subscribe, () => version)
  if (key === null) return LOADING
  return ensure(key, loader)
}

/** Combine loadables: ready only when all are ready; the first error wins. */
export function all<T extends unknown[]>(...items: { [K in keyof T]: Loadable<T[K]> }): Loadable<T> {
  for (const i of items) if (i.status === 'error') return i
  for (const i of items) if (i.status === 'loading') return LOADING
  return { status: 'ready', data: items.map((i) => (i as { data: unknown }).data) as T }
}

// ---------------------------------------------------------------- hooks

export type SourceInfo = { kind: DataSource['kind']; adminEnabled: boolean; source: DataSource }

export function useSourceInfo(): Loadable<SourceInfo> {
  return useLoad('source', async (src) => ({ kind: src.kind, adminEnabled: src.adminEnabled, source: src }))
}

export function useRunIndex(): Loadable<RunIndex> {
  return useLoad('index', (src) => src.runIndex())
}

/** The run being viewed: an explicitly opened historical run, else the latest. */
export function useActiveRunId(): Loadable<string> {
  const selected = useUi((s) => s.selectedRunId)
  const index = useRunIndex()
  if (index.status !== 'ready') return index
  const exists = selected && index.data.runs.some((r) => r.runId === selected)
  return { status: 'ready', data: exists ? selected : index.data.latestRunId }
}

export function useSummary(runId: string | null): Loadable<RunSummary> {
  return useLoad(runId ? `summary:${runId}` : null, (src) => src.summary(runId!))
}

/** Index + the active run's summary, the pair almost every data view needs. */
export function useActiveSummary(): Loadable<{ index: RunIndex; summary: RunSummary; runId: string; isLatest: boolean }> {
  const index = useRunIndex()
  const runId = useActiveRunId()
  const summary = useSummary(runId.status === 'ready' ? runId.data : null)
  const combined = all<[RunIndex, string, RunSummary]>(index, runId, summary)
  if (combined.status !== 'ready') return combined
  const [i, id, s] = combined.data
  return { status: 'ready', data: { index: i, summary: s, runId: id, isLatest: id === i.latestRunId } }
}

export function useVendorDetail(vendorId: string | null, runId: string | null): Loadable<VendorDetail> {
  return useLoad(vendorId && runId ? `detail:${runId}:${vendorId}` : null, (src) => src.vendorDetail(vendorId!, runId!))
}

/** Every vendor's detail file for a run (evidence ledger, CVE explorer, graph). */
export function useAllDetails(runId: string | null, vendorIds: string[] | null): Loadable<VendorDetail[]> {
  const key = runId && vendorIds ? `details:${runId}:${vendorIds.join(',')}` : null
  return useLoad(key, async (src) => {
    const out: VendorDetail[] = []
    // Bounded concurrency: 6 requests at a time.
    const ids = [...vendorIds!]
    const workers = Array.from({ length: Math.min(6, ids.length) }, async () => {
      while (ids.length) {
        const id = ids.shift()!
        out.push(await src.vendorDetail(id, runId!))
      }
    })
    await Promise.all(workers)
    return out.sort((a, b) => a.vendorId.localeCompare(b.vendorId))
  })
}

export function useHistory(): Loadable<HistorySeries[]> {
  return useLoad('history', (src) => src.history())
}

export function useDisputes(): Loadable<DisputeView[]> {
  return useLoad('disputes', (src) => src.disputes())
}

export function useNotebook(): Loadable<NotebookEntry[]> {
  return useLoad('notebook', (src) => src.notebook())
}

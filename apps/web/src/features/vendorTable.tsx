/**
 * Sorting for vendor tables. Null ("not measured") always sorts last in
 * either direction: a missing value is never ranked as a low one.
 */
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import type { FreshnessState, RunSummary, VendorSummary } from '@touchstone/core/model'
import { cx } from '../lib/cx.ts'
import { dimensionValue, worstFreshness } from './figures.tsx'

export type SortKey = 'name' | 'coverage' | 'quality' | 'vdp' | 'timeliness' | 'freshness'
export type SortDir = 'asc' | 'desc'

const FRESH_RANK: Record<FreshnessState, number> = { CURRENT: 3, AGING: 2, STALE: 1, UNKNOWN: 0 }

export function sortValue(v: VendorSummary, key: SortKey, summary: RunSummary): number | string | null {
  switch (key) {
    case 'name':
      return v.vendor.canonicalName.toLowerCase()
    case 'coverage':
      return v.coverage.percent
    case 'quality':
      return dimensionValue(v, 'CVE_QUALITY')
    case 'vdp':
      return dimensionValue(v, 'VDP')
    case 'timeliness':
      return dimensionValue(v, 'CVE_TIMELINESS')
    case 'freshness': {
      const s = worstFreshness(summary, v.vendor.id)
      return s === 'UNKNOWN' ? null : FRESH_RANK[s]
    }
  }
}

export function sortVendors(list: VendorSummary[], key: SortKey, dir: SortDir, summary: RunSummary): VendorSummary[] {
  return [...list].sort((a, b) => {
    const x = sortValue(a, key, summary)
    const y = sortValue(b, key, summary)
    if (x === null && y === null) return a.vendor.canonicalName.localeCompare(b.vendor.canonicalName)
    if (x === null) return 1
    if (y === null) return -1
    const c = typeof x === 'string' ? x.localeCompare(String(y)) : x - (y as number)
    return (dir === 'asc' ? c : -c) || a.vendor.canonicalName.localeCompare(b.vendor.canonicalName)
  })
}

export function SortTh({
  label,
  k,
  sort,
  dir,
  onSort,
  className,
}: {
  label: string
  k: SortKey
  sort: SortKey
  dir: SortDir
  onSort: (k: SortKey) => void
  className?: string
}) {
  const active = sort === k
  const Icon = !active ? ArrowUpDown : dir === 'asc' ? ArrowUp : ArrowDown
  return (
    <th scope="col" aria-sort={active ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'} className={className}>
      <button type="button" onClick={() => onSort(k)} className={cx('inline-flex items-center gap-1 uppercase hover:text-ink', active && 'text-ink')}>
        {label}
        <Icon aria-hidden="true" className="size-3" />
      </button>
    </th>
  )
}

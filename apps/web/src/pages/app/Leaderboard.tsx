/**
 * Evidence leaderboard. The reader chooses the sort; there is no overall
 * rank and no composite. "Why this vendor ranks here" opens the engine's own
 * ranking notes for each dimension.
 */
import { Fragment, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { ChevronDown } from 'lucide-react'
import { useActiveSummary } from '../../data/hooks.ts'
import { PageHeader } from '../../ui/Panel.tsx'
import { DemoLabel, Segmented } from '../../ui/controls.tsx'
import { EmptyState, Load } from '../../ui/States.tsx'
import { CATEGORY_FILTERS, CATEGORY_LABEL, DIMENSION_LABEL } from '../../lib/vocab.ts'
import { CoverageCell, DimensionCell, FreshnessCell } from '../../features/figures.tsx'
import { SortTh, sortVendors } from '../../features/vendorTable.tsx'
import type { SortDir, SortKey } from '../../features/vendorTable.tsx'
import { cx } from '../../lib/cx.ts'
import type { DimensionId, RunSummary, VendorSummary } from '@touchstone/core/model'

function Notes({ v }: { v: VendorSummary }) {
  const entries = Object.entries(v.rankingNotes)
  return (
    <div className="grid gap-3 py-1 md:grid-cols-3">
      {entries.map(([dim, note]) => (
        <div key={dim} className="min-w-0 rounded-[12px] border border-line bg-surface-raised p-3">
          <p className="ts-eyebrow mb-1">{DIMENSION_LABEL[dim as DimensionId] ?? dim}</p>
          <p className="text-[0.82rem] leading-relaxed text-ink-2">{note}</p>
        </div>
      ))}
      {entries.length === 0 && <p className="text-[0.82rem] text-ink-3">No ranking notes for this vendor.</p>}
    </div>
  )
}

function Row({ v, summary, open, onToggle }: { v: VendorSummary; summary: RunSummary; open: boolean; onToggle: () => void }) {
  const id = `why-${v.vendor.id}`
  return (
    <Fragment>
      <tr>
        <td className="min-w-[12rem] max-w-[16rem]">
          <Link to={`/app/vendors/${v.vendor.id}`} className="ts-ident font-semibold text-ink hover:underline">
            {v.vendor.canonicalName}
          </Link>
          <span className="block text-[0.75rem] text-ink-3">{CATEGORY_LABEL[v.vendor.category]}</span>
        </td>
        <td>
          <CoverageCell v={v} />
        </td>
        <td>
          <DimensionCell v={v} dim="CVE_QUALITY" />
        </td>
        <td>
          <DimensionCell v={v} dim="VDP" />
        </td>
        <td>
          <DimensionCell v={v} dim="CVE_TIMELINESS" />
        </td>
        <td>
          <FreshnessCell summary={summary} vendorId={v.vendor.id} />
        </td>
        <td className="text-right">
          <button type="button" aria-expanded={open} aria-controls={id} onClick={onToggle} className="inline-flex items-center gap-1 whitespace-nowrap text-[0.78rem] font-semibold text-ink-2 hover:text-ink">
            Why here
            <ChevronDown aria-hidden="true" className={cx('size-3.5 transition-transform', open && 'rotate-180')} />
          </button>
        </td>
      </tr>
      {open && (
        <tr id={id}>
          <td colSpan={7} className="bg-paper-2/50">
            <p className="mb-2 text-[0.8rem] font-semibold text-ink">Why this vendor ranks here</p>
            <Notes v={v} />
          </td>
        </tr>
      )}
    </Fragment>
  )
}

export function Leaderboard() {
  const value = useActiveSummary()
  const [filter, setFilter] = useState('all')
  const [sort, setSort] = useState<SortKey>('coverage')
  const [dir, setDir] = useState<SortDir>('desc')
  const [open, setOpen] = useState<string | null>(null)
  const summary = value.status === 'ready' ? value.data.summary : null
  const rows = useMemo(() => {
    if (!summary) return []
    const f = CATEGORY_FILTERS.find((c) => c.id === filter)!
    return sortVendors(
      summary.vendors.filter((v) => !f.categories || f.categories.includes(v.vendor.category)),
      sort,
      dir,
      summary,
    )
  }, [summary, filter, sort, dir])
  const onSort = (k: SortKey) => {
    if (k === sort) setDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSort(k)
      setDir(k === 'name' ? 'asc' : 'desc')
    }
  }
  return (
    <Load value={value} what="the leaderboard">
      {({ summary: s, index }) => (
        <>
          <PageHeader
            eyebrow="Vendors"
            title="Evidence leaderboard"
            lede="Sort by the dimension you care about. There is no overall rank: each column stands on its own evidence, and a value that could not be measured always sorts last."
            actions={index.mode === 'DEMO' ? <DemoLabel /> : undefined}
          />
          <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
            <Segmented label="Category" size="sm" value={filter} onChange={setFilter} options={CATEGORY_FILTERS.map((c) => ({ value: c.id, label: c.label }))} />
            <label className="flex items-center gap-2 text-[0.8rem] text-ink-2">
              Sort by
              <select
                className="ts-select h-9"
                value={`${sort}:${dir}`}
                onChange={(e) => {
                  const [k, d] = e.target.value.split(':') as [SortKey, SortDir]
                  setSort(k)
                  setDir(d)
                }}
              >
                <option value="coverage:desc">Evidence coverage, high to low</option>
                <option value="quality:desc">CVE quality, high to low</option>
                <option value="vdp:desc">VDP, high to low</option>
                <option value="timeliness:desc">CVE timeliness, high to low</option>
                <option value="freshness:desc">Data freshness, most current first</option>
                <option value="name:asc">Name, A to Z</option>
              </select>
            </label>
          </div>
          {rows.length === 0 ? (
            <EmptyState title="No vendor in this category">Choose another category.</EmptyState>
          ) : (
            <div className="ts-panel overflow-hidden">
              <div className="ts-scroll-thin overflow-x-auto">
                <table className="ts-tbl min-w-[60rem]">
                  <caption className="sr-only">Evidence leaderboard, sorted by {sort}</caption>
                  <thead>
                    <tr>
                      <SortTh label="Vendor" k="name" sort={sort} dir={dir} onSort={onSort} />
                      <SortTh label="Evidence coverage" k="coverage" sort={sort} dir={dir} onSort={onSort} />
                      <SortTh label="CVE quality" k="quality" sort={sort} dir={dir} onSort={onSort} />
                      <SortTh label="VDP" k="vdp" sort={sort} dir={dir} onSort={onSort} />
                      <SortTh label="CVE timeliness" k="timeliness" sort={sort} dir={dir} onSort={onSort} />
                      <SortTh label="Data freshness" k="freshness" sort={sort} dir={dir} onSort={onSort} />
                      <th scope="col">
                        <span className="sr-only">Explanation</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((v) => (
                      <Row key={v.vendor.id} v={v} summary={s} open={open === v.vendor.id} onToggle={() => setOpen((o) => (o === v.vendor.id ? null : v.vendor.id))} />
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          <p className="mt-4 max-w-prose text-[0.8rem] leading-relaxed text-ink-3">
            Evidence coverage is the share of fourteen evidence slots public sources could answer. It describes how much can be observed, not how strong a vendor’s
            security is.
          </p>
        </>
      )}
    </Load>
  )
}

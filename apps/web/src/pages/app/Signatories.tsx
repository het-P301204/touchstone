import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { Search } from 'lucide-react'
import type { RunSummary, VendorCategory, VendorSummary } from '@touchstone/core/model'
import { useActiveSummary } from '../../data/hooks.ts'
import { PageHeader } from '../../ui/Panel.tsx'
import { DemoLabel, Disclosure, Kbd } from '../../ui/controls.tsx'
import { EmptyState, Load } from '../../ui/States.tsx'
import { Tag } from '../../ui/StatusBadge.tsx'
import { CATEGORY_LABEL } from '../../lib/vocab.ts'
import { CoverageCell, DimensionCell, FreshnessCell, dimensionValue } from '../../features/figures.tsx'
import { SortTh, sortVendors } from '../../features/vendorTable.tsx'
import type { SortDir, SortKey } from '../../features/vendorTable.tsx'
import { useUi } from '../../state/ui.ts'

const COVERAGE_BANDS = [
  { id: 'all', label: 'Any coverage', test: () => true },
  { id: 'high', label: '≥ 70% coverage', test: (p: number) => p >= 70 },
  { id: 'mid', label: '40–70% coverage', test: (p: number) => p >= 40 && p < 70 },
  { id: 'low', label: '< 40% coverage', test: (p: number) => p < 40 },
]

/** How many of the three measured dimensions have a value. */
function completeness(v: VendorSummary): number {
  return (['VDP', 'CVE_QUALITY', 'CVE_TIMELINESS'] as const).filter((d) => dimensionValue(v, d) !== null).length
}

const SIGNATORY_LABEL = { LISTED: 'Listed', NOT_LISTED: 'Not listed', UNKNOWN: 'Unknown' } as const

function Table({ summary, rows, sort, dir, onSort }: { summary: RunSummary; rows: VendorSummary[]; sort: SortKey; dir: SortDir; onSort: (k: SortKey) => void }) {
  const navigate = useNavigate()
  return (
    <div className="ts-panel hidden overflow-hidden md:block">
      <div className="ts-scroll-thin overflow-x-auto">
        <table className="ts-tbl min-w-[62rem]">
          <caption className="sr-only">Signatories in this run</caption>
          <thead>
            <tr>
              <SortTh label="Organization" k="name" sort={sort} dir={dir} onSort={onSort} />
              <th scope="col">Category</th>
              <SortTh label="Evidence coverage" k="coverage" sort={sort} dir={dir} onSort={onSort} />
              <SortTh label="CVE quality" k="quality" sort={sort} dir={dir} onSort={onSort} />
              <SortTh label="VDP" k="vdp" sort={sort} dir={dir} onSort={onSort} />
              <SortTh label="CVE timeliness" k="timeliness" sort={sort} dir={dir} onSort={onSort} />
              <SortTh label="Freshness" k="freshness" sort={sort} dir={dir} onSort={onSort} />
              <th scope="col">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((v) => (
              <tr key={v.vendor.id} className="ts-rowlink" onClick={() => navigate(`/app/vendors/${v.vendor.id}`)}>
                <td className="min-w-[12rem] max-w-[16rem]">
                  <Link to={`/app/vendors/${v.vendor.id}`} onClick={(e) => e.stopPropagation()} className="ts-ident font-semibold text-ink hover:underline">
                    {v.vendor.canonicalName}
                  </Link>
                </td>
                <td className="text-[0.8rem] text-ink-2">{CATEGORY_LABEL[v.vendor.category]}</td>
                <td>
                  <CoverageCell v={v} />
                </td>
                <td>
                  <DimensionCell v={v} dim="CVE_QUALITY" compact />
                </td>
                <td>
                  <DimensionCell v={v} dim="VDP" compact />
                </td>
                <td>
                  <DimensionCell v={v} dim="CVE_TIMELINESS" compact />
                </td>
                <td>
                  <FreshnessCell summary={summary} vendorId={v.vendor.id} />
                </td>
                <td className="text-[0.8rem] text-ink-2">{SIGNATORY_LABEL[v.vendor.signatoryStatus]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** Phones: each vendor is an expandable row. */
function Cards({ summary, rows }: { summary: RunSummary; rows: VendorSummary[] }) {
  return (
    <ul className="space-y-2 md:hidden">
      {rows.map((v) => (
        <li key={v.vendor.id} className="ts-card px-4 py-3">
          <Disclosure
            summary={
              <span className="flex min-w-0 items-center justify-between gap-3">
                <span className="min-w-0">
                  <span className="ts-ident block font-semibold text-ink">{v.vendor.canonicalName}</span>
                  <span className="block text-[0.75rem] text-ink-3">{CATEGORY_LABEL[v.vendor.category]}</span>
                </span>
                <CoverageCell v={v} />
              </span>
            }
          >
            <dl className="mt-3 grid grid-cols-[auto_minmax(0,1fr)] items-center gap-x-4 gap-y-2.5 border-t border-line pt-3 text-[0.8rem]">
              <dt className="ts-eyebrow">CVE quality</dt>
              <dd>
                <DimensionCell v={v} dim="CVE_QUALITY" compact />
              </dd>
              <dt className="ts-eyebrow">VDP</dt>
              <dd>
                <DimensionCell v={v} dim="VDP" compact />
              </dd>
              <dt className="ts-eyebrow">Timeliness</dt>
              <dd>
                <DimensionCell v={v} dim="CVE_TIMELINESS" compact />
              </dd>
              <dt className="ts-eyebrow">Freshness</dt>
              <dd>
                <FreshnessCell summary={summary} vendorId={v.vendor.id} />
              </dd>
              <dt className="ts-eyebrow">Status</dt>
              <dd className="text-ink-2">{SIGNATORY_LABEL[v.vendor.signatoryStatus]}</dd>
            </dl>
            <Link to={`/app/vendors/${v.vendor.id}`} className="ts-link mt-3 inline-block text-[0.84rem]">
              Open profile
            </Link>
          </Disclosure>
        </li>
      ))}
    </ul>
  )
}

export function Signatories() {
  const value = useActiveSummary()
  const setCommandOpen = useUi((s) => s.setCommandOpen)
  const [q, setQ] = useState('')
  const [category, setCategory] = useState<VendorCategory | 'all'>('all')
  const [coverage, setCoverage] = useState('all')
  const [complete, setComplete] = useState<'all' | '3' | '1-2' | '0'>('all')
  const [sort, setSort] = useState<SortKey>('name')
  const [dir, setDir] = useState<SortDir>('asc')
  const onSort = (k: SortKey) => {
    if (k === sort) setDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSort(k)
      setDir(k === 'name' ? 'asc' : 'desc')
    }
  }
  const summary = value.status === 'ready' ? value.data.summary : null
  const rows = useMemo(() => {
    if (!summary) return []
    const needle = q.trim().toLowerCase()
    const band = COVERAGE_BANDS.find((b) => b.id === coverage)!
    const filtered = summary.vendors.filter((v) => {
      if (category !== 'all' && v.vendor.category !== category) return false
      if (!band.test(v.coverage.percent)) return false
      const c = completeness(v)
      if (complete === '3' && c !== 3) return false
      if (complete === '1-2' && (c < 1 || c > 2)) return false
      if (complete === '0' && c !== 0) return false
      if (needle && !`${v.vendor.canonicalName} ${v.vendor.aliases.map((a) => a.value).join(' ')}`.toLowerCase().includes(needle)) return false
      return true
    })
    return sortVendors(filtered, sort, dir, summary)
  }, [summary, q, category, coverage, complete, sort, dir])

  return (
    <Load value={value} what="signatories">
      {({ summary: s, index }) => {
        const categories = [...new Set(s.vendors.map((v) => v.vendor.category))].sort()
        return (
          <>
            <PageHeader
              eyebrow="Directory"
              title="Signatories"
              lede={`${s.signatoryList.declaredCount ?? s.signatoryList.parsedCount} companies on the signer list; ${s.vendors.length} with a vendor registry entry analysed in this run.`}
              actions={index.mode === 'DEMO' ? <DemoLabel /> : undefined}
            />
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <label className="relative min-w-0 flex-1 basis-64">
                <span className="sr-only">Search organizations and aliases</span>
                <Search aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-ink-3" />
                <input className="ts-input pl-9" placeholder="Search organizations and aliases" value={q} onChange={(e) => setQ(e.target.value)} />
              </label>
              <select className="ts-select" aria-label="Category" value={category} onChange={(e) => setCategory(e.target.value as VendorCategory | 'all')}>
                <option value="all">All categories</option>
                {categories.map((c) => (
                  <option key={c} value={c}>
                    {CATEGORY_LABEL[c]}
                  </option>
                ))}
              </select>
              <select className="ts-select" aria-label="Evidence coverage" value={coverage} onChange={(e) => setCoverage(e.target.value)}>
                {COVERAGE_BANDS.map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.label}
                  </option>
                ))}
              </select>
              <select className="ts-select" aria-label="Measurement completeness" value={complete} onChange={(e) => setComplete(e.target.value as typeof complete)}>
                <option value="all">Any completeness</option>
                <option value="3">All 3 dimensions measured</option>
                <option value="1-2">1–2 dimensions measured</option>
                <option value="0">No dimension measured</option>
              </select>
              <button type="button" onClick={() => setCommandOpen(true)} className="hidden items-center gap-1.5 text-[0.78rem] text-ink-3 hover:text-ink lg:inline-flex">
                Command palette <Kbd>Ctrl</Kbd>
                <Kbd>K</Kbd>
              </button>
            </div>
            <p className="mb-3 text-[0.8rem] text-ink-3" aria-live="polite">
              {rows.length} of {s.vendors.length} shown · sorted by {sort === 'name' ? 'name' : sort} ({dir === 'asc' ? 'ascending' : 'descending'}); not measured always last
            </p>
            {rows.length === 0 ? (
              <EmptyState title="No organization matches these filters">Clear the search or widen a filter.</EmptyState>
            ) : (
              <>
                <Table summary={s} rows={rows} sort={sort} dir={dir} onSort={onSort} />
                <Cards summary={s} rows={rows} />
              </>
            )}
            <p className="mt-4 flex flex-wrap items-center gap-2 text-[0.78rem] text-ink-3">
              <Tag>Note</Tag> Signer-list names without a registry entry are counted but not measured: a vendor is only measured once its identity mappings are evidenced.
            </p>
          </>
        )
      }}
    </Load>
  )
}

import { useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { Search } from 'lucide-react'
import type { RunSummary, VendorDetail } from '@touchstone/core/model'
import { useActiveSummary, useAllDetails } from '../../data/hooks.ts'
import { PageHeader } from '../../ui/Panel.tsx'
import { Button } from '../../ui/Button.tsx'
import { DemoLabel, Disclosure } from '../../ui/controls.tsx'
import { EmptyState, Load } from '../../ui/States.tsx'
import { COMPLETENESS_LABEL, allCves, completenessOf, severityOf } from '../../lib/cve.ts'
import type { Completeness, CveRow } from '../../lib/cve.ts'
import { date } from '../../lib/format.ts'
import { vendorName } from '../../lib/vocab.ts'
import { cx } from '../../lib/cx.ts'

const PAGE = 50
const COMPLETE_TONE: Record<Completeness, string> = {
  COMPLETE: 'text-sage-ink',
  ENRICHED_ONLY: 'text-iris-ink',
  MISSING_CWE: 'text-ink-2',
  MISSING_CPE: 'text-ink-2',
  MISSING_BOTH: 'text-ink-2',
  PLACEHOLDER_CWE: 'text-marigold-ink',
  MALFORMED_CPE: 'text-vermilion-ink',
}

function cweText(r: CveRow) {
  const w = r.record.cna.cwes.find((x) => x.id && !x.placeholder) ?? r.record.cna.cwes[0]
  return w ? w.raw : null
}

function Explorer({ summary, details }: { summary: RunSummary; details: VendorDetail[] }) {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  const [page, setPage] = useState(0)
  const vendor = params.get('vendor') ?? 'all'
  const year = params.get('year') ?? 'all'
  const severity = params.get('severity') ?? 'all'
  const cwe = params.get('cwe') ?? 'all'
  const product = params.get('product') ?? 'all'
  const complete = params.get('complete') ?? 'all'
  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params)
    if (v === 'all') next.delete(k)
    else next.set(k, v)
    setParams(next, { replace: true })
    setPage(0)
  }
  const rows = useMemo(() => allCves(details), [details])
  const years = useMemo(() => [...new Set(rows.map((r) => r.record.datePublished?.slice(0, 4)).filter(Boolean) as string[])].sort().reverse(), [rows])
  const cwes = useMemo(() => [...new Set(rows.map(cweText).filter(Boolean) as string[])].sort((a, b) => a.localeCompare(b, 'en', { numeric: true })), [rows])
  const products = useMemo(() => [...new Set(rows.flatMap((r) => r.record.affected.map((a) => a.product)))].sort(), [rows])
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return rows
      .filter((r) => {
        const c = r.record
        if (vendor !== 'all' && r.vendorId !== vendor) return false
        if (year !== 'all' && !c.datePublished?.startsWith(year)) return false
        if (severity !== 'all' && severityOf(c).severity !== severity) return false
        if (cwe !== 'all' && cweText(r) !== cwe) return false
        if (product !== 'all' && !c.affected.some((a) => a.product === product)) return false
        if (complete !== 'all' && completenessOf(c) !== complete) return false
        if (needle && !`${c.id} ${c.title ?? ''} ${c.affected.map((a) => a.product).join(' ')}`.toLowerCase().includes(needle)) return false
        return true
      })
      .sort((a, b) => (b.record.datePublished ?? '').localeCompare(a.record.datePublished ?? '') || a.record.id.localeCompare(b.record.id))
  }, [rows, q, vendor, year, severity, cwe, product, complete])
  const shown = filtered.slice(page * PAGE, page * PAGE + PAGE)
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE))

  return (
    <>
      <div className="mb-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-7">
        <label className="relative min-w-0 sm:col-span-2 lg:col-span-1 2xl:col-span-1">
          <span className="sr-only">Search CVE id, title or product</span>
          <Search aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-ink-3" />
          <input className="ts-input pl-9" placeholder="CVE id, title, product" value={q} onChange={(e) => (setQ(e.target.value), setPage(0))} />
        </label>
        <select className="ts-select w-full" aria-label="Vendor" value={vendor} onChange={(e) => set('vendor', e.target.value)}>
          <option value="all">All vendors</option>
          {summary.vendors.map((v) => (
            <option key={v.vendor.id} value={v.vendor.id}>
              {v.vendor.canonicalName}
            </option>
          ))}
        </select>
        <select className="ts-select w-full" aria-label="Year" value={year} onChange={(e) => set('year', e.target.value)}>
          <option value="all">All years</option>
          {years.map((y) => (
            <option key={y}>{y}</option>
          ))}
        </select>
        <select className="ts-select w-full" aria-label="Severity" value={severity} onChange={(e) => set('severity', e.target.value)}>
          <option value="all">All severities</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'].map((s) => (
            <option key={s} value={s}>
              {s.toLowerCase()}
            </option>
          ))}
        </select>
        <select className="ts-select w-full" aria-label="CWE" value={cwe} onChange={(e) => set('cwe', e.target.value)}>
          <option value="all">All CWEs</option>
          {cwes.map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
        <select className="ts-select w-full" aria-label="Product" value={product} onChange={(e) => set('product', e.target.value)}>
          <option value="all">All products</option>
          {products.map((p) => (
            <option key={p}>{p}</option>
          ))}
        </select>
        <select className="ts-select w-full" aria-label="Completeness" value={complete} onChange={(e) => set('complete', e.target.value)}>
          <option value="all">Any completeness</option>
          {(Object.keys(COMPLETENESS_LABEL) as Completeness[]).map((c) => (
            <option key={c} value={c}>
              {COMPLETENESS_LABEL[c]}
            </option>
          ))}
        </select>
      </div>
      <p className="mb-3 text-[0.8rem] text-ink-3" aria-live="polite">
        {filtered.length} of {rows.length} attributed records · newest first
      </p>
      {filtered.length === 0 ? (
        <EmptyState title="No record matches these filters">Clear a filter to see more records.</EmptyState>
      ) : (
        <>
          <div className="ts-panel hidden overflow-hidden md:block">
            <div className="ts-scroll-thin overflow-x-auto">
              <table className="ts-tbl min-w-[72rem]">
                <caption className="sr-only">CVE records attributed to vendors in this run</caption>
                <thead>
                  <tr>
                    <th scope="col">CVE</th>
                    <th scope="col">Vendor</th>
                    <th scope="col">Product</th>
                    <th scope="col">Published</th>
                    <th scope="col">Updated</th>
                    <th scope="col">Severity</th>
                    <th scope="col">CWE</th>
                    <th scope="col">CPE</th>
                    <th scope="col">Completeness</th>
                    <th scope="col">Source</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((r) => {
                    const c = r.record
                    const sev = severityOf(c)
                    const comp = completenessOf(c)
                    const w = cweText(r)
                    return (
                      <tr key={`${r.vendorId}-${c.id}-${c.sourceHash}`} className="ts-rowlink" onClick={() => navigate(`/app/cves/${encodeURIComponent(c.id)}`)}>
                        <td>
                          <Link to={`/app/cves/${encodeURIComponent(c.id)}`} onClick={(e) => e.stopPropagation()} className="whitespace-nowrap font-mono text-[0.8rem] font-semibold text-ink hover:underline">
                            {c.id}
                          </Link>
                        </td>
                        <td className="ts-ident max-w-[11rem] text-[0.8rem] text-ink-2">{vendorName(summary, r.vendorId)}</td>
                        <td className="ts-ident max-w-[11rem] text-[0.8rem] text-ink-2">{c.affected.map((a) => a.product).join(', ') || '—'}</td>
                        <td className="ts-num whitespace-nowrap text-[0.78rem] text-ink-2">{date(c.datePublished)}</td>
                        <td className="ts-num whitespace-nowrap text-[0.78rem] text-ink-2">{date(c.dateUpdated)}</td>
                        <td className="text-[0.78rem] lowercase text-ink-2">
                          {sev.severity}
                          {sev.from === 'ADP' && <span className="ml-1 text-[0.7rem] text-iris-ink">(ADP)</span>}
                        </td>
                        <td className="font-mono text-[0.76rem]">{w ? w : <span className="text-ink-3">—</span>}</td>
                        <td className="whitespace-nowrap text-[0.78rem] text-ink-2">{c.cna.cpes.length === 0 ? '—' : c.cna.cpes.some((p) => p.wellFormed) ? `${c.cna.cpes.length} well-formed` : 'malformed'}</td>
                        <td className={cx('text-[0.78rem] font-semibold', COMPLETE_TONE[comp])}>{COMPLETENESS_LABEL[comp]}</td>
                        <td className="ts-ident font-mono text-[0.74rem] text-ink-3">{c.assigner.shortName}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
          <ul className="space-y-2 md:hidden">
            {shown.map((r) => {
              const c = r.record
              const comp = completenessOf(c)
              return (
                <li key={`${r.vendorId}-${c.id}-${c.sourceHash}`} className="ts-card px-4 py-3">
                  <Disclosure
                    summary={
                      <span className="block min-w-0">
                        <span className="ts-ident block font-mono text-[0.84rem] font-semibold text-ink">{c.id}</span>
                        <span className="ts-ident block text-[0.76rem] text-ink-3">
                          {vendorName(summary, r.vendorId)} · {date(c.datePublished)}
                        </span>
                        <span className={cx('block text-[0.76rem] font-semibold', COMPLETE_TONE[comp])}>{COMPLETENESS_LABEL[comp]}</span>
                      </span>
                    }
                  >
                    <dl className="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5 border-t border-line pt-3 text-[0.8rem]">
                      <dt className="ts-eyebrow">Product</dt>
                      <dd className="ts-ident">{c.affected.map((a) => a.product).join(', ') || '—'}</dd>
                      <dt className="ts-eyebrow">Severity</dt>
                      <dd className="lowercase">{severityOf(c).severity}</dd>
                      <dt className="ts-eyebrow">CWE</dt>
                      <dd className="font-mono">{cweText(r) ?? '—'}</dd>
                      <dt className="ts-eyebrow">Source</dt>
                      <dd className="ts-ident font-mono">{c.assigner.shortName}</dd>
                    </dl>
                    <Link to={`/app/cves/${encodeURIComponent(c.id)}`} className="ts-link mt-3 inline-block text-[0.84rem]">
                      Open record
                    </Link>
                  </Disclosure>
                </li>
              )
            })}
          </ul>
          <div className="mt-4 flex items-center justify-between gap-3 text-[0.82rem] text-ink-2">
            <span>
              Page {page + 1} of {pages}
            </span>
            <div className="flex gap-2">
              <Button size="sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                Previous
              </Button>
              <Button size="sm" disabled={page >= pages - 1} onClick={() => setPage((p) => p + 1)}>
                Next
              </Button>
            </div>
          </div>
        </>
      )}
      <p className="mt-4 max-w-prose text-[0.78rem] leading-relaxed text-ink-3">
        Completeness here classifies each record’s CNA container. The published metric also applies the eligibility window and checks the CPE vendor namespace; open a vendor’s
        figure to see exactly which records counted.
      </p>
    </>
  )
}

export function CveExplorer() {
  const active = useActiveSummary()
  const runId = active.status === 'ready' ? active.data.runId : null
  const ids = active.status === 'ready' ? active.data.summary.vendors.map((v) => v.vendor.id) : null
  const details = useAllDetails(runId, ids)
  return (
    <Load value={active} what="the run">
      {({ summary, index }) => (
        <>
          <PageHeader
            eyebrow="CVE explorer"
            title="CVE records"
            lede="Every record attributed to a vendor in this run, with what the manufacturer’s CNA container supplied and what third parties added."
            actions={index.mode === 'DEMO' ? <DemoLabel /> : undefined}
          />
          <Load value={details} what="CVE records">
            {(d) => <Explorer summary={summary} details={d} />}
          </Load>
        </>
      )}
    </Load>
  )
}

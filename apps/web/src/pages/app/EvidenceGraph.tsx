/**
 * Evidence graph for one vendor: vendor → product → CVE → CWE / CPE,
 * vendor → VDP → policy, vendor → advisory. A quiet SVG; select a node to
 * inspect it.
 */
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import type { RunSummary, VendorDetail, VendorSummary } from '@touchstone/core/model'
import { useActiveSummary, useVendorDetail } from '../../data/hooks.ts'
import { PageHeader, Panel } from '../../ui/Panel.tsx'
import { DemoLabel, ExtLink, KV } from '../../ui/controls.tsx'
import { Load } from '../../ui/States.tsx'
import { cx } from '../../lib/cx.ts'
import { date } from '../../lib/format.ts'
import { COMPLETENESS_LABEL, completenessOf } from '../../lib/cve.ts'

type Kind = 'vendor' | 'product' | 'cve' | 'cwe' | 'cpe' | 'vdp' | 'policy' | 'advisory'
type GNode = { id: string; kind: Kind; label: string; col: number; data?: unknown }
type GEdge = { from: string; to: string; muted?: boolean }

const COLS = ['Vendor', 'Products · VDP · advisories', 'CVE records · policy', 'CWE / CPE (CNA)']
const MAX_CVES = 18

function build(v: VendorSummary, d: VendorDetail): { nodes: GNode[]; edges: GEdge[] } {
  const nodes: GNode[] = [{ id: 'vendor', kind: 'vendor', label: v.vendor.canonicalName, col: 0 }]
  const edges: GEdge[] = []
  const cves = [...d.cves].sort((a, b) => (b.datePublished ?? '').localeCompare(a.datePublished ?? '')).slice(0, MAX_CVES)
  const products = [...new Set(cves.flatMap((c) => c.affected.map((a) => a.product)))].slice(0, 8)
  for (const p of products) {
    nodes.push({ id: `p:${p}`, kind: 'product', label: p, col: 1 })
    edges.push({ from: 'vendor', to: `p:${p}` })
  }
  if (v.vdp) {
    nodes.push({ id: 'vdp', kind: 'vdp', label: 'VDP', col: 1, data: v.vdp })
    edges.push({ from: 'vendor', to: 'vdp' })
    if (v.vdp.policy.found) {
      nodes.push({ id: 'policy', kind: 'policy', label: v.vdp.policy.host ?? 'policy', col: 2, data: v.vdp })
      edges.push({ from: 'vdp', to: 'policy' })
    }
  }
  const adv = d.advisories.slice(0, 4)
  for (const a of adv) {
    nodes.push({ id: `a:${a.id}`, kind: 'advisory', label: a.id, col: 1, data: a })
    edges.push({ from: 'vendor', to: `a:${a.id}` })
  }
  const weak = new Map<string, number>()
  const cpeVendors = new Map<string, number>()
  for (const c of cves) {
    const id = `c:${c.id}`
    nodes.push({ id, kind: 'cve', label: c.id, col: 2, data: c })
    const prod = c.affected.map((a) => a.product).find((p) => products.includes(p))
    edges.push({ from: prod ? `p:${prod}` : 'vendor', to: id })
    for (const a of adv) if (a.cveIds.includes(c.id)) edges.push({ from: `a:${a.id}`, to: id, muted: true })
    for (const w of c.cna.cwes) {
      const key = w.raw
      weak.set(key, (weak.get(key) ?? 0) + 1)
      edges.push({ from: id, to: `w:${key}`, muted: w.placeholder })
    }
    for (const p of c.cna.cpes) {
      const key = p.wellFormed ? `cpe:${p.vendor}` : 'cpe:malformed'
      cpeVendors.set(key, (cpeVendors.get(key) ?? 0) + 1)
      edges.push({ from: id, to: key, muted: !p.wellFormed })
    }
  }
  for (const [k, n] of [...weak].sort((a, b) => b[1] - a[1]).slice(0, 10)) nodes.push({ id: `w:${k}`, kind: 'cwe', label: `${k} ×${n}`, col: 3 })
  for (const [k, n] of cpeVendors) nodes.push({ id: k, kind: 'cpe', label: `${k === 'cpe:malformed' ? 'malformed CPE' : `cpe vendor ${k.slice(4)}`} ×${n}`, col: 3 })
  const ids = new Set(nodes.map((n) => n.id))
  return { nodes, edges: edges.filter((e) => ids.has(e.from) && ids.has(e.to)) }
}

const KIND_STYLE: Record<Kind, string> = {
  vendor: 'fill-ink',
  product: 'fill-ink-2',
  cve: 'fill-ink-3',
  cwe: 'fill-sage',
  cpe: 'fill-iris',
  vdp: 'fill-marigold',
  policy: 'fill-marigold',
  advisory: 'fill-plum',
}

function Graph({ summary, v, d }: { summary: RunSummary; v: VendorSummary; d: VendorDetail }) {
  const { nodes, edges } = useMemo(() => build(v, d), [v, d])
  const [sel, setSel] = useState<string>('vendor')
  const W = 1100
  const rowH = 30
  const perCol = COLS.map((_, c) => nodes.filter((n) => n.col === c))
  const H = Math.max(...perCol.map((c) => c.length)) * rowH + 60
  // Last column leaves room for its labels.
  const colX = (c: number) => 24 + c * ((W - 24 - 230) / (COLS.length - 1))
  const pos = new Map<string, { x: number; y: number }>()
  perCol.forEach((list, c) => {
    const x = colX(c)
    const offset = (H - 40 - list.length * rowH) / 2
    list.forEach((n, i) => pos.set(n.id, { x, y: 40 + offset + i * rowH + rowH / 2 }))
  })
  const related = new Set(edges.filter((e) => e.from === sel || e.to === sel).flatMap((e) => [e.from, e.to]))
  const node = nodes.find((n) => n.id === sel)
  return (
    <div className="grid gap-6 2xl:grid-cols-[minmax(0,1fr)_22rem]">
      <div className="ts-panel min-w-0 overflow-hidden p-4">
        <div className="ts-scroll-thin overflow-x-auto">
          <svg viewBox={`0 0 ${W} ${H}`} className="min-w-[56rem]" role="group" aria-label={`Evidence graph for ${v.vendor.canonicalName}`}>
            {COLS.map((c, i) => (
              <text key={c} x={colX(i)} y={18} className="fill-ink-3 font-mono text-[10px] uppercase tracking-[0.1em]">
                {c}
              </text>
            ))}
            {edges.map((e, i) => {
              const a = pos.get(e.from)!
              const b = pos.get(e.to)!
              const on = sel === e.from || sel === e.to
              const mx = (a.x + b.x) / 2
              return (
                <path
                  key={i}
                  d={`M${a.x + 6},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x - 6},${b.y}`}
                  fill="none"
                  stroke={on ? 'rgb(var(--ink))' : 'rgb(var(--line-strong))'}
                  strokeWidth={on ? 1.4 : 0.9}
                  strokeDasharray={e.muted ? '3 3' : undefined}
                  opacity={on ? 0.9 : 0.55}
                />
              )
            })}
            {nodes.map((n) => {
              const p = pos.get(n.id)!
              const dim = sel !== 'vendor' && !related.has(n.id)
              return (
                <g
                  key={n.id}
                  role="button"
                  tabIndex={0}
                  aria-label={`${n.kind} ${n.label}`}
                  aria-pressed={sel === n.id}
                  onClick={() => setSel(n.id)}
                  onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), setSel(n.id))}
                  className={cx('cursor-pointer outline-none [&:focus-visible>circle]:stroke-ink [&:focus-visible>circle]:stroke-2', dim && 'opacity-40')}
                >
                  <circle cx={p.x} cy={p.y} r={sel === n.id ? 7 : 5.5} className={KIND_STYLE[n.kind]} stroke="rgb(var(--surface))" strokeWidth={2} />
                  <text
                    x={n.col === 0 ? p.x - 4 : p.x + 12}
                    y={n.col === 0 ? p.y - 14 : p.y + 4}
                    className={cx('font-mono text-[11px]', sel === n.id ? 'fill-ink font-semibold' : 'fill-ink-2')}
                    paintOrder="stroke"
                    stroke="rgb(var(--surface))"
                    strokeWidth={4}
                    strokeLinejoin="round"
                  >
                    {n.label.length > 30 ? `${n.label.slice(0, 29)}…` : n.label}
                  </text>
                </g>
              )
            })}
          </svg>
        </div>
        <p className="mt-2 text-[0.75rem] text-ink-3">
          Showing the {Math.min(MAX_CVES, d.cves.length)} most recent of {d.cves.length} records. Dashed edges: placeholder CWE, malformed CPE, or an advisory reference.
        </p>
      </div>
      <Panel title="Inspector" eyebrow={node?.kind ?? ''} className="min-w-0 self-start">
        {node && <Inspector node={node} v={v} summary={summary} />}
      </Panel>
    </div>
  )
}

function Inspector({ node, v, summary }: { node: GNode; v: VendorSummary; summary: RunSummary }) {
  if (node.kind === 'cve') {
    const c = node.data as VendorDetail['cves'][number]
    return (
      <div className="space-y-3">
        <KV
          rows={[
            ['Record', <Link to={`/app/cves/${encodeURIComponent(c.id)}`} className="ts-link font-mono text-[0.8rem]">{c.id}</Link>],
            ['Published', date(c.datePublished)],
            ['CNA CWE', c.cna.cwes.map((w) => w.raw).join(', ') || 'not provided'],
            ['CNA CPE', c.cna.cpes.length ? `${c.cna.cpes.length} (${c.cna.cpes.filter((p) => p.wellFormed).length} well-formed)` : 'not provided'],
            ['ADP adds', c.adp.map((a) => a.provider).join(', ') || '—'],
            ['Completeness', COMPLETENESS_LABEL[completenessOf(c)]],
          ]}
        />
      </div>
    )
  }
  if (node.kind === 'vdp' || node.kind === 'policy') {
    const vdp = v.vdp!
    return (
      <KV
        rows={[
          ['Policy', vdp.policy.url ? <ExtLink href={vdp.policy.url} /> : 'not found'],
          ['Criteria met', `${vdp.criteria.filter((c) => c.state === 'MET').length} of ${vdp.criteria.length}`],
          ['Observed', date(vdp.observedAt)],
          ['Profile', <Link to={`/app/vendors/${v.vendor.id}#vdp`} className="ts-link">VDP explorer</Link>],
        ]}
      />
    )
  }
  if (node.kind === 'advisory') {
    const a = node.data as VendorDetail['advisories'][number]
    return (
      <KV
        rows={[
          ['Advisory', <span className="font-mono text-[0.8rem]">{a.id}</span>],
          ['Title', a.title],
          ['Severity', a.severity.toLowerCase()],
          ['Released', date(a.publishedAt)],
          ['CVEs', a.cveIds.join(', ') || 'none listed'],
        ]}
      />
    )
  }
  if (node.kind === 'vendor') {
    return (
      <KV
        rows={[
          ['Vendor', <Link to={`/app/vendors/${v.vendor.id}`} className="ts-link">{v.vendor.canonicalName}</Link>],
          ['CVE records', String(v.cveCount)],
          ['Advisories', String(v.advisoryCount)],
          ['Run', <span className="font-mono text-[0.8rem]">{summary.manifest.runId}</span>],
        ]}
      />
    )
  }
  return <p className="ts-ident font-mono text-[0.84rem] text-ink">{node.label}</p>
}

export function EvidenceGraphPage() {
  const active = useActiveSummary()
  const [vendorId, setVendorId] = useState<string | null>(null)
  const runId = active.status === 'ready' ? active.data.runId : null
  const vid = vendorId ?? (active.status === 'ready' ? (active.data.summary.vendors[0]?.vendor.id ?? null) : null)
  const detail = useVendorDetail(vid, runId)
  return (
    <Load value={active} what="the run">
      {({ summary, index }) => (
        <>
          <PageHeader
            eyebrow="Evidence graph"
            title="How the evidence connects"
            lede="From a vendor to its products, CVE records and the weakness and platform identifiers its own CNA supplied; and to its disclosure policy and advisories."
            actions={
              <>
                {index.mode === 'DEMO' && <DemoLabel />}
                <select className="ts-select" aria-label="Vendor" value={vid ?? ''} onChange={(e) => setVendorId(e.target.value)}>
                  {summary.vendors.map((x) => (
                    <option key={x.vendor.id} value={x.vendor.id}>
                      {x.vendor.canonicalName}
                    </option>
                  ))}
                </select>
              </>
            }
          />
          <Load value={detail} what="the vendor’s evidence">
            {(d) => {
              const v = summary.vendors.find((x) => x.vendor.id === d.vendorId)
              return v ? <Graph key={d.vendorId} summary={summary} v={v} d={d} /> : null
            }}
          </Load>
        </>
      )}
    </Load>
  )
}

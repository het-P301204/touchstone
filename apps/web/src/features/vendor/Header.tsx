import { useState } from 'react'
import { Link } from 'react-router'
import { ChevronDown, Download, FileDown, Link2, Ruler } from 'lucide-react'
import type { RunSummary, VendorDetail, VendorSummary } from '@touchstone/core/model'
import { Button } from '../../ui/Button.tsx'
import { DemoLabel } from '../../ui/controls.tsx'
import { Tag } from '../../ui/StatusBadge.tsx'
import { CATEGORY_LABEL } from '../../lib/vocab.ts'
import { date } from '../../lib/format.ts'
import { cx } from '../../lib/cx.ts'
import { copyLink, downloadEvidence, exportReport } from '../exports.ts'
import type { ReportFormat } from '../../data/source.ts'
import { usePaths } from '../../lib/paths.ts'

const FORMATS: { id: ReportFormat; label: string }[] = [
  { id: 'pdf', label: 'PDF' },
  { id: 'markdown', label: 'Markdown' },
  { id: 'csv', label: 'CSV' },
  { id: 'json', label: 'JSON' },
]

function ExportMenu({ summary, detail }: { summary: RunSummary; detail: VendorDetail | null }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState<ReportFormat | null>(null)
  const [error, setError] = useState<string | null>(null)
  return (
    <div className="relative" id="export">
      <Button variant="primary" icon={<FileDown />} trailing={<ChevronDown />} aria-expanded={open} aria-haspopup="menu" onClick={() => setOpen((o) => !o)} disabled={!detail}>
        Export Report
      </Button>
      {open && detail && (
        <div role="menu" aria-label="Report format" className="absolute right-0 z-30 mt-2 w-48 rounded-card border border-line bg-surface-raised p-1.5 shadow-lift">
          {FORMATS.map((f) => (
            <button
              key={f.id}
              role="menuitem"
              type="button"
              disabled={busy !== null}
              onClick={async () => {
                setBusy(f.id)
                setError(null)
                try {
                  await exportReport(summary, detail, f.id)
                  setOpen(false)
                } catch (e) {
                  setError(e instanceof Error ? e.message : String(e))
                } finally {
                  setBusy(null)
                }
              }}
              className="flex w-full items-center justify-between rounded-[10px] px-3 py-2 text-left text-sm font-semibold text-ink hover:bg-paper-2 disabled:opacity-60"
            >
              {f.label}
              {busy === f.id && <span className="ts-pulse font-mono text-[0.7rem] text-ink-3">rendering</span>}
            </button>
          ))}
          {error && <p className="px-3 py-2 text-[0.75rem] text-vermilion-ink">{error}</p>}
        </div>
      )}
    </div>
  )
}

export function VendorHeader({ summary, v, detail, isDemo }: { summary: RunSummary; v: VendorSummary; detail: VendorDetail | null; isDemo: boolean }) {
  const paths = usePaths()
  const [copied, setCopied] = useState<string | null>(null)
  const m = summary.manifest
  const cohortSize = summary.cohort.find((c) => c.peerGroup === 'ALL_SIGNATORIES')?.vendorCount ?? summary.vendors.length
  const listed = v.vendor.signatoryStatus
  const share = async (what: string, path: string) => {
    const ok = await copyLink(path)
    setCopied(ok ? what : null)
    if (ok) window.setTimeout(() => setCopied(null), 1800)
  }
  return (
    <header className="mb-8">
      <nav aria-label="Breadcrumb" className="mb-4 text-[0.8rem] text-ink-3">
        <Link to={paths.inApp ? '/app/vendors' : '/app/vendors'} className="hover:text-ink">
          Vendors
        </Link>
        <span aria-hidden="true"> / </span>
        <span className="ts-ident text-ink-2">{v.vendor.canonicalName}</span>
      </nav>
      <div className="flex flex-wrap items-start justify-between gap-x-8 gap-y-5">
        <div className="min-w-0 max-w-3xl flex-1">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            {(isDemo || v.vendor.synthetic) && <DemoLabel long />}
            <Tag>{CATEGORY_LABEL[v.vendor.category]}</Tag>
          </div>
          <h1 className="ts-ident text-title-1 text-ink">{v.vendor.canonicalName}</h1>
          <p className="mt-3 text-[0.95rem] text-ink-2">
            Secure by Design Commitment ·{' '}
            {listed === 'LISTED' ? (
              <span className="font-semibold text-ink">Listed signatory{v.vendor.signedOn ? ` since ${date(v.vendor.signedOn)}` : ''}</span>
            ) : listed === 'NOT_LISTED' ? (
              <span className="font-semibold text-ink">Not on the latest signer list</span>
            ) : (
              <span className="font-semibold text-ink">Signatory status unknown (no successful signer-list snapshot)</span>
            )}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="md" variant="ghost" icon={<Ruler />} onClick={() => share('methodology', '/methodology')}>
            {copied === 'methodology' ? 'Link copied' : 'Share Methodology'}
          </Button>
          <Button size="md" variant="ghost" icon={<Link2 />} onClick={() => share('finding', `/vendors/${v.vendor.id}`)}>
            {copied === 'finding' ? 'Link copied' : 'Share Finding'}
          </Button>
          <Button size="md" icon={<Download />} disabled={!detail} onClick={() => detail && downloadEvidence(summary, detail)}>
            Download Evidence
          </Button>
          <ExportMenu summary={summary} detail={detail} />
        </div>
      </div>
      <dl className="mt-6 grid grid-cols-2 gap-x-6 gap-y-3 border-y border-line py-4 text-[0.82rem] sm:grid-cols-4">
        {(
          [
            ['Cohort size', `${cohortSize} vendors`],
            ['Last analyzed', date(m.asOf)],
            ['Methodology', m.methodologyVersion],
            ['Run', m.runId],
          ] as const
        ).map(([k, val]) => (
          <div key={k} className="min-w-0">
            <dt className="ts-eyebrow">{k}</dt>
            <dd className={cx('ts-ident mt-1 text-ink', k !== 'Last analyzed' && k !== 'Cohort size' && 'font-mono text-[0.8rem]')}>{val}</dd>
          </div>
        ))}
      </dl>
    </header>
  )
}

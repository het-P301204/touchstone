/**
 * Methodology demo: trace one vendor's CNA CWE coverage from the dataset to
 * the published figure, step by step, using the published run's own data.
 */
import { useEffect, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { Pause, Play, SkipForward } from 'lucide-react'
import type { RunSummary, VendorDetail } from '@touchstone/core/model'
import { useActiveSummary, useVendorDetail } from '../data/hooks.ts'
import { Button } from '../ui/Button.tsx'
import { Load } from '../ui/States.tsx'
import { cx } from '../lib/cx.ts'
import { date, minusDays, num, shortHash } from '../lib/format.ts'
import { breakdownLabel } from '../lib/vocab.ts'

type Step = { title: string; body: string; mono?: string }

function steps(summary: RunSummary, detail: VendorDetail, vendorName: string): Step[] {
  const m = summary.manifest
  const p = summary.methodology.parameters
  const goal = detail.goals.find((g) => g.metrics.some((x) => x.metricId === 'cve.cwe_coverage'))
  const metric = goal?.metrics.find((x) => x.metricId === 'cve.cwe_coverage')
  const evidence = detail.evidence.filter((e) => e.metricId === 'cve.cwe_coverage')
  const supports = evidence.filter((e) => e.interpretation === 'SUPPORTS').length
  const against = evidence.filter((e) => e.interpretation === 'DOES_NOT_SUPPORT').length
  const excluded = evidence.filter((e) => e.interpretation === 'EXCLUDED').length
  const gaps = Object.entries(metric?.breakdown ?? {})
    .filter(([k, v]) => k.startsWith('gap.') && v > 0)
    .map(([k, v]) => `${breakdownLabel(k)}: ${v}`)
  return [
    {
      title: 'Load the dataset',
      body: `Run ${m.runId} reads dataset ${m.datasetVersion}: ${num(m.snapshotIds.length)} snapshots, each stored with its sha256. Methodology ${m.methodologyVersion} fixes every parameter.`,
      mono: `inputsHash ${shortHash(m.inputsHash, 24)}`,
    },
    {
      title: 'Filter to the vendor’s records',
      body: `${num(detail.attributions.length)} CVE records are attributed to ${vendorName} by an explicit rule (assigner is the vendor’s CNA, or affected vendor plus a CPE in its namespace). Free text is never used.`,
      mono: detail.attributions.slice(0, 3).map((a) => `${a.cveId} · ${a.rule}`).join('\n'),
    },
    {
      title: 'Apply eligibility and exclusions',
      body: `Only PUBLISHED records with datePublished between ${date(minusDays(m.asOf, p.cveWindowDays))} and ${date(m.asOf)} count. ${num(detail.exclusions.length)} candidate records were excluded (ambiguous vendor, identity conflict, rejected or duplicate).`,
      mono: `eligible records: ${metric?.denominator ?? '—'} · minimum sample ${p.minimumEligibleRecords}`,
    },
    {
      title: 'Evaluate the CNA CWE field',
      body: `For each eligible record, read containers.cna.problemTypes. Third-party ADP containers are ignored. Placeholders (NVD-CWE-noinfo, NVD-CWE-Other) ${p.placeholderCweCountsAsPopulated ? 'count' : 'do not count'} under methodology ${m.methodologyVersion}.`,
      mono: gaps.length ? gaps.join(' · ') : 'no gaps recorded',
    },
    {
      title: 'Compute the ratio',
      body: 'Records with a usable CNA CWE divided by eligible records. A value is never invented: below the minimum sample the metric is reported as not measured.',
      mono: metric?.calculation || 'not measured',
    },
    {
      title: 'Store the evidence',
      body: `${num(evidence.length)} evidence items record what was read from each record: ${supports} support the figure, ${against} count against it, ${excluded} were examined and excluded.`,
      mono: evidence.slice(0, 3).map((e) => `${e.id} · ${e.subject} · ${e.interpretation}`).join('\n'),
    },
    {
      title: 'Publish',
      body: 'The run hashes its outputs. Re-running the same snapshots under the same methodology gives the same hash, which is what “reproducible” means here.',
      mono: `outputsHash ${shortHash(m.outputsHash, 24)}`,
    },
  ]
}

function Trace({ summary, detail, vendorName }: { summary: RunSummary; detail: VendorDetail; vendorName: string }) {
  const reduce = useReducedMotion()
  const list = steps(summary, detail, vendorName)
  const [at, setAt] = useState(reduce ? list.length - 1 : 0)
  const [playing, setPlaying] = useState(false)
  useEffect(() => {
    if (!playing) return
    if (at >= list.length - 1) {
      setPlaying(false)
      return
    }
    const t = window.setTimeout(() => setAt((a) => a + 1), 1300)
    return () => window.clearTimeout(t)
  }, [playing, at, list.length])
  return (
    <div>
      <div className="mb-4 flex flex-wrap gap-2">
        <Button
          size="sm"
          variant="primary"
          icon={playing ? <Pause /> : <Play />}
          onClick={() => {
            if (!playing && at >= list.length - 1) setAt(0)
            setPlaying((pl) => !pl)
          }}
        >
          {playing ? 'Pause' : at >= list.length - 1 ? 'Replay' : 'Play'}
        </Button>
        <Button size="sm" icon={<SkipForward />} disabled={at >= list.length - 1} onClick={() => setAt((a) => Math.min(a + 1, list.length - 1))}>
          Next step
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setAt(list.length - 1)}>
          Show all steps
        </Button>
      </div>
      <ol className="relative space-y-3 border-l border-line pl-6" aria-live="polite">
        {list.map((s, i) => (
          <li key={s.title} className="relative">
            <span
              aria-hidden="true"
              className={cx('absolute -left-[1.94rem] top-1 flex size-5 items-center justify-center rounded-full font-mono text-[0.62rem] ring-4 ring-surface', i <= at ? 'bg-ink text-paper' : 'bg-paper-3 text-ink-3')}
            >
              {i + 1}
            </span>
            <p className={cx('font-semibold', i <= at ? 'text-ink' : 'text-ink-3')}>{s.title}</p>
            <AnimatePresence initial={false}>
              {i <= at && (
                <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }} className="overflow-hidden">
                  <p className="mt-1 max-w-prose text-[0.86rem] leading-relaxed text-ink-2">{s.body}</p>
                  {s.mono && <pre className="ts-ident mt-2 whitespace-pre-wrap rounded-[12px] bg-paper-2/80 px-3 py-2 font-mono text-[0.74rem] leading-relaxed text-ink">{s.mono}</pre>}
                </motion.div>
              )}
            </AnimatePresence>
          </li>
        ))}
      </ol>
    </div>
  )
}

export function MethodTrace() {
  const active = useActiveSummary()
  const [vendorId, setVendorId] = useState<string | null>(null)
  const runId = active.status === 'ready' ? active.data.runId : null
  const vendors = active.status === 'ready' ? active.data.summary.vendors : []
  const chosen = vendorId ?? vendors.find((v) => v.vendor.id === 'northwind-systems')?.vendor.id ?? vendors[0]?.vendor.id ?? null
  const detail = useVendorDetail(chosen, runId)
  return (
    <Load value={active} what="the published run">
      {({ summary }) => (
        <div>
          <label className="mb-5 flex flex-wrap items-center gap-2 text-[0.84rem] text-ink-2">
            Trace CNA CWE coverage for
            <select className="ts-select h-9" value={chosen ?? ''} onChange={(e) => setVendorId(e.target.value)}>
              {summary.vendors.map((v) => (
                <option key={v.vendor.id} value={v.vendor.id}>
                  {v.vendor.canonicalName}
                </option>
              ))}
            </select>
          </label>
          <Load value={detail} what="the vendor’s evidence">
            {(d) => <Trace key={d.vendorId} summary={summary} detail={d} vendorName={summary.vendors.find((v) => v.vendor.id === d.vendorId)?.vendor.canonicalName ?? d.vendorId} />}
          </Load>
        </div>
      )}
    </Load>
  )
}

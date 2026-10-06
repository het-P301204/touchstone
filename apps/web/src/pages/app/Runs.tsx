/**
 * Runs: the history of published runs. Open a historical run to view its
 * stored figures, or reproduce any run in this browser from its own inputs.
 */
import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router'
import { CircleCheck, CircleX, FlaskConical, FolderOpen, Loader } from 'lucide-react'
import type { RunIndexEntry, RunSummary } from '@touchstone/core/model'
import { useRunIndex, useSummary } from '../../data/hooks.ts'
import { useUi } from '../../state/ui.ts'
import { PageHeader, Panel } from '../../ui/Panel.tsx'
import { Button } from '../../ui/Button.tsx'
import { CopyText, DemoLabel, KV } from '../../ui/controls.tsx'
import { Load } from '../../ui/States.tsx'
import { date, num } from '../../lib/format.ts'
import { cx } from '../../lib/cx.ts'
import { reproduceInBrowser } from '../../features/reproduce.ts'
import type { ReproducePhase, ReproduceResult } from '../../features/reproduce.ts'

const PHASE_LABEL: Record<ReproducePhase, string> = {
  fetching: 'Fetching the run’s inputs',
  'loading-engine': 'Loading the engine',
  running: 'Executing the run',
}

function Reproduce({ entry, summary, autoStart }: { entry: RunIndexEntry; summary: RunSummary; autoStart: boolean }) {
  const [phase, setPhase] = useState<ReproducePhase | null>(null)
  const [result, setResult] = useState<ReproduceResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const started = useRef(false)
  const run = async () => {
    setResult(null)
    setError(null)
    try {
      const r = await reproduceInBrowser(entry, summary.manifest, setPhase)
      setResult(r)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setPhase(null)
    }
  }
  useEffect(() => {
    if (autoStart && !started.current) {
      started.current = true
      void run()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart])
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" icon={phase ? <Loader className="motion-safe:animate-spin" /> : <FlaskConical />} disabled={!!phase} onClick={() => void run()}>
          {phase ? PHASE_LABEL[phase] : result ? 'Reproduce again' : 'Reproduce this run'}
        </Button>
        <p className="text-[0.8rem] text-ink-3">Downloads the run’s inputs (about a megabyte), executes methodology {entry.methodologyVersion} here, and compares hashes.</p>
      </div>
      {error && (
        <p role="alert" className="rounded-[12px] border border-vermilion/40 bg-vermilion/10 px-4 py-3 text-[0.86rem] text-vermilion-ink">
          Could not reproduce: {error}
        </p>
      )}
      {result && (
        <div role="status" className={cx('rounded-card border p-5', result.reproduced ? 'border-sage/50 bg-sage/10' : 'border-vermilion/40 bg-vermilion/10')}>
          <p className={cx('flex items-center gap-2 text-title-3', result.reproduced ? 'text-sage-ink' : 'text-vermilion-ink')}>
            {result.reproduced ? <CircleCheck aria-hidden="true" className="size-5" /> : <CircleX aria-hidden="true" className="size-5" />}
            {result.reproduced ? 'Reproduced: identical outputs hash' : 'Not reproduced: the outputs differ'}
          </p>
          <div className="mt-4">
            <KV
              rows={[
                ['Published outputs', <span className="ts-ident font-mono text-[0.76rem]">{result.expectedOutputsHash}</span>],
                ['Computed here', <span className={cx('ts-ident font-mono text-[0.76rem]', result.outputsHash === result.expectedOutputsHash ? 'text-sage-ink' : 'text-vermilion-ink')}>{result.outputsHash}</span>],
                ['Published inputs', <span className="ts-ident font-mono text-[0.76rem]">{result.expectedInputsHash}</span>],
                ['Computed here', <span className={cx('ts-ident font-mono text-[0.76rem]', result.inputsHash === result.expectedInputsHash ? 'text-sage-ink' : 'text-vermilion-ink')}>{result.inputsHash}</span>],
                ['Inputs', `${num(result.inputBytes / 1024, 0)} KB fetched in ${num(result.fetchMs, 0)} ms`],
                ['Engine run', `${num(result.runMs, 0)} ms in this browser`],
              ]}
            />
          </div>
          {result.mismatches.length > 0 && (
            <ul className="mt-4 list-disc space-y-1 pl-5 font-mono text-[0.74rem] text-vermilion-ink">
              {result.mismatches.map((m) => (
                <li key={m} className="ts-ident">
                  {m}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}

function RunDetail({ entry, latestId, autoReproduce }: { entry: RunIndexEntry; latestId: string; autoReproduce: boolean }) {
  const summary = useSummary(entry.runId)
  const setSelectedRunId = useUi((s) => s.setSelectedRunId)
  const navigate = useNavigate()
  return (
    <Load value={summary} what={`run ${entry.runId}`}>
      {(s) => {
        const m = s.manifest
        return (
          <div className="space-y-6">
            <Panel
              eyebrow={entry.runId === latestId ? 'Latest run' : 'Historical run'}
              title={<span className="font-mono">{m.runId}</span>}
              actions={
                <Button
                  icon={<FolderOpen />}
                  onClick={() => {
                    setSelectedRunId(entry.runId === latestId ? null : entry.runId)
                    navigate('/app')
                  }}
                >
                  {entry.runId === latestId ? 'Open the latest run' : 'Open this run'}
                </Button>
              }
            >
              <KV
                rows={[
                  ['As of', date(m.asOf)],
                  ['Dataset', <span className="font-mono text-[0.8rem]">{m.datasetVersion} · {m.mode}</span>],
                  ['Methodology', <span className="font-mono text-[0.8rem]">{m.methodologyVersion} · scoring {m.scoringVersion} · parser {m.parserVersion}</span>],
                  ['Inputs hash', <span className="inline-flex items-start gap-1 font-mono text-[0.76rem]"><span className="ts-ident">{m.inputsHash}</span><CopyText text={m.inputsHash} label="Copy inputs hash" /></span>],
                  ['Outputs hash', <span className="inline-flex items-start gap-1 font-mono text-[0.76rem]"><span className="ts-ident">{m.outputsHash}</span><CopyText text={m.outputsHash} label="Copy outputs hash" /></span>],
                  ['Snapshots', num(m.snapshotIds.length)],
                  ['Vendors', num(s.vendors.length)],
                ]}
              />
            </Panel>
            <Panel title="Reproduce in this browser" eyebrow="Reproducibility" description="Same snapshots + same methodology version → same outputs hash. The engine is the same code the CLI and API run.">
              <Reproduce entry={entry} summary={s} autoStart={autoReproduce} />
            </Panel>
            <div className="grid gap-6 xl:grid-cols-2">
              <Panel title="Stage log" eyebrow="Pipeline">
                <ol className="space-y-2">
                  {m.stages.map((st) => (
                    <li key={st.stage} className="grid grid-cols-[6.5rem_4rem_minmax(0,1fr)] gap-3 text-[0.82rem]">
                      <span className="font-mono text-ink">{st.stage}</span>
                      <span className={cx('font-mono text-[0.75rem]', st.status === 'OK' ? 'text-sage-ink' : st.status === 'WARN' ? 'text-marigold-ink' : st.status === 'FAILED' ? 'text-vermilion-ink' : 'text-ink-3')}>{st.status}</span>
                      <span className="text-ink-2">{st.detail}</span>
                    </li>
                  ))}
                </ol>
              </Panel>
              <Panel title="Quality gate" eyebrow={`${m.qualityChecks.filter((q) => q.passed).length} of ${m.qualityChecks.length} passed`}>
                <ul className="space-y-2">
                  {m.qualityChecks.map((q) => (
                    <li key={q.id} className="flex gap-2.5 text-[0.82rem]">
                      {q.passed ? <CircleCheck aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-sage-ink" /> : <CircleX aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-vermilion-ink" />}
                      <span className="min-w-0">
                        <span className="text-ink">{q.question}</span> <span className="sr-only">{q.passed ? 'passed' : 'needs review'}</span>
                        <span className="block text-[0.76rem] text-ink-3">{q.detail}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              </Panel>
            </div>
          </div>
        )
      }}
    </Load>
  )
}

export function Runs() {
  const index = useRunIndex()
  const [params, setParams] = useSearchParams()
  return (
    <Load value={index} what="runs">
      {(idx) => {
        const reproduceId = params.get('reproduce')
        const selectedId = params.get('run') ?? reproduceId ?? idx.latestRunId
        const entry = idx.runs.find((r) => r.runId === selectedId) ?? idx.runs.find((r) => r.runId === idx.latestRunId)!
        const runs = [...idx.runs].reverse()
        return (
          <>
            <PageHeader
              eyebrow="Runs"
              title="Published runs"
              lede="A run is a methodology version applied to a fixed set of snapshots. Opening a historical run shows the figures it published, under its own methodology, never recomputed with today’s data."
              actions={idx.mode === 'DEMO' ? <DemoLabel /> : undefined}
            />
            <div className="grid gap-6 xl:grid-cols-[20rem_minmax(0,1fr)]">
              <nav aria-label="Runs" className="min-w-0">
                <ol className="relative space-y-2 border-l border-line pl-5">
                  {runs.map((r, i) => {
                    const prev = runs[i + 1]
                    const versionChanged = prev && prev.methodologyVersion !== r.methodologyVersion
                    const on = r.runId === entry.runId
                    return (
                      <li key={r.runId} className="relative">
                        <span aria-hidden="true" className={cx('absolute -left-[1.62rem] top-4 size-2.5 rounded-full ring-4 ring-paper', on ? 'bg-ink' : 'bg-line-strong')} />
                        <button
                          type="button"
                          aria-current={on ? 'true' : undefined}
                          onClick={() => setParams({ run: r.runId }, { replace: true })}
                          className={cx('w-full rounded-card border px-4 py-3 text-left transition-colors', on ? 'border-ink/60 bg-surface-raised shadow-soft' : 'border-line bg-surface hover:border-line-strong')}
                        >
                          <span className="ts-ident block font-mono text-[0.8rem] font-semibold text-ink">{r.runId}</span>
                          <span className="block text-[0.76rem] text-ink-3">
                            as of {date(r.asOf)} · methodology {r.methodologyVersion}
                            {r.runId === idx.latestRunId && ' · latest'}
                          </span>
                        </button>
                        {versionChanged && <p className="mt-2 font-mono text-[0.7rem] text-plum-ink">methodology {prev.methodologyVersion} → {r.methodologyVersion}</p>}
                      </li>
                    )
                  })}
                </ol>
              </nav>
              <div className="min-w-0">
                <RunDetail key={entry.runId} entry={entry} latestId={idx.latestRunId} autoReproduce={reproduceId === entry.runId} />
              </div>
            </div>
          </>
        )
      }}
    </Load>
  )
}

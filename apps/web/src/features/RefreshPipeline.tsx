/**
 * Refresh pipeline: FETCH → NORMALIZE → VALIDATE → SCORE → PUBLISH.
 * API mode starts a real refresh job (administrative). The static demo
 * cannot fetch anything, so it replays the published run's own stage log
 * and says so.
 */
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { motion } from 'motion/react'
import { CircleCheck, CircleDashed, CircleX, Loader, RotateCw, TriangleAlert } from 'lucide-react'
import type { RunManifest } from '@touchstone/core/model'
import { getSource } from '../data/source.ts'
import type { RefreshJob, RefreshStage } from '../data/source.ts'
import { invalidate, useSourceInfo } from '../data/hooks.ts'
import { getAdminToken } from '../lib/admin.ts'
import { Button } from '../ui/Button.tsx'
import { cx } from '../lib/cx.ts'

const DISPLAY = ['FETCH', 'NORMALIZE', 'VALIDATE', 'SCORE', 'PUBLISH'] as const
/** Engine stages folded into the five displayed ones. */
const FOLD: Record<string, (typeof DISPLAY)[number]> = {
  FETCH: 'FETCH',
  SNAPSHOT: 'FETCH',
  NORMALIZE: 'NORMALIZE',
  IDENTITY: 'NORMALIZE',
  VALIDATE: 'VALIDATE',
  MEASURE: 'SCORE',
  SCORE: 'SCORE',
  EVIDENCE: 'SCORE',
  PUBLISH: 'PUBLISH',
}
const RANK: Record<RefreshStage['status'], number> = { PENDING: 0, SKIPPED: 1, OK: 2, RUNNING: 3, WARN: 4, FAILED: 5 }

function fold(stages: { stage: string; status: RefreshStage['status']; detail?: string }[]): RefreshStage[] {
  return DISPLAY.map((name) => {
    const parts = stages.filter((s) => (FOLD[s.stage] ?? s.stage) === name)
    if (!parts.length) return { stage: name, status: 'PENDING' as const, detail: '' }
    const worst = parts.reduce((w, p) => (RANK[p.status] > RANK[w.status] ? p : w), parts[0]!)
    const allPending = parts.every((p) => p.status === 'PENDING')
    const status = allPending ? 'PENDING' : parts.some((p) => p.status === 'RUNNING' || (p.status === 'PENDING' && parts.some((q) => q.status === 'OK'))) ? 'RUNNING' : worst.status
    return { stage: name, status, detail: parts.map((p) => p.detail).filter(Boolean).join(' · ') }
  })
}

function StageIcon({ status }: { status: RefreshStage['status'] }) {
  const cls = 'size-4'
  if (status === 'OK') return <CircleCheck aria-hidden="true" className={cx(cls, 'text-sage-ink')} />
  if (status === 'WARN') return <TriangleAlert aria-hidden="true" className={cx(cls, 'text-marigold-ink')} />
  if (status === 'FAILED') return <CircleX aria-hidden="true" className={cx(cls, 'text-vermilion-ink')} />
  if (status === 'RUNNING') return <Loader aria-hidden="true" className={cx(cls, 'motion-safe:animate-spin text-ink')} />
  return <CircleDashed aria-hidden="true" className={cx(cls, 'text-ink-3')} />
}

export function RefreshPipeline({ manifest, autoStart = false }: { manifest: RunManifest; autoStart?: boolean }) {
  const info = useSourceInfo()
  const [stages, setStages] = useState<RefreshStage[]>(() => fold(manifest.stages))
  const [state, setState] = useState<'idle' | 'running' | 'done' | 'error'>('idle')
  const [message, setMessage] = useState<string | null>(null)
  const [label, setLabel] = useState<'published' | 'replay' | 'live'>('published')
  const timers = useRef<number[]>([])
  const started = useRef(false)

  useEffect(() => () => timers.current.forEach((t) => window.clearTimeout(t)), [])

  const replay = () => {
    setLabel('replay')
    setState('running')
    setMessage(null)
    const final = fold(manifest.stages)
    setStages(final.map((s) => ({ ...s, status: 'PENDING' })))
    final.forEach((s, i) => {
      timers.current.push(window.setTimeout(() => setStages((cur) => cur.map((c, j) => (j === i ? { ...c, status: 'RUNNING' } : c))), 380 + i * 620))
      timers.current.push(window.setTimeout(() => setStages((cur) => cur.map((c, j) => (j === i ? s : c))), 380 + i * 620 + 480))
    })
    timers.current.push(
      window.setTimeout(() => {
        setState('done')
        setMessage('Replayed the published run’s stage log in this browser. The static demo cannot fetch sources; nothing was re-collected.')
      }, 380 + final.length * 620 + 200),
    )
  }

  const live = async () => {
    const src = await getSource()
    const token = getAdminToken()
    if (!src.refresh || !src.refreshStatus) return replay()
    if (!src.adminEnabled) {
      setState('error')
      setMessage('Administration is disabled on this server, and a refresh is an administrative action. Showing the published stage log instead.')
      return
    }
    if (!token) {
      setState('error')
      setMessage('A refresh needs the admin token. Add it under Settings (kept for this tab only).')
      return
    }
    setLabel('live')
    setState('running')
    setMessage(null)
    try {
      let job: RefreshJob = await src.refresh(token)
      setStages(fold(job.stages))
      while (job.status === 'QUEUED' || job.status === 'RUNNING') {
        await new Promise((r) => window.setTimeout(r, 700))
        job = await src.refreshStatus(job.jobId)
        setStages(fold(job.stages))
      }
      if (job.status === 'FAILED') {
        setState('error')
        setMessage(job.error ?? 'The refresh did not complete. The previous verified snapshot remains in use.')
      } else {
        setState('done')
        setMessage(job.statement ?? `Refresh complete${job.runId ? `: run ${job.runId}` : ''}.`)
        invalidate()
      }
    } catch (e) {
      setState('error')
      setMessage(e instanceof Error ? e.message : String(e))
    }
  }

  const run = () => {
    if (info.status === 'ready' && info.data.kind === 'api') void live()
    else replay()
  }

  useEffect(() => {
    if (autoStart && !started.current && info.status === 'ready') {
      started.current = true
      run()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart, info.status])

  const isStatic = info.status === 'ready' && info.data.kind === 'static'
  return (
    <div id="pipeline" className="scroll-mt-24">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-[0.8rem] text-ink-3">
          {label === 'published' && 'Stage log of the published run.'}
          {label === 'replay' && <span className="font-semibold text-marigold-ink">In-browser replay · static demo</span>}
          {label === 'live' && <span className="font-semibold text-ink">Live refresh job</span>}
        </p>
        <Button size="sm" variant="primary" icon={<RotateCw className={state === 'running' ? 'motion-safe:animate-spin' : undefined} />} disabled={state === 'running'} onClick={run}>
          {state === 'running' ? 'Running' : isStatic ? 'Refresh Now (replay)' : 'Refresh Now'}
        </Button>
      </div>
      <ol className="mt-4 grid gap-2 sm:grid-cols-5" aria-live="polite">
        {stages.map((s, i) => (
          <li key={s.stage} className="relative min-w-0">
            <motion.div
              layout
              className={cx(
                'flex h-full min-w-0 flex-col gap-2 rounded-card border p-3 transition-colors',
                s.status === 'RUNNING' ? 'border-ink bg-surface-raised shadow-soft' : s.status === 'PENDING' ? 'border-dashed border-line-strong bg-transparent' : 'border-line bg-surface-raised',
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[0.7rem] tracking-[0.1em] text-ink-2">
                  {String(i + 1).padStart(2, '0')} {s.stage}
                </span>
                <StageIcon status={s.status} />
              </div>
              <span className="sr-only">{s.status}</span>
              {s.detail && <p className="ts-ident line-clamp-3 text-[0.72rem] leading-snug text-ink-3">{s.detail}</p>}
            </motion.div>
          </li>
        ))}
      </ol>
      {message && (
        <p role="status" className={cx('mt-3 text-[0.82rem]', state === 'error' ? 'text-vermilion-ink' : 'text-ink-2')}>
          {message} {state === 'error' && message.includes('Settings') && <Link to="/app/settings" className="ts-link">Open Settings</Link>}
        </p>
      )}
    </div>
  )
}

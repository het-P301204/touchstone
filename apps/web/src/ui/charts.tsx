/**
 * Charts. Small, honest, SVG/CSS only:
 *   CountUp        a figure that counts up once on first view
 *   CoverageRing   evidence coverage (observed slots / total slots)
 *   HBar           one horizontal bar; null renders as a dashed "not measured" track
 *   StackBar       a 100% horizontal bar split into labelled parts
 *   Histogram      bucket distribution as horizontal bars
 *   TrendChart     a metric across runs, methodology versions marked on the axis
 * Motion respects prefers-reduced-motion (MotionConfig reducedMotion="user"
 * and useReducedMotion for the JS-driven count-up).
 */
import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { animate, motion, useInView, useReducedMotion } from 'motion/react'
import { cx } from '../lib/cx.ts'
import { NOT_MEASURED } from '../lib/format.ts'
import { TONE_CLASSES } from '../lib/status.ts'
import type { Tone } from '../lib/status.ts'

const EASE = [0.16, 1, 0.3, 1] as const

export function CountUp({ value, digits = 0, suffix = '', className }: { value: number | null; digits?: number; suffix?: string; className?: string }) {
  const ref = useRef<HTMLSpanElement>(null)
  const inView = useInView(ref, { once: true, margin: '-40px' })
  const reduce = useReducedMotion()
  const [shown, setShown] = useState<number | null>(reduce ? value : 0)
  useEffect(() => {
    if (value === null) return
    if (reduce || !inView) return
    const controls = animate(0, value, { duration: 0.9, ease: EASE, onUpdate: (v) => setShown(v) })
    return () => controls.stop()
  }, [value, inView, reduce])
  const display = value === null ? NOT_MEASURED : `${(reduce ? value : (shown ?? 0)).toFixed(digits)}${suffix}`
  return (
    <span ref={ref} className={cx('ts-num', className)} aria-label={value === null ? 'not measured' : `${value.toFixed(digits)}${suffix}`}>
      <span aria-hidden="true">{display}</span>
    </span>
  )
}

export function CoverageRing({
  percent,
  observed,
  total,
  size = 168,
  label = 'Coverage of independently observable evidence',
}: {
  percent: number
  observed: number
  total: number
  size?: number
  label?: string
}) {
  const stroke = 12
  const r = (size - stroke) / 2 - 2
  const c = 2 * Math.PI * r
  const frac = Math.max(0, Math.min(1, percent / 100))
  // Tick marks, one per slot: the ring is made of countable slots, not a vague gauge.
  const ticks = Array.from({ length: total }, (_, i) => {
    const a = (i / total) * Math.PI * 2 - Math.PI / 2
    const r1 = r + stroke / 2 + 3
    const r2 = r1 + 4
    return { x1: size / 2 + Math.cos(a) * r1, y1: size / 2 + Math.sin(a) * r1, x2: size / 2 + Math.cos(a) * r2, y2: size / 2 + Math.sin(a) * r2, on: i < observed }
  })
  return (
    <figure className="flex min-w-0 flex-col items-center gap-3">
      <div className="relative" style={{ width: size + 16, height: size + 16 }}>
        <svg viewBox={`-8 -8 ${size + 16} ${size + 16}`} width={size + 16} height={size + 16} role="img" aria-label={`${label}: ${observed} of ${total} slots, ${percent.toFixed(0)} percent`}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgb(var(--paper-3))" strokeWidth={stroke} />
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke="rgb(var(--sage))"
            strokeWidth={stroke}
            strokeLinecap="butt"
            strokeDasharray={c}
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
            initial={{ strokeDashoffset: c }}
            whileInView={{ strokeDashoffset: c * (1 - frac) }}
            viewport={{ once: true }}
            transition={{ duration: 1.1, ease: EASE, delay: 0.1 }}
          />
          {ticks.map((t, i) => (
            <line key={i} x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2} stroke={t.on ? 'rgb(var(--ink-2))' : 'rgb(var(--line-strong))'} strokeWidth={1.5} strokeLinecap="round" />
          ))}
        </svg>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <CountUp value={percent} digits={0} suffix="%" className="text-[2.4rem] font-medium leading-none tracking-tight text-ink" />
          <span className="ts-num mt-1.5 text-[0.75rem] text-ink-3">
            {observed} / {total} slots
          </span>
        </div>
      </div>
      <figcaption className="max-w-[15rem] text-center text-[0.8rem] leading-snug text-ink-2">{label}</figcaption>
    </figure>
  )
}

export function HBar({
  value,
  max = 100,
  tone = 'sage',
  label,
  valueLabel,
  marker,
  markerLabel,
  height = 'h-2.5',
  className,
}: {
  value: number | null
  max?: number
  tone?: Tone
  label?: ReactNode
  valueLabel?: ReactNode
  /** Optional reference marker (e.g. peer median). */
  marker?: number | null
  markerLabel?: string
  height?: string
  className?: string
}) {
  const frac = value === null ? 0 : Math.max(0, Math.min(1, value / max))
  const m = marker === null || marker === undefined ? null : Math.max(0, Math.min(1, marker / max))
  return (
    <div className={cx('min-w-0', className)}>
      {(label || valueLabel) && (
        <div className="mb-1.5 flex items-baseline justify-between gap-3 text-[0.82rem]">
          <span className="min-w-0 truncate text-ink-2">{label}</span>
          <span className="ts-num shrink-0 text-ink">{valueLabel ?? (value === null ? NOT_MEASURED : value.toFixed(1))}</span>
        </div>
      )}
      <div className={cx('relative w-full overflow-visible rounded-full', height, value === null ? 'ts-unknown' : 'bg-paper-3')}>
        {value !== null && (
          <motion.div
            className={cx('absolute inset-y-0 left-0 rounded-full', TONE_CLASSES[tone].fill)}
            initial={{ width: 0 }}
            whileInView={{ width: `${frac * 100}%` }}
            viewport={{ once: true }}
            transition={{ duration: 0.8, ease: EASE }}
          />
        )}
        {m !== null && (
          <span
            title={markerLabel}
            aria-hidden="true"
            className="absolute -inset-y-1 w-0.5 rounded-full bg-ink"
            style={{ left: `calc(${m * 100}% - 1px)` }}
          />
        )}
      </div>
    </div>
  )
}

export type StackPart = { key: string; label: string; value: number; tone: Tone; hatch?: boolean; dashed?: boolean }

export function StackBar({ parts, className, showLegend = true }: { parts: StackPart[]; className?: string; showLegend?: boolean }) {
  const total = parts.reduce((s, p) => s + p.value, 0)
  return (
    <div className={cx('min-w-0', className)}>
      <div className="flex h-3 w-full overflow-hidden rounded-full bg-paper-3" role="img" aria-label={parts.map((p) => `${p.label}: ${p.value}`).join(', ')}>
        {total > 0 &&
          parts.map((p, i) =>
            p.value > 0 ? (
              <motion.div
                key={p.key}
                className={cx('h-full', p.hatch ? 'ts-hatch bg-iris/20' : p.dashed ? 'ts-unknown bg-paper-2' : TONE_CLASSES[p.tone].fill, i > 0 && 'border-l-2 border-surface')}
                initial={{ width: 0 }}
                whileInView={{ width: `${(p.value / total) * 100}%` }}
                viewport={{ once: true }}
                transition={{ duration: 0.8, ease: EASE, delay: i * 0.05 }}
              />
            ) : null,
          )}
      </div>
      {showLegend && (
        <ul className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1.5 text-[0.78rem] text-ink-2">
          {parts.map((p) => (
            <li key={p.key} className="flex min-w-0 items-center gap-1.5">
              <span aria-hidden="true" className={cx('inline-block size-2.5 rounded-[3px]', p.hatch ? 'ts-hatch bg-iris/20' : p.dashed ? 'border border-dashed border-ink-3' : TONE_CLASSES[p.tone].fill)} />
              <span>{p.label}</span>
              <span className="ts-num text-ink">{p.value}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export function Histogram({
  buckets,
  tone = 'sage',
  unit = 'vendors',
  highlight,
}: {
  buckets: { bucket: string; count: number }[]
  tone?: Tone
  unit?: string
  highlight?: string
}) {
  const max = Math.max(1, ...buckets.map((b) => b.count))
  return (
    <ul className="space-y-2">
      {buckets.map((b, i) => (
        <li key={b.bucket} className="grid grid-cols-[6.5rem_minmax(0,1fr)_auto] items-center gap-3 text-[0.82rem]">
          <span className={cx('ts-num text-ink-2', highlight === b.bucket && 'font-semibold text-ink')}>{b.bucket}</span>
          <div className="relative h-5 min-w-0 rounded-[6px] bg-paper-2">
            <motion.div
              className={cx('absolute inset-y-0 left-0 rounded-[6px]', TONE_CLASSES[tone].fill, highlight && highlight !== b.bucket && 'opacity-50')}
              initial={{ width: 0 }}
              whileInView={{ width: `${(b.count / max) * 100}%` }}
              viewport={{ once: true }}
              transition={{ duration: 0.7, ease: EASE, delay: i * 0.04 }}
            />
          </div>
          <span className="ts-num w-10 text-right text-ink" aria-label={`${b.count} ${unit}`}>
            {b.count}
          </span>
        </li>
      ))}
    </ul>
  )
}

export type TrendPoint = { label: string; value: number | null; methodologyVersion: string; runId?: string }
export type TrendSeries = { key: string; label: string; tone: Tone; points: TrendPoint[]; dashed?: boolean }

/**
 * Line chart across runs. Null points break the line (never drawn as 0).
 * A methodology version change is marked with a vertical rule and its label.
 */
export function TrendChart({
  series,
  height = 220,
  yMax = 100,
  yLabel = '%',
  ariaLabel,
}: {
  series: TrendSeries[]
  height?: number
  yMax?: number
  yLabel?: string
  ariaLabel: string
}) {
  const first = series[0]
  if (!first || first.points.length === 0) return null
  const W = 960
  const H = height
  const pad = { l: 44, r: 48, t: 28, b: 42 }
  const n = first.points.length
  const x = (i: number) => pad.l + (n === 1 ? (W - pad.l - pad.r) / 2 : (i / (n - 1)) * (W - pad.l - pad.r))
  const y = (v: number) => pad.t + (1 - v / yMax) * (H - pad.t - pad.b)
  const versionChanges = first.points
    .map((p, i) => ({ i, v: p.methodologyVersion }))
    .filter((p, i, arr) => i > 0 && p.v !== arr[i - 1]!.v)
  const gridValues = [0, yMax / 2, yMax]

  return (
    <figure className="min-w-0">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label={ariaLabel}>
        {gridValues.map((g) => (
          <g key={g}>
            <line x1={pad.l} x2={W - pad.r} y1={y(g)} y2={y(g)} stroke="rgb(var(--line))" strokeWidth={1} />
            <text x={pad.l - 8} y={y(g) + 4} textAnchor="end" className="fill-ink-3 font-mono text-[11px]">
              {g}
              {yLabel === '%' ? '' : ''}
            </text>
          </g>
        ))}
        {versionChanges.map((vc) => {
          const vx = (x(vc.i) + x(vc.i - 1)) / 2
          return (
            <g key={vc.i}>
              <line x1={vx} x2={vx} y1={pad.t - 14} y2={H - pad.b} stroke="rgb(var(--plum))" strokeDasharray="3 3" strokeWidth={1.2} />
              <text x={vx + 5} y={pad.t - 6} className="fill-plum-ink font-mono text-[10.5px]">
                methodology {vc.v}
              </text>
            </g>
          )
        })}
        {first.points.map((p, i) => (
          <text key={i} x={x(i)} y={H - pad.b + 18} textAnchor="middle" className="fill-ink-3 font-mono text-[10.5px]">
            {p.label}
          </text>
        ))}
        {first.points.map((p, i) => (
          <text key={`v${i}`} x={x(i)} y={H - pad.b + 31} textAnchor="middle" className="fill-ink-3 font-mono text-[9.5px] opacity-80">
            v{p.methodologyVersion}
          </text>
        ))}
        {series.map((s, si) => {
          // Split into segments at nulls: a missing value is a gap, never zero.
          const segments: { i: number; v: number }[][] = []
          let cur: { i: number; v: number }[] = []
          s.points.forEach((p, i) => {
            if (p.value === null) {
              if (cur.length) segments.push(cur)
              cur = []
            } else cur.push({ i, v: p.value })
          })
          if (cur.length) segments.push(cur)
          const stroke = `rgb(var(--${s.tone === 'stone' ? 'ink-3' : s.tone}))`
          return (
            <g key={s.key}>
              {segments.map((seg, k) => (
                // pathLength drives stroke-dasharray, so a dashed series fades in instead of drawing.
                <motion.path
                  key={k}
                  d={seg.map((pt, j) => `${j === 0 ? 'M' : 'L'}${x(pt.i)},${y(pt.v)}`).join(' ')}
                  fill="none"
                  stroke={stroke}
                  strokeWidth={s.dashed ? 1.5 : 2.25}
                  strokeDasharray={s.dashed ? '6 5' : undefined}
                  strokeLinejoin="round"
                  initial={s.dashed ? { opacity: 0 } : { pathLength: 0 }}
                  whileInView={s.dashed ? { opacity: 1 } : { pathLength: 1 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.9, ease: EASE, delay: si * 0.08 }}
                />
              ))}
              {s.points.map((p, i) =>
                p.value === null ? (
                  <g key={i}>
                    <circle cx={x(i)} cy={H - pad.b} r={3.5} fill="rgb(var(--surface))" stroke="rgb(var(--ink-3))" strokeDasharray="2 2" />
                  </g>
                ) : (
                  <circle key={i} cx={x(i)} cy={y(p.value)} r={s.dashed ? 2.5 : 3.5} fill="rgb(var(--surface))" stroke={stroke} strokeWidth={2}>
                    <title>{`${s.label} · ${p.label}: ${p.value.toFixed(1)}`}</title>
                  </circle>
                ),
              )}
            </g>
          )
        })}
      </svg>
      {series.length > 1 && (
        <figcaption className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[0.78rem] text-ink-2">
          {series.map((s) => (
            <span key={s.key} className="inline-flex items-center gap-1.5">
              <span aria-hidden="true" className={cx('inline-block h-0.5 w-4', TONE_CLASSES[s.tone].fill, s.dashed && 'opacity-70')} />
              {s.label}
            </span>
          ))}
          <span className="inline-flex items-center gap-1.5">
            <span aria-hidden="true" className="inline-block size-2.5 rounded-full border border-dashed border-ink-3" />
            not measured
          </span>
        </figcaption>
      )}
    </figure>
  )
}

/**
 * The hero's signature visual: a claim drawn across a test surface.
 *
 * A pledge claim passes five stations (CLAIM, SOURCE, QUERY, MEASURE,
 * RESULT). A measurable claim leaves a solid streak and emerges with a
 * measured result; a claim outside the public evidence boundary leaves only
 * a hatched trace after SOURCE and emerges "Not externally verifiable".
 * Figures are illustrative and labelled so.
 */
import { useEffect, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { cx } from '../lib/cx.ts'
import { GOAL_STATUS } from '../lib/status.ts'
import type { GoalStatus } from '@touchstone/core/model'

type Claim = {
  goal: string
  short: string
  claim: string
  source: string
  query: string
  measure: string
  measureSub: string
  result: Extract<GoalStatus, 'VERIFIED' | 'NOT_EXTERNALLY_VERIFIABLE'>
  observable: boolean
}

const CLAIMS: Claim[] = [
  {
    goal: 'G6',
    short: 'CVE records',
    claim: 'Include accurate CWE and CPE fields in every CVE record.',
    source: 'CVE JSON 5.1 records · containers.cna',
    query: 'attributed · PUBLISHED · ≤ 730 days · third-party ADP data excluded',
    measure: '428 / 428',
    measureSub: 'records complete in the CNA container',
    result: 'VERIFIED',
    observable: true,
  },
  {
    goal: 'G1',
    short: 'MFA adoption',
    claim: 'Measurably increase the use of multi-factor authentication.',
    source: 'No public source reports adoption',
    query: 'nothing to query',
    measure: 'no measurement',
    measureSub: 'adoption lives in the vendor’s own telemetry',
    result: 'NOT_EXTERNALLY_VERIFIABLE',
    observable: false,
  },
  {
    goal: 'G5',
    short: 'Disclosure policy',
    claim: 'Publish a VDP that authorizes testing and offers good-faith safe harbor.',
    source: 'Vendor policy page · security.txt (RFC 9116)',
    query: '8 criteria · documented phrase rules · every sentence quoted',
    measure: '4 / 4',
    measureSub: 'pledge elements met, each with its quote',
    result: 'VERIFIED',
    observable: true,
  },
]

const STATIONS = ['Claim', 'Source', 'Query', 'Measure', 'Result'] as const
const STEP_MS = 760
const HOLD_MS = 2800

export function TestSurface() {
  const reduce = useReducedMotion()
  const [index, setIndex] = useState(0)
  const [phase, setPhase] = useState(reduce ? 5 : 0)
  const [paused, setPaused] = useState(false)
  const claim = CLAIMS[index]!

  useEffect(() => {
    if (reduce || paused) return
    const t = window.setTimeout(
      () => {
        if (phase < 5) setPhase(phase + 1)
        else {
          setIndex((i) => (i + 1) % CLAIMS.length)
          setPhase(0)
        }
      },
      phase === 0 ? 420 : phase < 5 ? STEP_MS : HOLD_MS,
    )
    return () => window.clearTimeout(t)
  }, [phase, reduce, paused])

  const select = (i: number) => {
    setIndex(i)
    setPhase(reduce ? 5 : 0)
  }

  const shown = (station: number) => phase > station
  const ResultIcon = GOAL_STATUS[claim.result].icon
  // Streak progress: 0..1 across the five stations.
  const progress = Math.min(phase, 5) / 5

  return (
    <div
      className="relative overflow-hidden rounded-hero bg-slab text-slab-ink shadow-lift ring-1 ring-slab-line"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocusCapture={() => setPaused(true)}
      onBlurCapture={() => setPaused(false)}
    >
      {/* Measurement scale along the top edge: the surface is an instrument. */}
      <div aria-hidden="true" className="absolute inset-x-0 top-0 flex h-3 justify-between px-6 opacity-60">
        {Array.from({ length: 49 }, (_, i) => (
          <span key={i} className={cx('w-px bg-slab-dim', i % 6 === 0 ? 'h-3' : 'h-1.5')} />
        ))}
      </div>

      <div className="relative px-5 pb-6 pt-8 sm:px-8 sm:pb-8 lg:px-10">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="font-mono text-[0.7rem] uppercase tracking-[0.14em] text-slab-dim">Test surface · illustrative figures, not a measurement of any vendor</p>
          <div role="tablist" aria-label="Example claims" className="flex flex-wrap gap-1.5">
            {CLAIMS.map((c, i) => (
              <button
                key={c.goal}
                role="tab"
                type="button"
                aria-selected={i === index}
                onClick={() => select(i)}
                className={cx(
                  'h-8 rounded-[10px] px-3 font-mono text-[0.72rem] transition-colors focus-visible:outline-slab-ink',
                  i === index ? 'bg-slab-ink text-slab' : 'text-slab-dim ring-1 ring-inset ring-slab-line hover:text-slab-ink',
                )}
              >
                {c.goal} · {c.short}
              </button>
            ))}
          </div>
        </div>

        <div className="relative mt-8" aria-live="polite">
          {/* The streak, behind the stations (desktop: horizontal). */}
          <div aria-hidden="true" className="absolute left-0 right-0 top-[1.15rem] hidden h-[5px] lg:block">
            <div className="absolute inset-0 rounded-full bg-slab-2" />
            <motion.div
              key={`streak-${index}`}
              className="absolute inset-y-0 left-0 rounded-full"
              style={{
                background: claim.observable
                  ? 'linear-gradient(90deg, rgb(var(--marigold) / 0.15), rgb(var(--marigold) / 0.9) 70%, #E9C46F)'
                  : 'linear-gradient(90deg, rgb(var(--marigold) / 0.15), rgb(var(--marigold) / 0.7) 18%, transparent 24%), repeating-linear-gradient(135deg, rgb(var(--iris) / 0.75) 0 2px, transparent 2px 7px)',
              }}
              initial={{ width: reduce ? `${progress * 100}%` : '0%' }}
              animate={{ width: `${progress * 100}%` }}
              transition={{ duration: reduce ? 0 : 0.7, ease: [0.45, 0, 0.55, 1] }}
            />
          </div>

          <ol className="relative grid gap-3 lg:grid-cols-5 lg:gap-4">
            {STATIONS.map((name, i) => {
              const on = shown(i)
              const boundary = !claim.observable && i >= 2 && i <= 3
              return (
                <li key={name} className="relative min-w-0">
                  <div className="flex items-center gap-2.5">
                    <span
                      aria-hidden="true"
                      className={cx(
                        'relative z-[1] flex size-[2.3rem] shrink-0 items-center justify-center rounded-full font-mono text-[0.7rem] ring-1 transition-colors duration-300',
                        on ? (boundary ? 'bg-slab ring-slab-iris text-slab-iris' : 'bg-slab-ink text-slab ring-slab-ink') : 'bg-slab text-slab-dim ring-slab-line',
                      )}
                    >
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <span className="relative z-[1] bg-slab pr-2 font-mono text-[0.72rem] uppercase tracking-[0.14em] text-slab-dim">{name}</span>
                  </div>
                  <div className="mt-3 min-h-[6.5rem] rounded-card bg-slab-2/80 p-4 ring-1 ring-inset ring-slab-line lg:min-h-[8.5rem]">
                    <AnimatePresence mode="wait">
                      {on ? (
                        <motion.div
                          key={`${index}-${i}`}
                          initial={{ opacity: 0, y: 6 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0 }}
                          transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
                          className="min-w-0"
                        >
                          {i === 0 && (
                            <p className="text-[0.92rem] font-semibold leading-snug text-slab-ink">
                              <span className="mr-1.5 font-mono text-[0.72rem] font-normal text-marigold">{claim.goal}</span>“{claim.claim}”
                            </p>
                          )}
                          {i === 1 && <p className={cx('text-[0.86rem] leading-snug', claim.observable ? 'text-slab-ink' : 'text-slab-iris')}>{claim.source}</p>}
                          {i === 2 && (
                            <p className={cx('font-mono text-[0.76rem] leading-relaxed', claim.observable ? 'text-slab-ink/90' : 'text-slab-dim line-through decoration-iris/60')}>
                              {claim.query}
                            </p>
                          )}
                          {i === 3 &&
                            (claim.observable ? (
                              <div>
                                <p className="font-mono text-[1.6rem] font-medium leading-none tracking-tight text-slab-ink">{claim.measure}</p>
                                <p className="mt-2 text-[0.78rem] leading-snug text-slab-dim">{claim.measureSub}</p>
                              </div>
                            ) : (
                              <div>
                                <div className="ts-hatch h-6 rounded-[6px] ring-1 ring-inset ring-iris/50" />
                                <p className="mt-2 text-[0.78rem] leading-snug text-slab-dim">{claim.measureSub}</p>
                              </div>
                            ))}
                          {i === 4 && (
                            <div>
                              <span
                                className={cx(
                                  'inline-flex items-center gap-1.5 rounded-chip px-2.5 py-1.5 text-[0.8rem] font-bold',
                                  claim.result === 'VERIFIED' ? 'bg-sage text-[rgb(var(--graphite-fixed))]' : 'ts-hatch bg-iris/25 text-slab-ink ring-1 ring-inset ring-iris',
                                )}
                              >
                                <ResultIcon aria-hidden="true" className="size-4" />
                                {claim.result === 'VERIFIED' ? 'Verified' : 'Not externally verifiable'}
                              </span>
                              <p className="mt-2 text-[0.78rem] leading-snug text-slab-dim">
                                {claim.result === 'VERIFIED' ? 'Evidence supports the measurement, and every figure can be re-run.' : 'No score is invented. The boundary is reported.'}
                              </p>
                            </div>
                          )}
                        </motion.div>
                      ) : (
                        <motion.span key="wait" aria-hidden="true" className="block h-2 w-10 rounded-full bg-slab-line/70" initial={{ opacity: 0 }} animate={{ opacity: 1 }} />
                      )}
                    </AnimatePresence>
                  </div>
                </li>
              )
            })}
          </ol>
        </div>
      </div>
    </div>
  )
}

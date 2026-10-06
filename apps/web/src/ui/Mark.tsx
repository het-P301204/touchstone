/**
 * The TOUCHSTONE mark: a test surface (the graphite slab), one contact
 * streak drawn across it, the contact point at the end of the streak, and a
 * measurement scale along the lower edge. A touchstone is the dark stone an
 * assayer rubs metal across to read the streak: the claim leaves a mark that
 * can be measured.
 */
import { useId } from 'react'
import { cx } from '../lib/cx.ts'

export function Mark({ className, title = 'TOUCHSTONE' }: { className?: string; title?: string | null }) {
  const id = useId()
  const grad = `${id}-streak`
  return (
    <svg viewBox="0 0 32 32" className={cx('shrink-0', className)} role={title ? 'img' : undefined} aria-label={title ?? undefined} aria-hidden={title ? undefined : true}>
      <defs>
        <linearGradient id={grad} x1="7" y1="20" x2="24" y2="11" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="rgb(var(--marigold))" stopOpacity="0.15" />
          <stop offset="0.55" stopColor="rgb(var(--marigold))" stopOpacity="0.85" />
          <stop offset="1" stopColor="#E9C46F" />
        </linearGradient>
      </defs>
      <rect x="1.5" y="1.5" width="29" height="29" rx="8" fill="rgb(var(--slab))" />
      <rect x="1.5" y="1.5" width="29" height="29" rx="8" fill="none" stroke="rgb(var(--slab-line))" strokeWidth="1" />
      <path d="M7.5 19.5 L23.5 11.5" stroke={`url(#${grad})`} strokeWidth="4.2" strokeLinecap="round" />
      <circle cx="23.5" cy="11.5" r="1.6" fill="rgb(var(--slab-ink))" />
      <path d="M8 25.2v-1.6M12 25.2v-2.6M16 25.2v-1.6M20 25.2v-2.6M24 25.2v-1.6" stroke="rgb(var(--slab-dim))" strokeWidth="1.1" strokeLinecap="round" />
    </svg>
  )
}

export function Wordmark({ className, compact = false }: { className?: string; compact?: boolean }) {
  return (
    <span className={cx('inline-flex items-center gap-2.5', className)}>
      <Mark className="size-7" title={null} />
      <span className="flex flex-col leading-none">
        <span className="text-[0.95rem] font-extrabold tracking-[0.14em] text-ink">TOUCHSTONE</span>
        {!compact && <span className="mt-1 hidden font-mono text-[0.625rem] uppercase tracking-[0.14em] text-ink-3 sm:block">Commitment verification</span>}
      </span>
    </span>
  )
}

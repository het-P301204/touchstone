/**
 * Small controls: Disclosure (animated expander), Segmented (radio group),
 * Kbd, DemoLabel, CopyText, ExternalLink, Field.
 */
import { useId, useState } from 'react'
import type { ReactNode } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { Check, ChevronDown, Copy, ExternalLink as ExternalIcon, FlaskConical } from 'lucide-react'
import { cx } from '../lib/cx.ts'

export function Disclosure({
  summary,
  children,
  defaultOpen = false,
  className,
  summaryClassName,
}: {
  summary: ReactNode
  children: ReactNode
  defaultOpen?: boolean
  className?: string
  summaryClassName?: string
}) {
  const [open, setOpen] = useState(defaultOpen)
  const id = useId()
  return (
    <div className={cx('min-w-0', className)}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((o) => !o)}
        className={cx('group flex w-full min-w-0 items-center justify-between gap-3 text-left', summaryClassName)}
      >
        <span className="min-w-0 flex-1">{summary}</span>
        <ChevronDown aria-hidden="true" className={cx('size-4 shrink-0 text-ink-3 transition-transform duration-200', open && 'rotate-180')} />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            id={id}
            key="body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden"
          >
            {children}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export function Segmented<T extends string>({
  value,
  onChange,
  options,
  label,
  size = 'md',
  className,
}: {
  value: T
  onChange: (v: T) => void
  options: { value: T; label: ReactNode; icon?: ReactNode; title?: string }[]
  label: string
  size?: 'sm' | 'md'
  className?: string
}) {
  const name = useId()
  return (
    <fieldset className={cx('min-w-0', className)}>
      <legend className="sr-only">{label}</legend>
      <div className="inline-flex max-w-full flex-wrap rounded-control bg-paper-2 p-1 ring-1 ring-inset ring-line">
        {options.map((o) => (
          <label
            key={o.value}
            title={o.title}
            className={cx(
              'relative inline-flex cursor-pointer items-center gap-1.5 rounded-[10px] font-semibold transition-colors [&_svg]:size-4',
              'has-[:focus-visible]:outline has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-focus',
              size === 'sm' ? 'h-7 px-2.5 text-[0.75rem]' : 'h-8 px-3 text-[0.8125rem]',
              value === o.value ? 'bg-surface-raised text-ink shadow-soft' : 'text-ink-2 hover:text-ink',
            )}
          >
            <input type="radio" name={name} value={o.value} checked={value === o.value} onChange={() => onChange(o.value)} className="sr-only" />
            {o.icon}
            {o.label}
          </label>
        ))}
      </div>
    </fieldset>
  )
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded-[6px] border border-line-strong bg-surface-raised px-1 font-mono text-[0.68rem] text-ink-2">{children}</kbd>
}

/** Persistent but quiet label shown whenever the dataset mode is DEMO. */
export function DemoLabel({ className, long = false }: { className?: string; long?: boolean }) {
  return (
    <span
      className={cx('inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-chip border border-dashed border-marigold-ink/50 bg-marigold/10 px-2 py-0.5 font-mono text-[0.68rem] font-medium uppercase tracking-[0.1em] text-marigold-ink', className)}
      title="Synthetic demo dataset: fictional vendors and records. These are not measurements of real companies."
    >
      <FlaskConical aria-hidden="true" className="size-3.5" />
      {long ? 'Demo data · fictional vendors' : 'Demo data'}
    </span>
  )
}

export function CopyText({ text, label = 'Copy', className }: { text: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      aria-label={`${label}: ${text}`}
      className={cx('inline-flex size-7 shrink-0 items-center justify-center rounded-[8px] text-ink-3 transition-colors hover:bg-paper-2 hover:text-ink', className)}
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setDone(true)
          window.setTimeout(() => setDone(false), 1400)
        })
      }}
    >
      {done ? <Check aria-hidden="true" className="size-3.5" /> : <Copy aria-hidden="true" className="size-3.5" />}
    </button>
  )
}

/** External link that never leaks the referrer and says where it goes. Only http(s) URLs render as links. */
export function ExtLink({ href, children, className }: { href: string; children?: ReactNode; className?: string }) {
  const safe = /^https?:\/\//i.test(href)
  if (!safe) return <span className={cx('ts-ident font-mono text-[0.8rem] text-ink-2', className)}>{children ?? href}</span>
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className={cx('ts-link ts-ident', className)}>
      {children ?? href}
      <ExternalIcon aria-hidden="true" className="ml-1 inline size-3 align-baseline" />
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  )
}

export function Field({ label, hint, children, htmlFor }: { label: ReactNode; hint?: ReactNode; children: ReactNode; htmlFor?: string }) {
  return (
    <div className="min-w-0">
      <label htmlFor={htmlFor} className="mb-1.5 block text-[0.82rem] font-semibold text-ink">
        {label}
      </label>
      {children}
      {hint && <p className="mt-1.5 text-[0.78rem] text-ink-3">{hint}</p>}
    </div>
  )
}

/** Key/value list for provenance blocks. */
export function KV({ rows, className }: { rows: [ReactNode, ReactNode][]; className?: string }) {
  return (
    <dl className={cx('grid grid-cols-1 gap-x-6 gap-y-2.5 text-[0.84rem] sm:grid-cols-[minmax(8rem,auto)_1fr]', className)}>
      {rows.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="ts-eyebrow pt-0.5">{k}</dt>
          <dd className="ts-ident min-w-0 text-ink">{v}</dd>
        </div>
      ))}
    </dl>
  )
}

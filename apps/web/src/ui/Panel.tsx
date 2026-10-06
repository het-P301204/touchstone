import type { ReactNode } from 'react'
import { cx } from '../lib/cx.ts'

/**
 * Panel: the standard container. `min-w-0` is in the base class so a long
 * identifier inside a grid or flex parent can never widen the page.
 */
export function Panel({
  title,
  eyebrow,
  description,
  actions,
  children,
  className,
  bodyClassName,
  as: As = 'section',
  id,
  flush = false,
}: {
  title?: ReactNode
  eyebrow?: ReactNode
  description?: ReactNode
  actions?: ReactNode
  children?: ReactNode
  className?: string
  bodyClassName?: string
  as?: 'section' | 'div' | 'article'
  id?: string
  flush?: boolean
}) {
  const hasHeader = title || eyebrow || actions || description
  return (
    <As id={id} className={cx('ts-panel', className)} aria-label={typeof title === 'string' ? title : undefined}>
      {hasHeader && (
        <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 px-5 pt-5 sm:px-6">
          <div className="min-w-0 grow basis-[min(100%,16rem)]">
            {eyebrow && <p className="ts-eyebrow mb-1.5">{eyebrow}</p>}
            {title && <h2 className="text-title-3 text-ink">{title}</h2>}
            {description && <p className="mt-1 max-w-prose text-sm text-ink-2">{description}</p>}
          </div>
          {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx(flush ? (hasHeader ? 'pt-4' : '') : cx('px-5 pb-5 sm:px-6 sm:pb-6', hasHeader ? 'pt-4' : 'pt-5'), bodyClassName)}>{children}</div>
    </As>
  )
}

/** Page header for app views. */
export function PageHeader({
  eyebrow,
  title,
  lede,
  actions,
  children,
}: {
  eyebrow?: ReactNode
  title: ReactNode
  lede?: ReactNode
  actions?: ReactNode
  children?: ReactNode
}) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-x-6 gap-y-4 sm:mb-8">
      <div className="min-w-0 max-w-3xl grow basis-[min(100%,24rem)]">
        {eyebrow && <p className="ts-eyebrow mb-2">{eyebrow}</p>}
        <h1 className="ts-ident text-title-1 text-ink">{title}</h1>
        {lede && <p className="mt-3 max-w-prose text-[0.975rem] leading-relaxed text-ink-2">{lede}</p>}
        {children}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}

/** Small labelled figure. */
export function Stat({ label, value, sub, className }: { label: ReactNode; value: ReactNode; sub?: ReactNode; className?: string }) {
  return (
    <div className={cx('min-w-0', className)}>
      <p className="ts-eyebrow">{label}</p>
      <p className="ts-num mt-1.5 text-[1.9rem] font-medium leading-none tracking-tight text-ink">{value}</p>
      {sub && <p className="mt-1.5 text-[0.8rem] text-ink-3">{sub}</p>}
    </div>
  )
}

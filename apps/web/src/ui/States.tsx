import type { ReactNode } from 'react'
import { DatabaseZap, RotateCw } from 'lucide-react'
import { cx } from '../lib/cx.ts'
import { DataError } from '../data/source.ts'
import { invalidate } from '../data/hooks.ts'
import type { Loadable } from '../data/hooks.ts'
import { Button } from './Button.tsx'

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden="true" className={cx('ts-skeleton rounded-card', className)} />
}

export function LoadingState({ label = 'Loading', rows = 3 }: { label?: string; rows?: number }) {
  return (
    <div role="status" aria-live="polite" className="space-y-3">
      <span className="sr-only">{label}</span>
      <Skeleton className="h-8 w-1/3" />
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-24 w-full" />
      ))}
    </div>
  )
}

export function EmptyState({ title, children, icon, action }: { title: ReactNode; children?: ReactNode; icon?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-3 rounded-card border border-dashed border-line-strong bg-paper-2/40 px-5 py-8 sm:px-8">
      {icon && <div className="text-ink-3 [&_svg]:size-6">{icon}</div>}
      <p className="text-title-3 text-ink">{title}</p>
      {children && <div className="max-w-prose text-sm leading-relaxed text-ink-2">{children}</div>}
      {action}
    </div>
  )
}

/**
 * Error display. A 404 on the bundle index means the demo dataset has not
 * been built yet: say so plainly, with the command that builds it.
 */
export function ErrorState({ error, what = 'this data' }: { error: Error; what?: string }) {
  const missingBundle = error instanceof DataError && error.status === 404
  if (missingBundle) {
    return (
      <EmptyState icon={<DatabaseZap />} title="No published dataset found">
        <p>
          The app could not find the published run files ({' '}
          <code className="ts-ident font-mono text-[0.8rem]">{error.url}</code>). In a local checkout they are produced by{' '}
          <code className="font-mono text-[0.8rem]">npm run demo:build</code>. Nothing is shown in their place: TOUCHSTONE does not display figures it cannot
          trace to a run.
        </p>
      </EmptyState>
    )
  }
  return (
    <div role="alert" className="rounded-card border border-vermilion/40 bg-vermilion/10 px-5 py-5">
      <p className="font-semibold text-vermilion-ink">Could not load {what}.</p>
      <p className="ts-ident mt-1 font-mono text-[0.8rem] text-ink-2">{error.message}</p>
      <Button size="sm" className="mt-3" icon={<RotateCw />} onClick={() => invalidate()}>
        Try again
      </Button>
    </div>
  )
}

/** Render a Loadable: skeleton while loading, ErrorState on error, children when ready. */
export function Load<T>({ value, children, what, loading }: { value: Loadable<T>; children: (data: T) => ReactNode; what?: string; loading?: ReactNode }) {
  if (value.status === 'loading') return <>{loading ?? <LoadingState label={`Loading ${what ?? 'data'}`} />}</>
  if (value.status === 'error') return <ErrorState error={value.error} what={what} />
  return <>{children(value.data)}</>
}

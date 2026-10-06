import { forwardRef } from 'react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { Link } from 'react-router'
import type { LinkProps } from 'react-router'
import { cx } from '../lib/cx.ts'

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'quiet' | 'on-slab' | 'on-slab-outline'
export type ButtonSize = 'sm' | 'md' | 'lg'

const base =
  'inline-flex min-w-0 select-none items-center justify-center gap-2 whitespace-nowrap rounded-control font-semibold transition-[background-color,border-color,color,box-shadow,transform] duration-150 ease-out-quart active:translate-y-px disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0'

const variants: Record<ButtonVariant, string> = {
  primary: 'bg-ink text-paper shadow-soft hover:bg-ink/90',
  secondary: 'border border-line-strong bg-surface-raised text-ink hover:border-ink/60 hover:bg-surface',
  ghost: 'text-ink hover:bg-paper-2',
  quiet: 'text-ink-2 underline decoration-line-strong underline-offset-4 hover:text-ink hover:decoration-ink',
  'on-slab': 'bg-slab-ink text-slab hover:bg-slab-ink/90 focus-visible:outline-slab-ink',
  'on-slab-outline': 'text-slab-ink ring-1 ring-inset ring-slab-line hover:bg-slab-2 focus-visible:outline-slab-ink',
}

const sizes: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-[0.8125rem]',
  md: 'h-10 px-4 text-sm',
  lg: 'h-12 px-5 text-[0.95rem]',
}

export function buttonClass(variant: ButtonVariant = 'secondary', size: ButtonSize = 'md', className?: string): string {
  return cx(base, variants[variant], sizes[size], variant === 'quiet' && 'h-auto px-0', className)
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: ButtonSize; icon?: ReactNode; trailing?: ReactNode }

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', icon, trailing, className, children, type = 'button', ...rest },
  ref,
) {
  return (
    <button ref={ref} type={type} className={buttonClass(variant, size, className)} {...rest}>
      {icon}
      {children}
      {trailing}
    </button>
  )
})

export function ButtonLink({
  variant = 'secondary',
  size = 'md',
  icon,
  trailing,
  className,
  children,
  ...rest
}: LinkProps & { variant?: ButtonVariant; size?: ButtonSize; icon?: ReactNode; trailing?: ReactNode }) {
  return (
    <Link className={buttonClass(variant, size, className)} {...rest}>
      {icon}
      {children}
      {trailing}
    </Link>
  )
}

export function IconButton({
  label,
  className,
  children,
  size = 'md',
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string; size?: 'sm' | 'md' }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cx(
        'inline-flex shrink-0 items-center justify-center rounded-control text-ink-2 transition-colors hover:bg-paper-2 hover:text-ink [&_svg]:size-[18px]',
        size === 'sm' ? 'size-8' : 'size-10',
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  )
}

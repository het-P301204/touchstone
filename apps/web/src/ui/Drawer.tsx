/**
 * Drawer: a right-side panel (bottom sheet on phones) with portal, focus
 * trap, Esc to close, aria-modal and focus restore.
 */
import { useId, useRef } from 'react'
import type { ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { AnimatePresence, motion } from 'motion/react'
import { X } from 'lucide-react'
import { cx } from '../lib/cx.ts'
import { IconButton } from './Button.tsx'
import { useFocusTrap } from './useFocusTrap.ts'

export interface DrawerProps {
  open: boolean
  onClose: () => void
  title: ReactNode
  eyebrow?: ReactNode
  width?: 'md' | 'lg' | 'xl'
  children?: ReactNode
  footer?: ReactNode
}

const widths = { md: 'md:max-w-md', lg: 'md:max-w-2xl', xl: 'md:max-w-3xl' }

function DrawerPanel({ onClose, title, eyebrow, width = 'lg', children, footer }: Omit<DrawerProps, 'open'>) {
  const ref = useRef<HTMLDivElement>(null)
  const titleId = useId()
  useFocusTrap(ref, true, { onEscape: onClose })
  return (
    <div className="fixed inset-0 z-[70]">
      <motion.div
        aria-hidden="true"
        className="absolute inset-0 bg-[rgb(var(--graphite-fixed)/0.36)]"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.2 }}
        onClick={onClose}
      />
      <motion.div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={cx(
          'absolute flex flex-col bg-surface shadow-overlay outline-none ring-1 ring-line',
          'inset-x-0 bottom-0 max-h-[92dvh] rounded-t-panel md:inset-y-0 md:left-auto md:right-0 md:max-h-none md:w-full md:rounded-l-panel md:rounded-tr-none',
          widths[width],
        )}
        initial={{ opacity: 0, x: 48 }}
        animate={{ opacity: 1, x: 0 }}
        exit={{ opacity: 0, x: 48 }}
        transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
      >
        <header className="flex items-start gap-4 border-b border-line px-5 pb-4 pt-5 sm:px-7">
          <div className="min-w-0 flex-1">
            {eyebrow && <p className="ts-eyebrow mb-1.5">{eyebrow}</p>}
            <h2 id={titleId} className="ts-ident text-title-2 text-ink">
              {title}
            </h2>
          </div>
          <IconButton label="Close" size="sm" onClick={onClose} className="-mr-2 -mt-1">
            <X />
          </IconButton>
        </header>
        <div className="ts-scroll-thin min-h-0 flex-1 overflow-y-auto px-5 py-5 sm:px-7">{children}</div>
        {footer && <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-line bg-paper-2/60 px-5 py-4 sm:px-7">{footer}</footer>}
      </motion.div>
    </div>
  )
}

export function Drawer(props: DrawerProps) {
  return createPortal(<AnimatePresence>{props.open && <DrawerPanel key="drawer" {...props} />}</AnimatePresence>, document.body)
}

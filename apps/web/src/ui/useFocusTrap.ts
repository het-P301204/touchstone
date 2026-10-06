/**
 * useFocusTrap(ref, active, { onEscape })
 *
 * While active: moves focus into the container, keeps Tab / Shift+Tab inside,
 * calls onEscape on Esc, locks page scroll, and restores focus to the
 * previously focused element when deactivated.
 */
import { useEffect, useRef } from 'react'
import type { RefObject } from 'react'

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((el) => !el.hasAttribute('inert') && el.getClientRects().length > 0)
}

let scrollLocks = 0

export function useFocusTrap(ref: RefObject<HTMLElement | null>, active: boolean, options: { onEscape?: () => void; initialFocus?: RefObject<HTMLElement | null> } = {}): void {
  const onEscapeRef = useRef(options.onEscape)
  useEffect(() => {
    onEscapeRef.current = options.onEscape
  })
  const initialFocus = options.initialFocus

  useEffect(() => {
    if (!active) return
    const root = ref.current
    if (!root) return
    const previous = document.activeElement as HTMLElement | null
    const raf = requestAnimationFrame(() => {
      const target = initialFocus?.current ?? root
      target.focus({ preventScroll: true })
    })

    scrollLocks++
    const html = document.documentElement
    const prevOverflow = html.style.overflow
    if (scrollLocks === 1) html.style.overflow = 'hidden'

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        onEscapeRef.current?.()
        return
      }
      if (e.key !== 'Tab') return
      const items = focusables(root)
      if (items.length === 0) {
        e.preventDefault()
        root.focus()
        return
      }
      const first = items[0]!
      const last = items[items.length - 1]!
      const activeEl = document.activeElement
      if (e.shiftKey && (activeEl === first || activeEl === root || !root.contains(activeEl))) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && (activeEl === last || !root.contains(activeEl))) {
        e.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKey, true)

    return () => {
      cancelAnimationFrame(raf)
      document.removeEventListener('keydown', onKey, true)
      scrollLocks--
      if (scrollLocks === 0) html.style.overflow = prevOverflow
      if (previous && document.contains(previous)) previous.focus({ preventScroll: true })
    }
  }, [active, ref, initialFocus])
}

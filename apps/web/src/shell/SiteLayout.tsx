/**
 * Public site layout: landing, methodology, goals, "Evidence we cannot see"
 * and the shareable vendor pages. No admin tools here.
 */
import { useEffect, useState } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router'
import { AnimatePresence, motion } from 'motion/react'
import { ArrowUpRight, Menu, X } from 'lucide-react'
import { cx } from '../lib/cx.ts'
import { PLEDGE_SOURCE_URL } from '../lib/core.ts'
import { Wordmark } from '../ui/Mark.tsx'
import { ButtonLink, IconButton } from '../ui/Button.tsx'
import { ThemeToggle } from './ThemeToggle.tsx'
import { GlobalOverlays, useCommandShortcut } from './GlobalOverlays.tsx'
import { SkipLink } from './SkipLink.tsx'

const LINKS = [
  { to: '/methodology', label: 'Methodology' },
  { to: '/goals', label: 'Goals' },
  { to: '/cannot-see', label: 'Evidence we cannot see' },
]

export function SiteLayout() {
  useCommandShortcut()
  const { pathname, hash } = useLocation()
  const [menuOpen, setMenuOpen] = useState(false)
  const [lastPath, setLastPath] = useState(pathname)
  if (pathname !== lastPath) {
    setLastPath(pathname)
    setMenuOpen(false)
  }
  useEffect(() => {
    if (hash) {
      document.getElementById(hash.slice(1))?.scrollIntoView()
      return
    }
    window.scrollTo({ top: 0 })
  }, [pathname, hash])

  return (
    <div className="flex min-h-dvh flex-col bg-paper">
      <SkipLink />
      <header className="sticky top-0 z-40 border-b border-line/80 bg-paper/85 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-page items-center gap-3 px-4 sm:px-6 lg:px-10">
          <Link to="/" className="flex min-w-0 items-center rounded-control py-1" aria-label="TOUCHSTONE home">
            <Wordmark />
          </Link>
          <nav aria-label="Site" className="ml-6 hidden items-center gap-1 md:flex">
            {LINKS.map((l) => (
              <NavLink
                key={l.to}
                to={l.to}
                className={({ isActive }) => cx('rounded-control px-3 py-2 text-sm font-semibold transition-colors', isActive ? 'text-ink' : 'text-ink-2 hover:text-ink')}
              >
                {l.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-1.5">
            <ThemeToggle />
            <ButtonLink to="/app" variant="primary" size="sm" className="hidden sm:inline-flex">
              Explore the Scorecard
            </ButtonLink>
            <IconButton label={menuOpen ? 'Close menu' : 'Open menu'} className="md:hidden" aria-expanded={menuOpen} onClick={() => setMenuOpen((o) => !o)}>
              {menuOpen ? <X /> : <Menu />}
            </IconButton>
          </div>
        </div>
        <AnimatePresence>
          {menuOpen && (
            <motion.nav
              aria-label="Site"
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden border-t border-line md:hidden"
            >
              <ul className="space-y-1 px-4 py-3">
                {[...LINKS, { to: '/app', label: 'Explore the Scorecard' }].map((l) => (
                  <li key={l.to}>
                    <Link to={l.to} className="block rounded-control px-3 py-2.5 font-semibold text-ink hover:bg-paper-2">
                      {l.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </motion.nav>
          )}
        </AnimatePresence>
      </header>
      <main id="main" tabIndex={-1} className="flex-1 outline-none">
        <Outlet />
      </main>
      <SiteFooter />
      <GlobalOverlays />
    </div>
  )
}

function SiteFooter() {
  return (
    <footer className="border-t border-line bg-paper-2/50">
      <div className="mx-auto grid max-w-page gap-8 px-4 py-12 sm:px-6 md:grid-cols-[1.4fr_1fr_1fr] lg:px-10">
        <div className="min-w-0">
          <Wordmark />
          <p className="mt-4 max-w-sm text-sm leading-relaxed text-ink-2">
            Measure the commitment. Not the claim. TOUCHSTONE evaluates publicly available evidence. It does not conduct intrusive testing of vendor infrastructure.
          </p>
        </div>
        <div className="min-w-0">
          <p className="ts-eyebrow mb-3">Read</p>
          <ul className="space-y-2 text-sm">
            <li>
              <Link className="ts-link font-medium" to="/methodology">
                Methodology
              </Link>
            </li>
            <li>
              <Link className="ts-link font-medium" to="/goals">
                The seven goals
              </Link>
            </li>
            <li>
              <Link className="ts-link font-medium" to="/cannot-see">
                Evidence we cannot see
              </Link>
            </li>
          </ul>
        </div>
        <div className="min-w-0">
          <p className="ts-eyebrow mb-3">Source</p>
          <ul className="space-y-2 text-sm">
            <li>
              <a className="ts-link inline-flex items-center gap-1 font-medium" href={PLEDGE_SOURCE_URL} target="_blank" rel="noopener noreferrer">
                CISA Secure by Design Pledge <ArrowUpRight aria-hidden="true" className="size-3.5" />
              </a>
            </li>
            <li>
              <Link className="ts-link font-medium" to="/app/disputes">
                Challenge a finding
              </Link>
            </li>
          </ul>
          <p className="mt-6 text-[0.75rem] leading-relaxed text-ink-3">
            An independent research project. Not affiliated with or endorsed by CISA. A measurement describes observable evidence and should not be interpreted as a
            complete security assessment.
          </p>
        </div>
      </div>
    </footer>
  )
}

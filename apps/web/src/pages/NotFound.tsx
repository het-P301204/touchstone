import { Link, useLocation } from 'react-router'

export function NotFound() {
  const { pathname } = useLocation()
  const inApp = pathname.startsWith('/app')
  return (
    <div className={inApp ? 'py-10' : 'mx-auto max-w-page px-4 py-20 sm:px-6 lg:px-10'}>
      <p className="ts-eyebrow">404</p>
      <h1 className="mt-2 text-title-1">Nothing is published at this address</h1>
      <p className="ts-ident mt-3 font-mono text-sm text-ink-2">{pathname}</p>
      <p className="mt-6 text-sm text-ink-2">
        <Link to={inApp ? '/app' : '/'} className="ts-link">
          {inApp ? 'Back to the overview' : 'Back to the start'}
        </Link>
      </p>
    </div>
  )
}

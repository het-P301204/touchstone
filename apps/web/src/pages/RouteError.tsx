import { isRouteErrorResponse, Link, useRouteError } from 'react-router'
import { Mark } from '../ui/Mark.tsx'

export function RouteError() {
  const error = useRouteError()
  const status = isRouteErrorResponse(error) ? error.status : null
  const message = isRouteErrorResponse(error) ? error.statusText : error instanceof Error ? error.message : 'Unknown error'
  return (
    <div className="mx-auto flex min-h-dvh max-w-2xl flex-col justify-center px-6 py-16">
      <Mark className="size-10" />
      <h1 className="mt-6 text-title-1">{status === 404 ? 'Page not found' : 'This view could not be displayed'}</h1>
      <p className="ts-ident mt-3 font-mono text-sm text-ink-2">{message}</p>
      <p className="mt-6 text-sm text-ink-2">
        <Link to="/" className="ts-link">
          Return to the start
        </Link>{' '}
        or{' '}
        <Link to="/app" className="ts-link">
          open the scorecard
        </Link>
        .
      </p>
    </div>
  )
}

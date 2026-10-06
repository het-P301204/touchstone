import type { ComponentType } from 'react'
import { createBrowserRouter } from 'react-router'
import { SiteLayout } from './shell/SiteLayout.tsx'
import { RouteError } from './pages/RouteError.tsx'
import { Landing } from './pages/Landing.tsx'
import { LoadingState } from './ui/States.tsx'

const basename = import.meta.env.BASE_URL.replace(/\/$/, '') || '/'

function RouteFallback() {
  return (
    <div className="mx-auto max-w-page px-4 py-16 sm:px-6 lg:px-10">
      <LoadingState label="Loading TOUCHSTONE" />
    </div>
  )
}

const page =
  <K extends string>(load: () => Promise<Record<K, ComponentType>>, name: K) =>
  async () => ({ Component: (await load())[name] })

const methodology = page(() => import('./pages/Methodology.tsx'), 'MethodologyPage')
const goals = page(() => import('./pages/Goals.tsx'), 'GoalsIndex')
const goal = page(() => import('./pages/Goals.tsx'), 'GoalDetail')
const cannotSee = page(() => import('./pages/CannotSee.tsx'), 'CannotSee')
const vendor = page(() => import('./pages/app/VendorProfile.tsx'), 'VendorProfile')
const notFound = page(() => import('./pages/NotFound.tsx'), 'NotFound')

export const router = createBrowserRouter(
  [
    {
      element: <SiteLayout />,
      errorElement: <RouteError />,
      hydrateFallbackElement: <RouteFallback />,
      children: [
        { index: true, element: <Landing /> },
        { path: 'methodology', lazy: methodology },
        { path: 'goals', lazy: goals },
        { path: 'goals/:goalId', lazy: goal },
        { path: 'cannot-see', lazy: cannotSee },
        { path: 'vendors/:vendorId', lazy: vendor },
        { path: '*', lazy: notFound },
      ],
    },
    {
      path: 'app',
      lazy: page(() => import('./shell/AppShell.tsx'), 'AppShell'),
      errorElement: <RouteError />,
      hydrateFallbackElement: <RouteFallback />,
      children: [
        { index: true, lazy: page(() => import('./pages/app/Overview.tsx'), 'Overview') },
        { path: 'signatories', lazy: page(() => import('./pages/app/Signatories.tsx'), 'Signatories') },
        { path: 'vendors', lazy: page(() => import('./pages/app/Leaderboard.tsx'), 'Leaderboard') },
        { path: 'vendors/:vendorId', lazy: vendor },
        { path: 'compare', lazy: page(() => import('./pages/app/Compare.tsx'), 'Compare') },
        { path: 'goals', lazy: goals },
        { path: 'goals/:goalId', lazy: goal },
        { path: 'cannot-see', lazy: cannotSee },
        { path: 'evidence', lazy: page(() => import('./pages/app/EvidenceLedger.tsx'), 'EvidenceLedger') },
        { path: 'cves', lazy: page(() => import('./pages/app/CveExplorer.tsx'), 'CveExplorer') },
        { path: 'cves/:cveId', lazy: page(() => import('./pages/app/CveRecordPage.tsx'), 'CveRecordPage') },
        { path: 'graph', lazy: page(() => import('./pages/app/EvidenceGraph.tsx'), 'EvidenceGraphPage') },
        { path: 'trends', lazy: page(() => import('./pages/app/Trends.tsx'), 'Trends') },
        { path: 'cohort', lazy: page(() => import('./pages/app/Cohort.tsx'), 'Cohort') },
        { path: 'runs', lazy: page(() => import('./pages/app/Runs.tsx'), 'Runs') },
        { path: 'methodology', lazy: methodology },
        { path: 'disputes', lazy: page(() => import('./pages/app/Disputes.tsx'), 'Disputes') },
        { path: 'notebook', lazy: page(() => import('./pages/app/Notebook.tsx'), 'Notebook') },
        { path: 'research', lazy: page(() => import('./pages/app/Research.tsx'), 'Research') },
        { path: 'settings', lazy: page(() => import('./pages/app/Settings.tsx'), 'Settings') },
        { path: 'admin', lazy: page(() => import('./pages/app/Admin.tsx'), 'Admin') },
        { path: '*', lazy: notFound },
      ],
    },
  ],
  { basename },
)

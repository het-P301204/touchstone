import { useLocation } from 'react-router'

/** True inside the app shell (/app/*); false on the public site. */
export function useInApp(): boolean {
  return useLocation().pathname.startsWith('/app')
}

/** Link builders that stay inside the current surface (public site vs app). */
export function usePaths() {
  const inApp = useInApp()
  const p = inApp ? '/app' : ''
  return {
    inApp,
    vendor: (id: string) => `${p}/vendors/${encodeURIComponent(id)}`,
    goal: (id: string) => `${p}/goals/${encodeURIComponent(id)}`,
    goals: `${p}/goals`,
    methodology: `${p}/methodology`,
    cannotSee: `${p}/cannot-see`,
  }
}

/**
 * The API's admin bearer token, kept in sessionStorage only (cleared when
 * the tab closes, never written to localStorage or a URL).
 */
const KEY = 'touchstone.adminToken'

export function getAdminToken(): string | null {
  try {
    return window.sessionStorage.getItem(KEY)
  } catch {
    return null
  }
}

export function setAdminToken(token: string | null): void {
  try {
    if (token) window.sessionStorage.setItem(KEY, token)
    else window.sessionStorage.removeItem(KEY)
  } catch {
    /* storage unavailable */
  }
}

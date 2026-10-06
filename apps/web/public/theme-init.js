// Applies the saved theme before first paint so the page never flashes the
// wrong palette. Kept as an external file: the CSP allows no inline script.
// The React app (src/state/ui.ts) owns the preference after startup.
;(function () {
  let pref = 'system'
  try {
    const saved = window.localStorage.getItem('touchstone.theme')
    if (saved === 'light' || saved === 'dark' || saved === 'system') pref = saved
  } catch (e) {
    /* storage unavailable: follow the system */
  }
  const dark = pref === 'dark' || (pref === 'system' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light')
})()

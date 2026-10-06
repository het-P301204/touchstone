import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import type { Plugin } from 'vite'

const repoRoot = fileURLToPath(new URL('../../', import.meta.url))

/**
 * index.html carries the production Content-Security-Policy. The dev server
 * injects an inline React Refresh preamble that a strict `script-src 'self'`
 * would block, so the meta tag is removed while serving and kept in builds.
 */
function devOnlyStripCsp(): Plugin {
  return {
    name: 'touchstone:dev-strip-csp',
    apply: 'serve',
    transformIndexHtml(html) {
      return html.replace(/<meta\s+http-equiv="Content-Security-Policy"[^>]*>\s*/i, '')
    },
  }
}

/**
 * GitHub Pages serves 404.html for unknown paths. Emitting a copy of
 * index.html under that name lets deep links (/touchstone/app/vendors/x)
 * boot the SPA, whose router then resolves the path.
 */
function spaFallback404(): Plugin {
  return {
    name: 'touchstone:spa-404',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const index = bundle['index.html']
      if (index && index.type === 'asset') this.emitFile({ type: 'asset', fileName: '404.html', source: index.source })
    },
  }
}

export default defineConfig(({ mode }) => ({
  base: mode === 'pages' ? '/touchstone/' : '/',
  plugins: [react(), devOnlyStripCsp(), ...(mode === 'pages' ? [spaFallback404()] : [])],
  server: {
    fs: { allow: [repoRoot] },
    proxy: { '/api': { target: 'http://127.0.0.1:8787', changeOrigin: false } },
  },
  build: {
    target: 'es2023',
    // Inlined data: fonts or scripts would violate font-src/script-src 'self'.
    assetsInlineLimit: 0,
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
}))

/**
 * Serves the built web app (apps/web/dist) in --production. Every request path
 * is decoded, resolved, and checked to stay inside the dist directory before
 * anything is read; a path that escapes is answered with 404, never a file.
 */
import { readFileSync, realpathSync, statSync } from 'node:fs'
import { extname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import type { Hono } from 'hono'
import type { Env } from './security.ts'

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.pdf': 'application/pdf',
}

/** Resolve a URL path to a file inside root, or null when it does not exist or would escape. */
export function resolveInside(root: string, urlPath: string): string | null {
  let rel: string
  try {
    rel = decodeURIComponent(urlPath)
  } catch {
    return null
  }
  if (rel.includes('\0')) return null
  // Treat both separators as separators on every platform, then drop leading ones.
  const cleaned = rel.replace(/\\/g, '/').replace(/^\/+/, '')
  // A drive letter or UNC prefix would make resolve() ignore root.
  if (/^[A-Za-z]:/.test(cleaned) || cleaned.startsWith('//')) return null
  const target = resolve(root, cleaned)
  const r = relative(root, target)
  if (r === '' || r.startsWith('..') || isAbsolute(r)) return null
  let st
  try {
    st = statSync(target)
  } catch {
    return null
  }
  if (!st.isFile()) return null
  // A symlink inside dist must not point outside it either.
  const real = realpathSync(target)
  const rr = relative(root, real)
  if (rr.startsWith('..') || isAbsolute(rr)) return null
  return real
}

export function serveStatic(app: Hono<Env>, dist: string): void {
  let root: string
  try {
    root = realpathSync(resolve(dist))
  } catch {
    root = resolve(dist)
  }
  const index = join(root, 'index.html')
  app.on(['GET', 'HEAD'], '*', (c) => {
    const path = new URL(c.req.url).pathname
    let file = resolveInside(root, path)
    if (!file) {
      // A missing asset is a 404; anything else is a client-side route and gets the app shell.
      const ext = extname(path)
      if (ext && ext !== '.html') return c.json({ error: { code: 'NOT_FOUND', message: 'No such file.' } }, 404)
      try {
        statSync(index)
      } catch {
        return c.json({ error: { code: 'WEB_BUILD_MISSING', message: 'The web app has not been built. Run npm run build.' } }, 503)
      }
      file = index
    }
    const isAsset = file.startsWith(join(root, 'assets') + sep)
    c.header('Content-Type', MIME[extname(file).toLowerCase()] ?? 'application/octet-stream')
    c.header('Cache-Control', isAsset ? 'public, max-age=31536000, immutable' : 'no-cache')
    return c.body(new Uint8Array(readFileSync(file)))
  })
}

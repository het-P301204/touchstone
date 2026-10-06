/**
 * TOUCHSTONE API server.
 *   node apps/api/src/index.ts                API only (the web app runs on Vite in development)
 *   node apps/api/src/index.ts --production   also serves the built web app from apps/web/dist
 */
import { serve } from '@hono/node-server'
import { createApp, tryLoadBundle } from './app.ts'
import { ConfigError, loadConfig } from './config.ts'
import { logger } from './security.ts'
import { Store } from './store.ts'

const startedAt = Date.now()
let config
try {
  config = loadConfig()
} catch (e) {
  if (e instanceof ConfigError) {
    console.error(`touchstone-api: ${e.message}`)
    process.exit(1)
  }
  throw e
}
const log = logger(config.logLevel)
if (config.anyHostAllowed) {
  log('warn', {
    operation: 'config',
    warning: `TOUCHSTONE_ALLOWED_HOSTS=* accepts any Host header: DNS-rebinding protection is off${config.host ? ` for HOST=${config.host}` : ''}. Use it only behind a proxy that validates Host.`,
  })
}
const store = new Store(config.dbPath)
const interrupted = store.failInterruptedJobs(new Date().toISOString())
if (interrupted) log('warn', { operation: 'refresh.recover', interruptedJobs: interrupted })

const bundle = tryLoadBundle(config.dataDir, log)
const { app, refresh, seed } = createApp({ store, config, bundle, log, startedAt })
const seeded = seed()
if (seeded.disputes.skipped.some((s) => s.reason !== 'already present')) {
  log('warn', { operation: 'seed.disputes', skipped: seeded.disputes.skipped.filter((s) => s.reason !== 'already present') })
}

const server = serve({ fetch: app.fetch, port: config.port, hostname: config.host }, (info) => {
  log('info', {
    operation: 'listen',
    url: `http://${config.host.includes(':') ? `[${config.host}]` : config.host}:${info.port}`,
    production: config.production,
    refreshMode: config.mode,
    networkCollection: config.mode === 'live',
    data: bundle ? { dir: config.dataDir, mode: bundle.index.mode, runs: bundle.index.runs.length, latestRunId: bundle.latestRunId } : null,
    db: store.mode,
    seededDisputes: seeded.disputes.inserted.length,
    seededNotebook: seeded.notebook,
    adminEnabled: config.adminToken !== null,
    webDist: config.production ? config.webDist : null,
  })
})

let stopping = false
const shutdown = (signal: string) => {
  if (stopping) return
  stopping = true
  log('info', { operation: 'shutdown', signal })
  const force = setTimeout(() => process.exit(1), 10_000)
  force.unref()
  server.close(() => {
    void refresh.idle().finally(() => {
      store.close()
      process.exit(0)
    })
  })
}
process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))

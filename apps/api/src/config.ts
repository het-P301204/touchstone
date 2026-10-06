/**
 * Configuration comes only from the environment (documented in .env.example)
 * and the --production flag. It is validated once at start; a bad value stops
 * the server with a message naming the variable, never a stack trace.
 *
 * TOUCHSTONE holds one secret: the optional TOUCHSTONE_ADMIN_TOKEN. It is never
 * logged and never defaulted. Without it every administrative endpoint answers
 * 403 "administration disabled".
 */
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'

/** Repository root, so every entry point (npm start, dev:api, tests, CLI) shares one layout. */
export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

export const API_VERSION = '0.1.0'

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent'
export type DataMode = 'demo' | 'live'

export type Config = {
  production: boolean
  port: number
  host: string
  /** Published bundle directory (index.json, runs/, inputs/, history.json, ...). */
  dataDir: string
  /** SQLite database file, or ":memory:". Holds disputes, the notebook and refresh jobs. */
  dbPath: string
  /** Raw demo fixtures replayed by a DEMO refresh. */
  demoFixturesDir: string
  mode: DataMode
  /** Live collection only: vendor registry file and snapshot output directory. */
  liveRegistry: string | null
  liveOutDir: string
  adminToken: string | null
  trustProxy: boolean
  /** Origins that get CORS headers. Empty (the default) means CORS is off. */
  corsOrigins: string[]
  /** Host header values accepted (DNS-rebinding protection). Empty means any host (only with an explicit "*"). */
  allowedHosts: string[]
  /** True when TOUCHSTONE_ALLOWED_HOSTS=* was set explicitly: the Host check is off (logged as a warning at start). */
  anyHostAllowed: boolean
  rateLimitPerMinute: number
  disputeRateLimitPerHour: number
  reproduceRateLimitPerHour: number
  /** Server-wide ceilings, whatever the client address. */
  disputeGlobalLimitPerHour: number
  reproduceGlobalLimitPerHour: number
  /** Reproductions waiting behind the one in flight before new ones get 429. */
  reproduceQueueLimit: number
  maxBodyBytes: number
  logLevel: LogLevel
  webDist: string
}

export class ConfigError extends Error {}

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]'])
export const isLoopback = (host: string): boolean => LOOPBACK.has(host.toLowerCase())

const list = (raw: string | undefined): string[] =>
  (raw ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

const intVar = (min: number, max: number, fallback: number) =>
  z
    .string()
    .trim()
    .optional()
    .transform((s, ctx) => {
      if (s === undefined || s === '') return fallback
      const n = Number(s)
      if (!Number.isInteger(n) || n < min || n > max) {
        ctx.addIssue({ code: 'custom', message: `must be an integer between ${min} and ${max}` })
        return z.NEVER
      }
      return n
    })

const boolVar = z
  .string()
  .trim()
  .toLowerCase()
  .optional()
  .transform((s, ctx) => {
    if (s === undefined || s === '' || s === 'false' || s === '0') return false
    if (s === 'true' || s === '1') return true
    ctx.addIssue({ code: 'custom', message: 'must be true or false' })
    return z.NEVER
  })

const EnvSchema = z.object({
  HOST: z.string().trim().min(1).optional(),
  PORT: intVar(0, 65535, 8787),
  NODE_ENV: z.string().optional(),
  TOUCHSTONE_DATA_DIR: z.string().trim().min(1).optional(),
  TOUCHSTONE_DB: z.string().trim().min(1).optional(),
  TOUCHSTONE_DEMO_FIXTURES: z.string().trim().min(1).optional(),
  TOUCHSTONE_MODE: z
    .string()
    .trim()
    .toLowerCase()
    .optional()
    .pipe(z.enum(['demo', 'live']).optional()),
  TOUCHSTONE_LIVE_REGISTRY: z.string().trim().min(1).optional(),
  TOUCHSTONE_LIVE_OUT: z.string().trim().min(1).optional(),
  TOUCHSTONE_ADMIN_TOKEN: z
    .string()
    .trim()
    .optional()
    .refine((s) => s === undefined || s === '' || s.length >= 24, 'must be at least 24 characters (use a long random value)'),
  TOUCHSTONE_TRUST_PROXY: boolVar,
  TOUCHSTONE_CORS_ORIGINS: z
    .string()
    .optional()
    .transform((s) => list(s))
    .pipe(z.array(z.url({ protocol: /^https?$/ }).refine((u) => new URL(u).origin === u, 'must be an origin like https://example.org (no path)'))),
  TOUCHSTONE_ALLOWED_HOSTS: z.string().optional(),
  TOUCHSTONE_RATE_LIMIT_PER_MINUTE: intVar(1, 100_000, 300),
  TOUCHSTONE_DISPUTE_RATE_LIMIT_PER_HOUR: intVar(1, 10_000, 10),
  TOUCHSTONE_REPRODUCE_RATE_LIMIT_PER_HOUR: intVar(1, 10_000, 30),
  TOUCHSTONE_DISPUTE_GLOBAL_LIMIT_PER_HOUR: intVar(1, 1_000_000, 200),
  TOUCHSTONE_REPRODUCE_GLOBAL_LIMIT_PER_HOUR: intVar(1, 1_000_000, 120),
  TOUCHSTONE_REPRODUCE_QUEUE_LIMIT: intVar(0, 100, 4),
  TOUCHSTONE_MAX_BODY_BYTES: intVar(1024, 1024 * 1024, 32 * 1024),
  TOUCHSTONE_LOG_LEVEL: z
    .string()
    .trim()
    .toLowerCase()
    .optional()
    .pipe(z.enum(['debug', 'info', 'warn', 'error', 'silent']).optional()),
  TOUCHSTONE_WEB_DIST: z.string().trim().min(1).optional(),
})

export function loadConfig(env: NodeJS.ProcessEnv = process.env, argv: string[] = process.argv): Config {
  const parsed = EnvSchema.safeParse(env)
  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => `${i.path.join('.') || 'environment'}: ${i.message}`)
    throw new ConfigError(`Invalid configuration:\n  ${lines.join('\n  ')}`)
  }
  const e = parsed.data
  const host = e.HOST ?? '127.0.0.1'
  const mode: DataMode = e.TOUCHSTONE_MODE ?? 'demo'
  const hostsEnv = (e.TOUCHSTONE_ALLOWED_HOSTS ?? '').trim()
  const anyHostAllowed = hostsEnv === '*'
  let allowedHosts: string[]
  if (anyHostAllowed) allowedHosts = []
  else if (hostsEnv !== '') allowedHosts = list(hostsEnv).map((h) => h.toLowerCase())
  else if (isLoopback(host)) allowedHosts = ['127.0.0.1', 'localhost', '[::1]']
  else {
    // Fail closed: without a Host allowlist a LAN- or internet-bound server is open to DNS rebinding.
    throw new ConfigError(
      `Invalid configuration:\n  TOUCHSTONE_ALLOWED_HOSTS: required when HOST=${host} is not a loopback address (DNS-rebinding protection). ` +
        'List the host names clients use (e.g. touchstone.example.org,localhost), or set it to * to accept any Host explicitly.',
    )
  }
  const db = e.TOUCHSTONE_DB ?? '.data/touchstone.db'
  const config: Config = {
    production: argv.includes('--production') || e.NODE_ENV === 'production',
    port: e.PORT,
    host,
    dataDir: resolve(REPO_ROOT, e.TOUCHSTONE_DATA_DIR ?? 'apps/web/public/data'),
    dbPath: db === ':memory:' || db === 'memory' ? ':memory:' : resolve(REPO_ROOT, db),
    demoFixturesDir: resolve(REPO_ROOT, e.TOUCHSTONE_DEMO_FIXTURES ?? 'fixtures/demo'),
    mode,
    liveRegistry: e.TOUCHSTONE_LIVE_REGISTRY ? resolve(REPO_ROOT, e.TOUCHSTONE_LIVE_REGISTRY) : null,
    liveOutDir: resolve(REPO_ROOT, e.TOUCHSTONE_LIVE_OUT ?? '.touchstone/live'),
    adminToken: e.TOUCHSTONE_ADMIN_TOKEN ? e.TOUCHSTONE_ADMIN_TOKEN : null,
    trustProxy: e.TOUCHSTONE_TRUST_PROXY,
    corsOrigins: e.TOUCHSTONE_CORS_ORIGINS,
    allowedHosts,
    anyHostAllowed,
    rateLimitPerMinute: e.TOUCHSTONE_RATE_LIMIT_PER_MINUTE,
    disputeRateLimitPerHour: e.TOUCHSTONE_DISPUTE_RATE_LIMIT_PER_HOUR,
    reproduceRateLimitPerHour: e.TOUCHSTONE_REPRODUCE_RATE_LIMIT_PER_HOUR,
    disputeGlobalLimitPerHour: e.TOUCHSTONE_DISPUTE_GLOBAL_LIMIT_PER_HOUR,
    reproduceGlobalLimitPerHour: e.TOUCHSTONE_REPRODUCE_GLOBAL_LIMIT_PER_HOUR,
    reproduceQueueLimit: e.TOUCHSTONE_REPRODUCE_QUEUE_LIMIT,
    maxBodyBytes: e.TOUCHSTONE_MAX_BODY_BYTES,
    logLevel: e.TOUCHSTONE_LOG_LEVEL ?? 'info',
    webDist: resolve(REPO_ROOT, e.TOUCHSTONE_WEB_DIST ?? 'apps/web/dist'),
  }
  if (config.mode === 'live' && !config.liveRegistry) {
    throw new ConfigError('Invalid configuration:\n  TOUCHSTONE_LIVE_REGISTRY: required when TOUCHSTONE_MODE=live (the vendor registry file to collect for)')
  }
  return config
}

/** Defaults for tests: in-memory database, silent logs, any Host accepted. */
export function testConfig(overrides: Partial<Config> = {}): Config {
  return { ...loadConfig({ TOUCHSTONE_DB: ':memory:', TOUCHSTONE_LOG_LEVEL: 'silent' }, []), allowedHosts: [], ...overrides }
}

/**
 * Live collection orchestrator: public sources -> snapshots -> RunInputs.
 *
 * For each requested vendor: security.txt, the policy page (robots.txt
 * respected), CSAF advisories, and CVE records (ids given by the caller
 * and/or enumerated from NVD by the vendor's CNA org id). Every fetch is a
 * recorded snapshot. A failed fetch is a FAILED snapshot; when an earlier
 * good snapshot exists, the FAILED snapshot names it in `substitutedBy` and
 * the observation carries `carriedFromSnapshotId`. Nothing is substituted
 * silently.
 */

import { readFileSync } from 'node:fs'
import type { Advisory, CveRecord, RunInputs, Snapshot, SourceRef, VdpObservation, Vendor } from '../../core/src/model/index.ts'
import { CURRENT_METHODOLOGY_VERSION, methodologyVersion } from '../../core/src/methodology/versions.ts'
import { matchSignatories } from '../../core/src/identity/index.ts'
import { assessVdp } from '../../core/src/vdp/assess.ts'
import { CVE_ID_PATTERN } from '../../core/src/normalize/cve.ts'
import { CISA_SIGNERS_SOURCE, collectSignerList } from './collectors/cisa-signers.ts'
import { collectCsaf, csafSource } from './collectors/csaf.ts'
import { CVE_RECORD_SOURCE, collectCveRecord } from './collectors/cve-records.ts'
import { NVD_MIN_INTERVAL_MS, NVD_SOURCE, enumerateNvdCveIds } from './collectors/nvd-enumerate.ts'
import { collectSecurityTxt, securityTxtSource } from './collectors/security-txt.ts'
import { collectVdpPolicy, robotsSource, vdpSource } from './collectors/vdp-policy.ts'
import type { CollectContext, Fetcher } from './collectors/common.ts'
import { HostRateLimiter } from './safe-fetch.ts'
import type { SafeFetchOptions } from './safe-fetch.ts'
import { SnapshotStore } from './store.ts'

export type CollectLiveOptions = {
  vendorIds: string[]
  /** Path of a vendors.json registry (Vendor[]). */
  registryPath: string
  /** Snapshot store root (snapshots under <outDir>/snapshots). */
  outDir: string
  asOf?: string
  methodologyVersion?: string
  /** Explicit CVE ids per vendor id. */
  cveIds?: Record<string, string[]>
  /** Enumerate CVE ids from NVD by CNA org id (slow without a key: one request per 6.5 s). */
  enumerateNvd?: boolean
  maxCvesPerVendor?: number
  maxAdvisoriesPerVendor?: number
  /** Injected for tests; defaults to safeFetch. */
  fetcher?: Fetcher
  fetchDefaults?: Partial<SafeFetchOptions>
  now?: () => Date
}

export type CollectLiveResult = RunInputs & { errors: string[] }

export async function collectLive(opts: CollectLiveOptions): Promise<CollectLiveResult> {
  const now = opts.now ?? (() => new Date())
  const asOf = opts.asOf ?? now().toISOString()
  const mvId = opts.methodologyVersion ?? CURRENT_METHODOLOGY_VERSION
  const mv = methodologyVersion(mvId)
  const registry = JSON.parse(readFileSync(opts.registryPath, 'utf8')) as Vendor[]
  const unknown = opts.vendorIds.filter((id) => !registry.some((v) => v.id === id))
  if (unknown.length > 0) throw new Error(`Unknown vendor id(s): ${unknown.join(', ')}`)
  const vendors = registry.filter((v) => opts.vendorIds.includes(v.id)).map((v) => ({ ...v, synthetic: false }))

  const limiter = new HostRateLimiter(1_000)
  const nvdLimiter = new HostRateLimiter(NVD_MIN_INTERVAL_MS)
  const ctx: CollectContext = {
    store: new SnapshotStore(opts.outDir),
    fetchDefaults: { rateLimiter: limiter, ...opts.fetchDefaults, ...(opts.now ? { now: opts.now } : {}) },
    parserVersion: mv.parserVersion,
    ...(opts.fetcher ? { fetcher: opts.fetcher } : {}),
  }
  const nvdCtx: CollectContext = { ...ctx, fetchDefaults: { ...ctx.fetchDefaults, rateLimiter: nvdLimiter } }

  const snapshots: Snapshot[] = []
  const sources: SourceRef[] = [CISA_SIGNERS_SOURCE, CVE_RECORD_SOURCE]
  const errors: string[] = []
  const cves: CveRecord[] = []
  const advisories: Advisory[] = []
  const vdp: VdpObservation[] = []

  // Signer list.
  const signers = await collectSignerList(ctx)
  snapshots.push(...signers.snapshots)
  let signatoryList: RunInputs['signatoryList']
  if (signers.parsed) {
    const { matched } = matchSignatories(signers.parsed.names, vendors)
    const listed = new Set(matched.map((m) => m.vendorId))
    for (const v of vendors) v.signatoryStatus = listed.has(v.id) ? 'LISTED' : 'NOT_LISTED'
    signatoryList = { declaredCount: signers.parsed.declaredCount, parsedCount: signers.parsed.names.length, warnings: signers.parsed.warnings }
    if (signers.used) signatoryList.snapshotId = signers.used.id
  } else {
    for (const v of vendors) v.signatoryStatus = 'UNKNOWN'
    errors.push(`signer list: ${signers.error ?? 'unavailable'}`)
  }

  const windowStart = new Date(Date.parse(asOf) - mv.parameters.cveWindowDays * 86_400_000).toISOString()
  for (const v of vendors) {
    // Each vendor is isolated: one malformed feed or record is an error entry, not an aborted run.
    try {
      // security.txt and policy.
      const stxt = await collectSecurityTxt(ctx, v, asOf)
      snapshots.push(...stxt.snapshots)
      sources.push(securityTxtSource(v))
      const pol = await collectVdpPolicy(ctx, v, stxt.securityTxt)
      snapshots.push(...pol.snapshots)
      if (pol.policy.url) {
        sources.push(vdpSource(v, pol.policy.url))
        const host = new URL(pol.policy.url).hostname
        if (pol.snapshots.some((s) => s.sourceId === robotsSource(host).id)) sources.push(robotsSource(host))
      }
      if (pol.note) errors.push(`${v.id} policy: ${pol.note}`)
      const obs = assessVdp({ vendorId: v.id, observedAt: pol.observedAt ?? stxt.observedAt ?? asOf, asOf, securityTxt: stxt.securityTxt, policy: pol.policy, params: mv.parameters })
      if (pol.carriedFromSnapshotId) obs.carriedFromSnapshotId = pol.carriedFromSnapshotId
      vdp.push(obs)

      // CSAF.
      if (v.csafProviderUrl) {
        sources.push(csafSource(v))
        const c = await collectCsaf(ctx, v, { maxAdvisories: opts.maxAdvisoriesPerVendor ?? 100 })
        snapshots.push(...c.snapshots)
        advisories.push(...c.advisories)
        errors.push(...c.errors.map((e) => `${v.id} csaf: ${e}`))
      }

      // CVE ids.
      const ids = new Set(opts.cveIds?.[v.id] ?? [])
      if (opts.enumerateNvd) {
        const orgIds = v.aliases.filter((a) => a.kind === 'CNA_ORG_ID').map((a) => a.value)
        for (const orgId of orgIds) {
          if (!sources.includes(NVD_SOURCE)) sources.push(NVD_SOURCE)
          const e = await enumerateNvdCveIds(nvdCtx, { sourceIdentifier: orgId, from: windowStart, to: asOf })
          snapshots.push(...e.snapshots)
          for (const id of e.ids) ids.add(id)
          errors.push(...e.errors.map((x) => `${v.id} nvd: ${x}`))
        }
      }
      // A cap shrinks the denominator of every CVE metric, so it is never silent.
      const cap = opts.maxCvesPerVendor ?? 500
      if (ids.size > cap) {
        errors.push(`${v.id}: collected ${cap} of ${ids.size} candidate CVE ids (cap reached); CVE metrics describe this sample, not the full window`)
      }
      // CVE ids referenced by this vendor's advisories are always fetched, even beyond the cap:
      // an uncollected CVE must never be read as an absent one.
      const referenced = new Set(advisories.filter((a) => a.vendorId === v.id).flatMap((a) => a.cveIds).filter((id) => CVE_ID_PATTERN.test(id)))
      const sampled = [...ids].filter((id) => !referenced.has(id)).sort().slice(0, Math.max(0, cap - referenced.size))
      for (const id of [...new Set([...referenced, ...sampled])].sort()) {
        const r = await collectCveRecord(ctx, id)
        snapshots.push(...r.snapshots)
        if (r.record) cves.push(r.record)
        else errors.push(`${id}: ${r.error ?? 'unavailable'}`)
      }
  
    } catch (err) {
      errors.push(`${v.id}: collection stopped for this vendor: ${err instanceof Error ? err.message.slice(0, 300) : String(err)}`)
    }
  }

  const byId = <T extends { id: string }>(a: T, b: T) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
  const uniqueSnapshots = [...new Map(snapshots.map((s) => [s.id, s])).values()].sort(byId)
  const uniqueSources = [...new Map(sources.map((s) => [s.id, s])).values()].sort(byId)

  const result: CollectLiveResult = {
    mode: 'LIVE',
    datasetVersion: asOf.slice(0, 10),
    asOf,
    methodologyVersion: mvId,
    vendors: vendors.sort(byId),
    cves: cves.sort(byId),
    advisories: advisories.sort(byId),
    vdp,
    previousVdp: [],
    snapshots: uniqueSnapshots,
    sources: uniqueSources,
    history: [],
    errors,
  }
  if (signatoryList) result.signatoryList = signatoryList
  return result
}

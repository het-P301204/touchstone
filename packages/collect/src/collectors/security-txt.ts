/** RFC 9116 security.txt from a vendor domain (/.well-known/ first, then the legacy root path). */

import type { SecurityTxt, Snapshot, SourceRef, Vendor } from '../../../core/src/model/index.ts'
import { parseSecurityTxt } from '../../../core/src/normalize/security-txt.ts'
import { decodeUtf8, fetchToSnapshot } from './common.ts'
import type { CollectContext } from './common.ts'

export function securityTxtSource(vendor: Vendor): SourceRef {
  return {
    id: `vendor.${vendor.id}.security-txt`,
    family: 'SECURITY_TXT',
    title: `${vendor.canonicalName} security.txt`,
    url: `https://${vendor.domains[0] ?? ''}/.well-known/security.txt`,
    publisher: vendor.canonicalName,
    attribution: 'Vendor-published security.txt (RFC 9116).',
    retention: 'RAW',
  }
}

export async function collectSecurityTxt(ctx: CollectContext, vendor: Vendor, asOf: string): Promise<{ snapshots: Snapshot[]; securityTxt: SecurityTxt; observedAt?: string }> {
  const domain = vendor.domains[0]
  const absent = (url: string, warning: string): SecurityTxt => ({ present: false, url, contacts: [], policyUrls: [], canonical: [], warnings: [warning], signed: false })
  if (!domain) return { snapshots: [], securityTxt: absent('', 'NOT_COLLECTED: the vendor has no registered domain.') }
  const src = securityTxtSource(vendor)
  const snapshots: Snapshot[] = []
  for (const url of [`https://${domain}/.well-known/security.txt`, `https://${domain}/security.txt`]) {
    const r = await fetchToSnapshot(ctx, { sourceId: src.id, url, allowHosts: [domain], allowedContentTypes: ['text/plain'], retention: 'RAW', maxBytes: 64 * 1024 })
    snapshots.push(...r.snapshots)
    if (r.absent) continue
    if (!r.body || !r.used) {
      const s = absent(url, `FETCH_FAILED: ${r.error ?? 'no content'}`)
      s.snapshotId = r.snapshots[0]!.id
      return { snapshots, securityTxt: s, observedAt: r.snapshots[0]!.fetchedAt }
    }
    return { snapshots, securityTxt: parseSecurityTxt(decodeUtf8(r.body), { url, snapshotId: r.used.id, asOf }), observedAt: r.used.fetchedAt }
  }
  const s = absent(`https://${domain}/.well-known/security.txt`, 'NOT_FOUND: no security.txt at /.well-known/security.txt or /security.txt.')
  s.snapshotId = snapshots[0]!.id
  return { snapshots, securityTxt: s, observedAt: snapshots[0]!.fetchedAt }
}

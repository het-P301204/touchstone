/** CISA Secure by Design Pledge signer list. */

import type { Snapshot, SourceRef } from '../../../core/src/model/index.ts'
import { parseSignerList } from '../../../core/src/normalize/signers.ts'
import { decodeUtf8, fetchToSnapshot } from './common.ts'
import type { CollectContext } from './common.ts'

export const CISA_SIGNERS_URL = 'https://www.cisa.gov/securebydesign/pledge/secure-design-pledge-signers'

export const CISA_SIGNERS_SOURCE: SourceRef = {
  id: 'cisa.signers',
  family: 'CISA_PLEDGE',
  title: 'CISA Secure by Design Pledge signers',
  url: CISA_SIGNERS_URL,
  publisher: 'Cybersecurity and Infrastructure Security Agency',
  attribution: 'Public U.S. government web page (cisa.gov).',
  retention: 'RAW',
}

export async function collectSignerList(ctx: CollectContext): Promise<{
  snapshots: Snapshot[]
  used?: Snapshot
  carried: boolean
  parsed?: ReturnType<typeof parseSignerList>
  error?: string
}> {
  const r = await fetchToSnapshot(ctx, {
    sourceId: CISA_SIGNERS_SOURCE.id,
    url: CISA_SIGNERS_URL,
    allowHosts: ['www.cisa.gov'],
    allowedContentTypes: ['text/html'],
    retention: 'RAW',
    maxBytes: 3 * 1024 * 1024,
  })
  const out: Awaited<ReturnType<typeof collectSignerList>> = { snapshots: r.snapshots, carried: r.carried }
  if (r.used) out.used = r.used
  if (r.error) out.error = r.error
  if (r.body) out.parsed = parseSignerList(decodeUtf8(r.body))
  return out
}

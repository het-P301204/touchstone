/**
 * Snapshot ids: "SN-" + first 12 hex of sha256 over (sourceId, url, content
 * sha256). A failed fetch has no content; its id is computed over the
 * failure marker and the attempt time so that each failed attempt is a
 * distinct, recorded snapshot.
 */

import { shortHash } from '../util/sha256.ts'

export function snapshotId(sourceId: string, url: string, contentSha256: string): string {
  return `SN-${shortHash(`${sourceId}\n${url}\n${contentSha256}`)}`
}

export function failedSnapshotId(sourceId: string, url: string, attemptedAt: string): string {
  return snapshotId(sourceId, url, `FAILED@${attemptedAt}`)
}

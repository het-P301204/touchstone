/**
 * Content-addressed snapshot store.
 *
 *   <root>/snapshots/<sha256>        raw bytes (RAW retention only)
 *   <root>/snapshots/index.jsonl     one Snapshot per line, append-only
 *
 * The default root is ".touchstone". Raw files are written atomically
 * (temp file + rename) and never overwritten: the name is the content hash.
 * Reads re-hash the bytes, so a modified file is detected, not trusted.
 * For EXTRACT_ONLY sources (third-party policy pages) only the hash and the
 * Snapshot record are kept; the caller keeps the extracted fields.
 */

import { createHash, randomBytes } from 'node:crypto'
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { RetentionMode, Snapshot, SnapshotStatus } from '../../core/src/model/index.ts'
import { failedSnapshotId, snapshotId } from '../../core/src/normalize/snapshot-id.ts'

export const DEFAULT_STORE_ROOT = '.touchstone'
const SHA = /^[0-9a-f]{64}$/

export class SnapshotStore {
  root: string
  dir: string
  constructor(root: string = DEFAULT_STORE_ROOT) {
    this.root = root
    this.dir = join(root, 'snapshots')
    mkdirSync(this.dir, { recursive: true })
  }

  /** Store raw bytes; returns their sha256 and the path relative to the store root. */
  put(bytes: Uint8Array): { sha256: string; rawPath: string } {
    const sha256 = createHash('sha256').update(bytes).digest('hex')
    const path = join(this.dir, sha256)
    if (!existsSync(path)) {
      const tmp = join(this.dir, `.tmp-${randomBytes(6).toString('hex')}`)
      writeFileSync(tmp, bytes)
      renameSync(tmp, path)
    }
    return { sha256, rawPath: `snapshots/${sha256}` }
  }

  /** Read raw bytes by hash, verifying the content. */
  get(sha256: string): Uint8Array | null {
    if (!SHA.test(sha256)) throw new Error(`not a sha256: ${sha256}`)
    const path = join(this.dir, sha256)
    if (!existsSync(path)) return null
    const bytes = readFileSync(path)
    const actual = createHash('sha256').update(bytes).digest('hex')
    if (actual !== sha256) throw new Error(`snapshot ${sha256} is corrupt (content hashes to ${actual})`)
    return new Uint8Array(bytes)
  }

  /** Record a successful (or rejected) fetch. Raw bytes are kept only for RAW retention. */
  record(input: {
    sourceId: string
    url: string
    fetchedAt: string
    body: Uint8Array
    retention: RetentionMode
    parserVersion: string
    httpStatus?: number
    contentType?: string
    status?: Extract<SnapshotStatus, 'OK' | 'REJECTED'>
    error?: string
  }): Snapshot {
    let sha256: string
    let rawPath: string | undefined
    if (input.retention === 'RAW') {
      const put = this.put(input.body)
      sha256 = put.sha256
      rawPath = put.rawPath
    } else {
      sha256 = createHash('sha256').update(input.body).digest('hex')
    }
    const s: Snapshot = {
      id: snapshotId(input.sourceId, input.url, sha256),
      sourceId: input.sourceId,
      url: input.url,
      fetchedAt: input.fetchedAt,
      status: input.status ?? 'OK',
      sha256,
      bytes: input.body.byteLength,
      parserVersion: input.parserVersion,
    }
    if (rawPath) s.rawPath = rawPath
    if (input.httpStatus !== undefined) s.httpStatus = input.httpStatus
    if (input.contentType !== undefined) s.contentType = input.contentType
    if (input.error !== undefined) s.error = input.error
    this.append(s)
    return s
  }

  /** Record a failed attempt. When an earlier good snapshot is used instead, name it in substitutedBy. */
  recordFailure(input: { sourceId: string; url: string; fetchedAt: string; error: string; parserVersion: string; httpStatus?: number; substitutedBy?: string }): Snapshot {
    const s: Snapshot = {
      id: failedSnapshotId(input.sourceId, input.url, input.fetchedAt),
      sourceId: input.sourceId,
      url: input.url,
      fetchedAt: input.fetchedAt,
      status: 'FAILED',
      error: input.error,
      parserVersion: input.parserVersion,
    }
    if (input.httpStatus !== undefined) s.httpStatus = input.httpStatus
    if (input.substitutedBy !== undefined) s.substitutedBy = input.substitutedBy
    this.append(s)
    return s
  }

  /**
   * Keep the extracted text of a snapshot (for EXTRACT_ONLY sources, the
   * only content retained), so a later failed fetch can carry it forward.
   */
  putExtract(snapshotIdValue: string, text: string): void {
    if (!/^SN-[0-9a-f]{12}$/.test(snapshotIdValue)) throw new Error(`not a snapshot id: ${snapshotIdValue}`)
    const dir = join(this.root, 'extracts')
    mkdirSync(dir, { recursive: true })
    const path = join(dir, `${snapshotIdValue}.txt`)
    // Exclusive create: content-addressed, so an existing file already holds this text.
    try {
      writeFileSync(path, text, { flag: 'wx' })
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e
    }
  }

  getExtract(snapshotIdValue: string): string | null {
    if (!/^SN-[0-9a-f]{12}$/.test(snapshotIdValue)) return null
    const path = join(this.root, 'extracts', `${snapshotIdValue}.txt`)
    try {
      return readFileSync(path, 'utf8')
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw e
    }
  }

  private append(s: Snapshot): void {
    appendFileSync(join(this.dir, 'index.jsonl'), JSON.stringify(s) + '\n')
  }

  /** Every recorded snapshot, oldest first. Malformed lines are skipped. */
  list(): Snapshot[] {
    const path = join(this.dir, 'index.jsonl')
    if (!existsSync(path)) return []
    const out: Snapshot[] = []
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      if (line.trim().length === 0) continue
      try {
        out.push(JSON.parse(line) as Snapshot)
      } catch {
        // a torn final line from an interrupted write
      }
    }
    return out
  }

  /** The most recent OK snapshot for a source and URL (the substitution candidate after a failure). */
  latestOk(sourceId: string, url: string): Snapshot | undefined {
    let best: Snapshot | undefined
    for (const s of this.list()) {
      if (s.sourceId !== sourceId || s.url !== url || s.status !== 'OK') continue
      if (!best || s.fetchedAt > best.fetchedAt) best = s
    }
    return best
  }
}

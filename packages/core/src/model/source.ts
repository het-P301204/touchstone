/**
 * Sources and snapshots. Every measurement in TOUCHSTONE traces back to a
 * snapshot: an immutable, content-addressed copy (or, where retention is not
 * appropriate, a hash plus extracted fields) of what a public source returned
 * at a specific time.
 */

export type SourceFamily =
  | 'CISA_PLEDGE' // CISA Secure by Design Pledge signer list and pledge text
  | 'CVE_PROGRAM' // CVE JSON 5.x records (cveawg.mitre.org / CVEProject/cvelistV5)
  | 'NVD' // NVD CVE API 2.0 (used only to enumerate candidate CVE ids)
  | 'VENDOR_ADVISORY' // vendor CSAF 2.0 advisories / PSIRT feeds
  | 'VENDOR_VDP' // vendor vulnerability disclosure policy page
  | 'SECURITY_TXT' // RFC 9116 /.well-known/security.txt

/** How long TOUCHSTONE retains the raw bytes of a snapshot. */
export type RetentionMode =
  | 'RAW' // raw bytes stored (public-domain or permissively licensed source)
  | 'EXTRACT_ONLY' // only hash + extracted fields stored (third-party policy pages)

export type SourceRef = {
  id: string // stable, e.g. "cisa.signers", "cve.record", "vendor.northwind.vdp"
  family: SourceFamily
  title: string
  /** Canonical URL of the source (for a per-record source, the URL template). */
  url: string
  publisher: string
  /** Short attribution / licence note shown next to evidence. */
  attribution: string
  retention: RetentionMode
}

export type SnapshotStatus =
  | 'OK'
  | 'FAILED' // fetch failed; see `error`; no content
  | 'REJECTED' // fetched but rejected by validation (size, content-type, parse)

export type Snapshot = {
  /** "SN-" + first 12 hex of sha256 over (sourceId, url, sha256 of content). */
  id: string
  sourceId: string
  url: string
  /** ISO-8601 UTC. Supplied by the collector, never read by the engine. */
  fetchedAt: string
  status: SnapshotStatus
  httpStatus?: number
  contentType?: string
  /** sha256 hex of the raw bytes. Present when status is OK. */
  sha256?: string
  bytes?: number
  /** Path of raw content relative to the snapshot store, when retained. */
  rawPath?: string
  error?: string
  parserVersion: string
  /**
   * When a refresh failed and an earlier snapshot is used instead, the run
   * records the substitution explicitly here: the failed attempt is kept and
   * this field names the snapshot actually used. Never silent.
   */
  substitutedBy?: string
}

export type FreshnessState = 'CURRENT' | 'AGING' | 'STALE' | 'UNKNOWN'

export type SourceFreshness = {
  sourceId: string
  title: string
  family: SourceFamily
  /** Last time a fetch was attempted. */
  lastAttemptAt?: string
  /** Last time a fetch succeeded. Freshness is computed from this, never from lastAttemptAt. */
  lastSuccessAt?: string
  lastStatus?: SnapshotStatus
  /** Snapshot used by the run (may be older than the last attempt after a failure). */
  usedSnapshotId?: string
  ageHours?: number
  state: FreshnessState
  note?: string
}

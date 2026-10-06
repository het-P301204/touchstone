/**
 * IP address classification for outbound requests.
 *
 * Only globally routable unicast addresses are acceptable destinations.
 * IPv4 is parsed strictly (four decimal octets; no octal, hex or shorthand
 * forms). IPv6 is parsed to 16 bytes; anything outside 2000::/3 is rejected,
 * and within it the documentation, Teredo, 6to4, ORCHID and benchmarking
 * ranges are rejected too. IPv4-mapped (::ffff:0:0/96), IPv4-compatible
 * (::/96) and NAT64 (64:ff9b::/96, 64:ff9b:1::/48) addresses are rejected
 * outright: they reach IPv4 space by another name.
 */

export function parseIPv4(s: string): number[] | null {
  const parts = s.split('.')
  if (parts.length !== 4) return null
  const out: number[] = []
  for (const p of parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(p)) return null
    const n = Number(p)
    if (n > 255) return null
    out.push(n)
  }
  return out
}

export function parseIPv6(input: string): number[] | null {
  let s = input
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)
  if (s.includes('%')) return null // zone ids are link-local by nature
  if (s.length === 0 || s.length > 45) return null
  let tail: number[] = []
  const lastColon = s.lastIndexOf(':')
  if (s.includes('.')) {
    const v4 = parseIPv4(s.slice(lastColon + 1))
    if (!v4) return null
    tail = v4
    s = s.slice(0, lastColon + 1) + '0:0'
  }
  const halves = s.split('::')
  if (halves.length > 2) return null
  const parseGroups = (part: string): number[] | null => {
    if (part === '') return []
    const groups = part.split(':')
    const out: number[] = []
    for (const g of groups) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null
      out.push(parseInt(g, 16))
    }
    return out
  }
  const head = parseGroups(halves[0]!)
  const rest = halves.length === 2 ? parseGroups(halves[1]!) : []
  if (!head || !rest) return null
  let groups: number[]
  if (halves.length === 2) {
    const missing = 8 - head.length - rest.length
    if (missing < 1) return null
    groups = [...head, ...new Array<number>(missing).fill(0), ...rest]
  } else {
    groups = head
  }
  if (groups.length !== 8) return null
  const bytes: number[] = []
  for (const g of groups) bytes.push(g >> 8, g & 0xff)
  if (tail.length === 4) bytes.splice(12, 4, ...tail)
  return bytes
}

function inV4(ip: number[], cidr: string): boolean {
  const [base, bitsS] = cidr.split('/')
  const b = parseIPv4(base!)!
  const bits = Number(bitsS)
  const a = ((ip[0]! << 24) | (ip[1]! << 16) | (ip[2]! << 8) | ip[3]!) >>> 0
  const c = ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return (a & mask) === (c & mask)
}

function inV6(ip: number[], cidr: string): boolean {
  const [base, bitsS] = cidr.split('/')
  const b = parseIPv6(base!)!
  let bits = Number(bitsS)
  for (let i = 0; i < 16 && bits > 0; i++) {
    const take = Math.min(8, bits)
    const mask = (0xff << (8 - take)) & 0xff
    if ((ip[i]! & mask) !== (b[i]! & mask)) return false
    bits -= take
  }
  return true
}

/** Non-public IPv4 ranges (RFC 6890 special-purpose registry and friends). */
export const BLOCKED_V4: readonly string[] = [
  '0.0.0.0/8', // this network
  '10.0.0.0/8', // private
  '100.64.0.0/10', // CGNAT shared address space
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local (cloud metadata lives here)
  '172.16.0.0/12', // private
  '192.0.0.0/24', // IETF protocol assignments
  '192.0.2.0/24', // TEST-NET-1
  '192.31.196.0/24', // AS112
  '192.52.193.0/24', // AMT
  '192.88.99.0/24', // 6to4 relay anycast
  '192.168.0.0/16', // private
  '192.175.48.0/24', // AS112
  '198.18.0.0/15', // benchmarking
  '198.51.100.0/24', // TEST-NET-2
  '203.0.113.0/24', // TEST-NET-3
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved + broadcast
]

/** Ranges inside 2000::/3 that are still not acceptable destinations. */
export const BLOCKED_V6_IN_GLOBAL: readonly string[] = [
  '2001::/23', // IETF protocol assignments (incl. Teredo 2001::/32)
  '2001:db8::/32', // documentation
  '2002::/16', // 6to4 (embeds IPv4)
  '3fff::/20', // documentation (RFC 9637)
]

export type AddressVerdict = { ok: true; family: 4 | 6 } | { ok: false; reason: string }

export function classifyAddress(address: string): AddressVerdict {
  const v4 = parseIPv4(address)
  if (v4) {
    for (const c of BLOCKED_V4) if (inV4(v4, c)) return { ok: false, reason: `IPv4 ${address} is in non-public range ${c}` }
    return { ok: true, family: 4 }
  }
  const v6 = parseIPv6(address)
  if (!v6) return { ok: false, reason: `not an IP address: ${JSON.stringify(address.slice(0, 60))}` }
  if (inV6(v6, '::ffff:0:0/96')) return { ok: false, reason: `IPv4-mapped IPv6 address ${address} rejected` }
  if (inV6(v6, '64:ff9b::/96') || inV6(v6, '64:ff9b:1::/48')) return { ok: false, reason: `NAT64 address ${address} rejected` }
  if (inV6(v6, '::/96')) return { ok: false, reason: `IPv4-compatible, loopback or unspecified IPv6 address ${address} rejected` }
  if (inV6(v6, 'fc00::/7')) return { ok: false, reason: `unique local address ${address} rejected` }
  if (inV6(v6, 'fe80::/10') || inV6(v6, 'fec0::/10')) return { ok: false, reason: `link-local / site-local address ${address} rejected` }
  if (inV6(v6, 'ff00::/8')) return { ok: false, reason: `multicast address ${address} rejected` }
  if (!inV6(v6, '2000::/3')) return { ok: false, reason: `IPv6 ${address} is not global unicast (2000::/3)` }
  for (const c of BLOCKED_V6_IN_GLOBAL) if (inV6(v6, c)) return { ok: false, reason: `IPv6 ${address} is in non-public range ${c}` }
  return { ok: true, family: 6 }
}

/** True when the string is an IP literal (v4, v6, or bracketed v6). */
export function isIpLiteral(host: string): boolean {
  return parseIPv4(host) !== null || parseIPv6(host) !== null || /^\[.*\]$/.test(host) || /^[0-9.]+$/.test(host) || /^0x/i.test(host)
}

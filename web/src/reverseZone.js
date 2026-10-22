// Turn a network in CIDR notation into its reverse-lookup zone name, e.g.
// "192.168.0.0/24" -> "0.168.192.in-addr.arpa" and
// "2001:db8::/32" -> "8.b.d.0.1.0.0.2.ip6.arpa".
//
// Returns null when `input` is not CIDR notation (an ordinary zone name),
// { name } on success, or { error } when it is CIDR but cannot map to a
// zone. Reverse zones follow label boundaries, so IPv4 prefixes must be a
// multiple of 8 bits and IPv6 prefixes a multiple of 4 (classless RFC 2317
// delegation is not generated). Host bits past the prefix are ignored.
export function reverseZoneName(input) {
  const text = (input || '').trim();
  const slash = text.indexOf('/');
  if (slash < 0) return null;
  const addr = text.slice(0, slash);
  const prefixText = text.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefixText)) return { error: `Invalid prefix length "/${prefixText}".` };
  const prefix = Number(prefixText);

  if (addr.includes(':')) {
    const nibbles = ipv6Nibbles(addr);
    if (!nibbles) return { error: `"${addr}" is not a valid IPv6 address.` };
    if (prefix < 4 || prefix > 128 || prefix % 4 !== 0) {
      return { error: 'IPv6 reverse zones need a prefix that is a multiple of 4 (e.g. /48 or /64).' };
    }
    return { name: `${nibbles.slice(0, prefix / 4).reverse().join('.')}.ip6.arpa` };
  }

  const octets = addr.split('.');
  if (octets.length !== 4 || !octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255)) {
    return { error: `"${addr}" is not a valid IPv4 address.` };
  }
  if (![8, 16, 24, 32].includes(prefix)) {
    return { error: 'IPv4 reverse zones need a /8, /16, /24 or /32 prefix.' };
  }
  return {
    name: `${octets.slice(0, prefix / 8).map(Number).reverse().join('.')}.in-addr.arpa`,
  };
}

// Convert a single IP address into its full reverse-DNS owner name. Returns
// null for invalid addresses; the caller can then match the name against an
// already-hosted reverse zone without creating one implicitly.
export function reverseRecordName(address) {
  const text = (address || '').trim();
  if (!text || text.includes('/')) return null;
  if (text.includes(':')) {
    const zone = reverseZoneName(`${text}/128`);
    return zone?.name || null;
  }
  const zone = reverseZoneName(`${text}/32`);
  return zone?.name || null;
}

// Expand an IPv6 address into its 32 hex nibbles, or null when invalid.
function ipv6Nibbles(addr) {
  if (!/^[0-9a-fA-F:]+$/.test(addr) || (addr.match(/::/g) || []).length > 1) return null;
  const [head, tail] = addr.includes('::') ? addr.split('::') : [addr, null];
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const missing = 8 - left.length - right.length;
  if (tail === null ? missing !== 0 : missing < 1) return null;
  const groups = [...left, ...Array(tail === null ? 0 : missing).fill('0'), ...right];
  if (groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  return groups.flatMap((g) => g.toLowerCase().padStart(4, '0').split(''));
}

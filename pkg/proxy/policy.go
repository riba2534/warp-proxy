package proxy

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// errBlocked marks a destination refused by the policy.
var errBlocked = errors.New("destination not allowed by policy")

// Ranges refused besides the ones netip.Addr classifies itself.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"; Linux connects 0.x to the host itself
	netip.MustParsePrefix("100.64.0.0/10"),      // CGNAT shared address space
	netip.MustParsePrefix("255.255.255.255/32"), // limited broadcast
}

// blocked reports whether ip is an internal destination: loopback, unspecified,
// link-local, multicast, broadcast, private (RFC 1918, fc00::/7), CGNAT or
// 0.0.0.0/8. IPv4-mapped IPv6 addresses are judged as the IPv4 address.
func blocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsPrivate() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// isLocalhost reports whether host is "localhost" or a name under it, which
// RFC 6761 reserves for loopback.
func isLocalhost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// parseIPHost returns the address host denotes without DNS: an IP literal
// (optionally bracketed or zoned) or a legacy numeric IPv4 form such as
// "2130706433", "0x7f.1" or "127.1". getaddrinfo and many clients accept the
// legacy forms, so they are treated as the address they spell instead of being
// left to a resolver that might map them anywhere.
func parseIPHost(host string) (netip.Addr, bool) {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip, true
	}
	return parseLegacyIPv4(strings.TrimSuffix(host, "."))
}

// parseLegacyIPv4 parses the inet_aton forms a, a.b, a.b.c and a.b.c.d where
// each part is decimal, octal (leading 0) or hexadecimal (leading 0x) and the
// last part fills the remaining bytes.
func parseLegacyIPv4(s string) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var v uint64
	for i, p := range parts {
		n, ok := parseLegacyPart(p)
		if !ok {
			return netip.Addr{}, false
		}
		if i < len(parts)-1 {
			if n > 0xff {
				return netip.Addr{}, false
			}
			v |= n << (8 * (3 - i))
			continue
		}
		if n >= 1<<(8*(4-i)) {
			return netip.Addr{}, false
		}
		v |= n
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

func parseLegacyPart(p string) (uint64, bool) {
	base := 10
	switch {
	case len(p) > 2 && (p[:2] == "0x" || p[:2] == "0X"):
		base, p = 16, p[2:]
	case len(p) > 1 && p[0] == '0':
		base, p = 8, p[1:]
	}
	// With an explicit base ParseUint accepts digits only: no sign, no underscores.
	n, err := strconv.ParseUint(p, base, 32)
	return n, err == nil
}

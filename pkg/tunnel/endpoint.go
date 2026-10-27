//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
)

// Endpoint resolution is bounded per hostname and in total, so a broken
// resolver cannot stall Up or RotateEndpoint; IP literals need no lookup.
var (
	resolveTimeout = 3 * time.Second
	resolveBudget  = 10 * time.Second
)

type resolveFunc func(ctx context.Context, candidate string) (netip.AddrPort, error)

// pickEndpoint tries the candidates once each, starting at start and wrapping,
// and returns the index and address of the first one that resolves. Once the
// budget is spent, hostnames fail at once but IP literals are still tried.
func pickEndpoint(ctx context.Context, candidates []string, start int, resolve resolveFunc) (int, netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveBudget)
	defer cancel()
	var errs []error
	for i := range len(candidates) {
		idx := (start + i) % len(candidates)
		ap, err := resolve(ctx, candidates[idx])
		if err == nil {
			return idx, ap, nil
		}
		errs = append(errs, err)
	}
	return 0, netip.AddrPort{}, fmt.Errorf("no endpoint candidate resolved: %w", errors.Join(errs...))
}

type resolver struct {
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// ipv6 reports whether addr is reachable outside the tunnel.
	ipv6 func(addr netip.Addr) bool
}

// newResolver returns the system resolver. Like WireGuard's own UDP, its
// sockets are unmarked and use the main table, so it works while the tunnel is down.
func newResolver() resolver {
	return resolver{
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		ipv6: func(addr netip.Addr) bool {
			routes, err := netlink.RouteGet(addr.AsSlice())
			return err == nil && len(routes) > 0
		},
	}
}

// resolve returns the first address of the candidate in resolver order that is
// IPv4 or reachable over IPv6, so IPv4 is preferred when this netns has no IPv6.
func (r resolver) resolve(ctx context.Context, candidate string) (netip.AddrPort, error) {
	host, port, err := splitEndpoint(candidate)
	if err != nil {
		return netip.AddrPort{}, err
	}
	addrs := []netip.Addr{}
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, a)
	} else {
		ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		defer cancel()
		if addrs, err = r.lookup(ctx, host); err != nil {
			return netip.AddrPort{}, fmt.Errorf("resolve %s: %w", candidate, err)
		}
	}
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() || r.ipv6(a) {
			return netip.AddrPortFrom(a, port), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("resolve %s: no IPv4 address and no IPv6 route", candidate)
}

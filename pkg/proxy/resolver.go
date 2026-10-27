package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
)

type lookupFunc = func(ctx context.Context, host string) ([]netip.Addr, error)

type controlFunc = func(network, address string, c syscall.RawConn) error

// newLookup returns the host lookup for servers ("ip" or "ip:port", default
// port 53), whose sockets get control before they connect, or the system
// resolver's lookup when there are none.
func newLookup(servers []string, control controlFunc) (lookupFunc, error) {
	var d dnsServers
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		addr, err := parseDNSServer(s)
		if err != nil {
			return nil, err
		}
		d.resolvers = append(d.resolvers, pinnedResolver(addr, control))
	}
	if len(d.resolvers) == 0 {
		return func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}, nil
	}
	return d.lookup, nil
}

func parseDNSServer(s string) (string, error) {
	if ip, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(ip, 53).String(), nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil || ap.Port() == 0 {
		return "", fmt.Errorf("proxy: invalid DNS server %q: want ip or ip:port", s)
	}
	return ap.String(), nil
}

// pinnedResolver is a pure Go resolver that sends every query to addr instead
// of the servers in /etc/resolv.conf.
func pinnedResolver(addr string, control controlFunc) *net.Resolver {
	d := net.Dialer{Control: control}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}}
}

// dnsServers asks one server after another, starting with the one that
// answered last, and moves on when a server fails (no reply, refusal,
// SERVFAIL); a name that does not exist is an answer. The servers share the
// lookup's budget like the candidates of a dial.
type dnsServers struct {
	resolvers []*net.Resolver
	current   atomic.Uint32
}

func (d *dnsServers) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	n := uint32(len(d.resolvers))
	start := d.current.Load()
	var err error
	for k := range n {
		i := (start + k) % n
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout(ctx, int(n-k)))
		var addrs []netip.Addr
		addrs, err = d.resolvers[i].LookupNetIP(attemptCtx, "ip", host)
		cancel()
		var dnsErr *net.DNSError
		if err == nil || errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			d.current.CompareAndSwap(start, i)
			return addrs, err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, err
}

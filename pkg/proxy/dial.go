package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"time"
)

// minAttemptTimeout keeps a fallback attempt from getting a uselessly small
// share of the dial budget (the same floor net.Dialer uses).
const minAttemptTimeout = 2 * time.Second

type dialFunc = func(ctx context.Context, network, address string) (net.Conn, error)

// defaultDial dials with TCP keep-alive (Go disables Nagle by default); Control
// marks each socket (Options.Mark). Unless private destinations are allowed it
// also re-checks the policy behind connect, as defence in depth: Control vets
// the address the socket is about to connect to, and refuseSelf catches this
// host's own addresses, which no prefix list covers (the tunnel's global IPv6
// address, a host-network public address).
func (s *Server) defaultDial() dialFunc {
	d := &net.Dialer{KeepAlive: keepAlivePeriod, Control: s.markSocket}
	if s.opts.AllowPrivate {
		return d.DialContext
	}
	d.Control = func(network, address string, c syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || blocked(ap.Addr()) {
			return errBlocked
		}
		return s.markSocket(network, address, c)
	}
	return refuseSelf(d.DialContext)
}

// refuseSelf closes and refuses a connection whose local and remote IP are the
// same, which is what the kernel picks whenever the destination is a local
// address outside 127.0.0.0/8.
func refuseSelf(dial dialFunc) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		local, _ := c.LocalAddr().(*net.TCPAddr)
		remote, _ := c.RemoteAddr().(*net.TCPAddr)
		if local != nil && remote != nil && local.IP.Equal(remote.IP) {
			_ = c.Close()
			return nil, &net.OpError{Op: "dial", Net: network, Source: local, Addr: remote, Err: errBlocked}
		}
		return c, nil
	}
}

// loopbackAddrs is what localhost names resolve to (RFC 6761), whatever DNS says.
var loopbackAddrs = []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()}

// resolve returns the candidate addresses for host in resolver order. IP
// literals, legacy numeric forms and localhost names skip DNS.
func (s *Server) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, ok := parseIPHost(host); ok {
		return []netip.Addr{ip}, nil
	}
	if isLocalhost(host) {
		return loopbackAddrs, nil
	}
	// An absolute name is queried as is: resolv.conf's search list and ndots
	// cannot turn it into some internal name or add NXDOMAIN round trips.
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	addrs, err := s.lookup(ctx, host)
	if err == nil && len(addrs) == 0 {
		err = &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if markErr := s.markErr.Load(); err != nil && markErr != nil {
		// The resolver keeps only the text of a dial error; while sockets
		// cannot be marked, DNS sockets fail for that reason too.
		err = *markErr
	}
	return addrs, err
}

// connect resolves host, drops every candidate the policy refuses and dials the
// rest in resolver order within one DialTimeout budget. It returns errBlocked
// when no candidate was allowed, otherwise the last dial error.
func (s *Server) connect(ctx context.Context, host string, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, s.opts.DialTimeout)
	defer cancel()
	addrs, err := s.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if !s.opts.AllowPrivate {
		addrs = slices.DeleteFunc(slices.Clone(addrs), blocked)
		if len(addrs) == 0 {
			return nil, errBlocked
		}
	}
	for i, ip := range addrs {
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, attemptTimeout(ctx, len(addrs)-i))
		c, dialErr := s.dial(attemptCtx, "tcp", netip.AddrPortFrom(ip.Unmap(), port).String())
		cancelAttempt()
		if dialErr == nil {
			return c, nil
		}
		err = dialErr
		if ctx.Err() != nil {
			break
		}
	}
	return nil, err
}

// attemptTimeout splits what is left of ctx's budget evenly over the candidates
// (addresses, DNS servers) still to try, so one black hole cannot starve the rest.
func attemptTimeout(ctx context.Context, left int) time.Duration {
	deadline, _ := ctx.Deadline()
	return max(time.Until(deadline)/time.Duration(left), minAttemptTimeout)
}

// failure is the kind of a connect error, which selects the reply code.
type failure int

const (
	failGeneral failure = iota
	failPolicy
	failUnreachable
	failRefused
	failTimeout
)

func classify(err error) failure {
	var netErr net.Error
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, errBlocked):
		return failPolicy
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return failTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return failRefused
	case errors.As(err, &dnsErr), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return failUnreachable
	}
	return failGeneral
}

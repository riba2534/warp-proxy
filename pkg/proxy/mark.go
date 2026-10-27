package proxy

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"
)

// errMark marks a dial refused because its socket could not be marked: an
// unmarked socket would bypass the tunnel.
var errMark = errors.New("cannot mark socket")

// markSocket sets Options.Mark on a socket about to connect to address; it has
// the shape of net.Dialer.Control. Internal destinations (the blocked set,
// dialed only with AllowPrivate, and DNS servers the operator put there) stay
// unmarked so they use the normal routes; the tunnel would never deliver them.
// The first failure is logged and kept in markErr: marking fails for the whole
// process (no CAP_NET_ADMIN, not Linux), not for one socket.
func (s *Server) markSocket(_, address string, c syscall.RawConn) error {
	if s.opts.Mark == 0 {
		return nil
	}
	if ap, err := netip.ParseAddrPort(address); err == nil && blocked(ap.Addr()) {
		return nil
	}
	if err := s.setMark(c, s.opts.Mark); err != nil {
		err = fmt.Errorf("%w %#x: %w", errMark, s.opts.Mark, err)
		if s.markErr.CompareAndSwap(nil, &err) {
			s.log.Warn("cannot mark proxy sockets; refusing to dial", "error", err)
		}
		return err
	}
	return nil
}

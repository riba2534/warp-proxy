//go:build unix

package proxy

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

const testMark = 0x57415250

// markRecorder replaces the SO_MARK setter: it records markEntry for the type
// of the socket it was given, then fails with err if not nil.
func markRecorder(marks *recorder, err error) func(*Server) {
	return func(s *Server) {
		s.setMark = func(c syscall.RawConn, mark uint32) error {
			typ := -1
			_ = c.Control(func(fd uintptr) { typ, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE) })
			marks.add(markEntry(map[int]string{syscall.SOCK_STREAM: "tcp", syscall.SOCK_DGRAM: "udp"}[typ], mark))
			return err
		}
	}
}

func markEntry(kind string, mark uint32) string { return fmt.Sprintf("%s %#x", kind, mark) }

// marksAfterConnect relays through a server with mark that resolves the
// destination through a DNS server, and returns the marks set on the way.
func marksAfterConnect(t *testing.T, mark uint32) []string {
	t.Helper()
	upstream := startUpstream(t, pong)
	dns := startDNSServer(t, map[string]netip.Addr{"marked.test.": netip.MustParseAddr("127.0.0.1")}, dnsmessage.RCodeNameError)
	var marks recorder
	s := startServer(t, Options{Mark: mark, AllowPrivate: true, DNSServers: []string{dns.addr}}, nil, markRecorder(&marks, nil))
	c := dialProxy(t, s)
	mustSOCKS5(t, c, socks5Domain("marked.test", netip.MustParseAddrPort(upstream).Port()))
	exchange(t, c, "marked")
	return marks.list()
}

// The mark reaches every socket to the DNS server and then the upstream socket.
func TestMarkAppliedToUpstreamAndDNS(t *testing.T) {
	got := marksAfterConnect(t, testMark)
	n := len(got)
	if n < 2 || got[n-1] != markEntry("tcp", testMark) ||
		slices.ContainsFunc(got[:n-1], func(m string) bool { return m != markEntry("udp", testMark) }) {
		t.Errorf("marks %q, want the DNS sockets as udp, then the upstream as tcp, all %#x", got, testMark)
	}
}

// Under the destination policy (the default) the socket is marked after the
// policy check. The setter fails, so the socket to the public destination
// never connects and nothing leaves the host.
func TestMarkAppliedUnderPolicy(t *testing.T) {
	var marks recorder
	s := startServer(t, Options{Mark: testMark}, nil, markRecorder(&marks, syscall.EPERM))
	c := dialProxy(t, s)
	if code, _ := socks5Connect(t, c, socks5IP("203.0.113.1", 80)); code != socks5GeneralFailure {
		t.Errorf("socks5 reply %#x, want a general failure", code)
	}
	if got := marks.list(); !slices.Equal(got, []string{markEntry("tcp", testMark)}) {
		t.Errorf("marks %q", got)
	}
}

func TestNoMarkWithoutMark(t *testing.T) {
	if got := marksAfterConnect(t, 0); len(got) != 0 {
		t.Errorf("marked %q without a Mark", got)
	}
}

// A socket that cannot be marked is never connected: the client gets a general
// failure, the destination and the DNS server see nothing, and the failure is
// logged once.
func TestMarkFailureRefusesDial(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	upstream := startUpstream(t, acceptInto(accepted))
	port := netip.MustParseAddrPort(upstream).Port()
	dns := startDNSServer(t, map[string]netip.Addr{"marked.test.": netip.MustParseAddr("127.0.0.1")}, dnsmessage.RCodeNameError)
	var logs lockedBuffer
	var marks recorder
	s := startServer(t, Options{
		Mark: testMark, AllowPrivate: true, DNSServers: []string{dns.addr},
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}, nil, markRecorder(&marks, syscall.EPERM))

	c := dialProxy(t, s) // upstream socket
	if code, _ := socks5Connect(t, c, socks5IP("127.0.0.1", port)); code != socks5GeneralFailure {
		t.Errorf("socks5 reply %#x, want a general failure", code)
	}
	c = dialProxy(t, s) // DNS socket
	if code, _ := socks5Connect(t, c, socks5Domain("marked.test", port)); code != socks5GeneralFailure {
		t.Errorf("socks5 reply %#x for a hostname, want a general failure", code)
	}
	c = dialProxy(t, s)
	fmt.Fprintf(c, "CONNECT marked.test:%d HTTP/1.1\r\n\r\n", port)
	if status := readResponse(t, c).StatusCode; status != http.StatusBadGateway {
		t.Errorf("http status %d, want 502", status)
	}

	select {
	case <-accepted:
		t.Error("an unmarked socket reached the destination")
	default:
	}
	if n := dns.queries(); n != 0 {
		t.Errorf("%d DNS queries left on unmarked sockets", n)
	}
	if got := marks.list(); !slices.Contains(got, markEntry("tcp", testMark)) || !slices.Contains(got, markEntry("udp", testMark)) {
		t.Errorf("mark attempts %q", got)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Errorf("%d warnings, want 1:\n%s", n, logs.String())
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

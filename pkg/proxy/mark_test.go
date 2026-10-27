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
	"time"

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

// Only sockets to public destinations are marked: internal ones (dialed with
// AllowPrivate, or DNS servers there) keep the normal routes. Nothing is
// marked without a Mark.
func TestMarkOnlyPublicDestinations(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // any socket can stand in for the one being dialed
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	raw, err := pc.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"203.0.113.1:80": true, "1.1.1.1:53": true, "[2606:4700:4700::1111]:53": true, "[::ffff:1.1.1.1]:443": true,
		"10.0.0.5:80": false, "172.18.0.2:80": false, "192.168.1.53:53": false, "127.0.0.53:53": false, "[::1]:53": false,
		"100.64.0.1:80": false, "169.254.169.254:80": false, "[fd00::53]:53": false, "[fe80::1%lo]:53": false,
		"[::ffff:10.0.0.5]:80": false, "224.0.0.251:5353": false,
	}
	for _, mark := range []uint32{testMark, 0} {
		for address, public := range cases {
			var marks recorder
			s := NewServer(Options{Mark: mark, AllowPrivate: true})
			markRecorder(&marks, nil)(s)
			if err := s.markSocket("tcp", address, raw); err != nil {
				t.Fatalf("markSocket(%s): %v", address, err)
			}
			if marked, want := len(marks.list()) == 1, public && mark != 0; marked != want {
				t.Errorf("mark %#x, %s: marked %v, want %v", mark, address, marked, want)
			}
		}
	}
}

// Through real relays with AllowPrivate, a loopback destination reached by IP
// or through a loopback DNS server works and nothing is marked; the setter
// fails, so a marked socket would have failed the request.
func TestPrivateDestinationsStayUnmarked(t *testing.T) {
	upstream := startUpstream(t, pong)
	port := netip.MustParseAddrPort(upstream).Port()
	dns := startDNSServer(t, map[string]netip.Addr{"private.test.": netip.MustParseAddr("127.0.0.1")}, dnsmessage.RCodeNameError)
	var marks recorder
	s := startServer(t, Options{Mark: testMark, AllowPrivate: true, DNSServers: []string{dns.addr}}, nil, markRecorder(&marks, syscall.EPERM))
	for _, req := range [][]byte{socks5Domain("private.test", port), socks5IP("127.0.0.1", port)} {
		c := dialProxy(t, s)
		mustSOCKS5(t, c, req)
		exchange(t, c, "private")
	}
	if got := marks.list(); len(got) != 0 {
		t.Errorf("marked %q", got)
	}
}

// Sockets to a public destination and to a public DNS server are marked under
// either policy. The setter fails, so none of them connects and nothing leaves
// the host: the client gets a general failure and the failure is logged once.
func TestMarkPublicDestinationsFailClosed(t *testing.T) {
	for _, allowPrivate := range []bool{false, true} {
		t.Run(fmt.Sprintf("AllowPrivate=%v", allowPrivate), func(t *testing.T) {
			var logs lockedBuffer
			var marks recorder
			s := startServer(t, Options{
				Mark: testMark, AllowPrivate: allowPrivate, DialTimeout: time.Second,
				DNSServers: []string{"203.0.113.53"}, Logger: slog.New(slog.NewTextHandler(&logs, nil)),
			}, nil, markRecorder(&marks, syscall.EPERM))

			c := dialProxy(t, s) // upstream socket
			if code, _ := socks5Connect(t, c, socks5IP("203.0.113.1", 80)); code != socks5GeneralFailure {
				t.Errorf("socks5 reply %#x, want a general failure", code)
			}
			if got := marks.list(); !slices.Equal(got, []string{markEntry("tcp", testMark)}) {
				t.Errorf("marks for the upstream %q", got)
			}

			c = dialProxy(t, s) // DNS sockets
			if code, _ := socks5Connect(t, c, socks5Domain("public.test", 80)); code != socks5GeneralFailure {
				t.Errorf("socks5 reply %#x for a hostname, want a general failure", code)
			}
			c = dialProxy(t, s)
			fmt.Fprintf(c, "CONNECT public.test:80 HTTP/1.1\r\n\r\n")
			if status := readResponse(t, c).StatusCode; status != http.StatusBadGateway {
				t.Errorf("http status %d, want 502", status)
			}
			got := marks.list()
			if len(got) < 2 || slices.ContainsFunc(got[1:], func(m string) bool { return m != markEntry("udp", testMark) }) {
				t.Errorf("marks %q, want the upstream then only DNS sockets", got)
			}
			if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
				t.Errorf("%d warnings, want 1:\n%s", n, logs.String())
			}
		})
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

package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// testTimeout bounds every blocking step of a test.
const testTimeout = 5 * time.Second

// recorder collects strings from concurrent goroutines.
type recorder struct {
	mu    sync.Mutex
	items []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	r.items = append(r.items, s)
	r.mu.Unlock()
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.items)
}

// fakeResolver answers from fixed tables and records every name it is asked.
type fakeResolver struct {
	hosts map[string][]netip.Addr
	errs  map[string]error
	asked recorder
}

func (f *fakeResolver) lookup(_ context.Context, host string) ([]netip.Addr, error) {
	f.asked.add(host)
	if err := f.errs[host]; err != nil {
		return nil, err
	}
	if addrs, ok := f.hosts[host]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func addrs(ips ...string) []netip.Addr {
	out := make([]netip.Addr, len(ips))
	for i, ip := range ips {
		out[i] = netip.MustParseAddr(ip)
	}
	return out
}

var exampleHosts = map[string][]netip.Addr{"example.test": addrs("203.0.113.20")}

// redirectTo returns a Dial hook that records each address in dials (if not
// nil) and connects it to the loopback target instead, so tests can use public
// destinations.
func redirectTo(target string, dials *recorder) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if dials != nil {
			dials.add(address)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
}

// dialErr is the error net.Dialer returns when connect fails with errno.
func dialErr(errno syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
}

// testLogger sends server logs, including the per-connection debug lines, to the test log.
func testLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// startServer starts a server on loopback; lookup, when non-nil, replaces DNS.
// Cleanup stops it and checks that Serve returned nil.
func startServer(t *testing.T, opts Options, lookup *fakeResolver) *Server {
	t.Helper()
	opts.ListenAddr = "127.0.0.1:0"
	if opts.Logger == nil {
		opts.Logger = testLogger(t)
	}
	s := NewServer(opts)
	if lookup != nil {
		s.lookup = lookup.lookup
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	t.Cleanup(func() {
		if err := s.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("Serve after Stop: %v", err)
			}
		case <-time.After(testTimeout):
			t.Error("Serve did not return after Stop")
		}
	})
	return s
}

// startUpstream serves each connection to a loopback port with handler and
// closes it after.
func startUpstream(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	return startUpstreamAt(t, "127.0.0.1:0", handler)
}

// startUpstreamAt is startUpstream on addr; the test is skipped when addr
// cannot be bound.
func startUpstreamAt(t *testing.T, addr string, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(testTimeout))
				handler(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// pong reads until the client half-closes, then answers "pong:" + what it read
// and closes, exercising both directions and the half-close of each.
func pong(c net.Conn) {
	data, err := io.ReadAll(c)
	if err == nil {
		_, _ = c.Write(append([]byte("pong:"), data...))
	}
}

// acceptInto hands each upstream connection to the test and keeps it open
// until the test closes it.
func acceptInto(ch chan<- net.Conn) func(net.Conn) {
	return func(c net.Conn) {
		done := make(chan struct{})
		ch <- &notifyConn{Conn: c, closed: done}
		<-done
	}
}

type notifyConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *notifyConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func receive(t *testing.T, ch <-chan net.Conn) net.Conn {
	t.Helper()
	select {
	case c := <-ch:
		t.Cleanup(func() { c.Close() })
		return c
	case <-time.After(testTimeout):
		t.Fatal("upstream connection not received")
		return nil
	}
}

func dialProxy(t *testing.T, s *Server) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", s.Addr().String(), testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(testTimeout))
	return c.(*net.TCPConn)
}

// openRelay connects a SOCKS5 client to 203.0.113.1:80 through s, whose Dial
// hook leads to an acceptInto upstream, and returns both ends.
func openRelay(t *testing.T, s *Server, accepted <-chan net.Conn) (*net.TCPConn, net.Conn) {
	t.Helper()
	c := dialProxy(t, s)
	mustSOCKS5(t, c, socks5IP("203.0.113.1", 80))
	return c, receive(t, accepted)
}

// exchange sends payload, half-closes, and expects the pong upstream's answer
// followed by EOF.
func exchange(t *testing.T, c *net.TCPConn, payload string) {
	t.Helper()
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("reading relay: %v", err)
	}
	if want := "pong:" + payload; string(got) != want {
		t.Fatalf("relay returned %q, want %q", got, want)
	}
}

func echo(t *testing.T, from, to net.Conn, msg string) {
	t.Helper()
	if _, err := from.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = to.SetReadDeadline(time.Now().Add(testTimeout))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(to, got); err != nil || string(got) != msg {
		t.Fatalf("relayed %q, %v; want %q", got, err, msg)
	}
}

// expectClosed checks that the server closed c (EOF or reset, not a timeout).
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(testTimeout))
	if _, err := io.Copy(io.Discard, c); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("connection still open")
		}
	}
}

func socks5Greeting(methods ...byte) []byte {
	return append([]byte{socks5Version, byte(len(methods))}, methods...)
}

func socks5Request(cmd, atyp byte, addr []byte, port uint16) []byte {
	req := append([]byte{socks5Version, cmd, 0x00, atyp}, addr...)
	return binary.BigEndian.AppendUint16(req, port)
}

func socks5Domain(name string, port uint16) []byte {
	return socks5Request(socks5CmdConnect, atypDomain, append([]byte{byte(len(name))}, name...), port)
}

func socks5IP(ip string, port uint16) []byte {
	a := netip.MustParseAddr(ip)
	atyp := byte(atypIPv4)
	if a.Is6() {
		atyp = atypIPv6
	}
	return socks5Request(socks5CmdConnect, atyp, a.AsSlice(), port)
}

// socks5Connect performs the no-auth greeting and sends req; it returns the
// reply code and the bound address.
func socks5Connect(t *testing.T, c net.Conn, req []byte) (byte, netip.AddrPort) {
	t.Helper()
	if _, err := c.Write(socks5Greeting(socks5NoAuth)); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil {
		t.Fatalf("method reply: %v", err)
	}
	if method != [2]byte{socks5Version, socks5NoAuth} {
		t.Fatalf("method reply %x", method)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	return readSOCKS5Reply(t, c)
}

// mustSOCKS5 is socks5Connect for requests that must succeed.
func mustSOCKS5(t *testing.T, c net.Conn, req []byte) netip.AddrPort {
	t.Helper()
	code, bound := socks5Connect(t, c, req)
	if code != socks5Succeeded {
		t.Fatalf("socks5 reply %#x", code)
	}
	return bound
}

func readSOCKS5Reply(t *testing.T, c net.Conn) (byte, netip.AddrPort) {
	t.Helper()
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if head[0] != socks5Version || head[2] != 0 {
		t.Fatalf("connect reply header %x", head)
	}
	n := 4
	if head[3] == atypIPv6 {
		n = 16
	} else if head[3] != atypIPv4 {
		t.Fatalf("reply ATYP %#x", head[3])
	}
	b := make([]byte, n+2)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("connect reply address: %v", err)
	}
	ip, _ := netip.AddrFromSlice(b[:n])
	return head[1], netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[n:]))
}

func socks4Request(cmd byte, ip [4]byte, port uint16, user, host string) []byte {
	req := []byte{socks4Version, cmd}
	req = binary.BigEndian.AppendUint16(req, port)
	req = append(req, ip[:]...)
	req = append(append(req, user...), 0)
	if host != "" {
		req = append(append(req, host...), 0)
	}
	return req
}

func readSOCKS4Reply(t *testing.T, c net.Conn) byte {
	t.Helper()
	var reply [8]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatalf("socks4 reply: %v", err)
	}
	if reply[0] != 0 {
		t.Fatalf("socks4 reply version %#x", reply[0])
	}
	return reply[1]
}

func expectEstablished(t *testing.T, c net.Conn) {
	t.Helper()
	got := make([]byte, len(httpEstablished))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("CONNECT response: %v", err)
	}
	if string(got) != string(httpEstablished) {
		t.Fatalf("CONNECT response %q", got)
	}
}

// readResponse reads an HTTP error response; the server sends no body.
func readResponse(t *testing.T, c net.Conn) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	resp.Body.Close()
	return resp
}

// probe asks for a destination that must fail over SOCKS5, SOCKS4a and HTTP
// CONNECT, checks that each connection is closed after the reply, and returns
// the three replies.
func probe(t *testing.T, s *Server, host string, port uint16) (socks5Code, socks4Code byte, status int) {
	t.Helper()
	c := dialProxy(t, s)
	socks5Code, _ = socks5Connect(t, c, socks5Domain(host, port))
	expectClosed(t, c)

	c = dialProxy(t, s)
	if _, err := c.Write(socks4Request(socks4Connect, [4]byte{0, 0, 0, 1}, port, "", host)); err != nil {
		t.Fatal(err)
	}
	socks4Code = readSOCKS4Reply(t, c)
	expectClosed(t, c)

	c = dialProxy(t, s)
	target := net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(int(port)))
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\n\r\n", target); err != nil {
		t.Fatal(err)
	}
	status = readResponse(t, c).StatusCode
	expectClosed(t, c)
	return socks5Code, socks4Code, status
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

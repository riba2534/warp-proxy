package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// TestConnect relays data both ways, with a half-close in each direction, for
// every request form of the three protocols.
func TestConnect(t *testing.T) {
	socks5 := func(req []byte) func(*testing.T, net.Conn) {
		return func(t *testing.T, c net.Conn) {
			// BND.ADDR is the upstream connection's local address.
			if bound := mustSOCKS5(t, c, req); bound.Addr() != netip.MustParseAddr("127.0.0.1") || bound.Port() == 0 {
				t.Errorf("bound address %v", bound)
			}
		}
	}
	socks4 := func(req []byte) func(*testing.T, net.Conn) {
		return func(t *testing.T, c net.Conn) {
			if _, err := c.Write(req); err != nil {
				t.Fatal(err)
			}
			if code := readSOCKS4Reply(t, c); code != socks4Granted {
				t.Fatalf("socks4 reply %#x", code)
			}
		}
	}
	httpConnect := func(head string) func(*testing.T, net.Conn) {
		return func(t *testing.T, c net.Conn) {
			if _, err := c.Write([]byte(head)); err != nil {
				t.Fatal(err)
			}
			expectEstablished(t, c)
		}
	}
	cases := []struct {
		name      string
		handshake func(*testing.T, net.Conn)
		dial      string
	}{
		{"socks5 ipv4", socks5(socks5IP("203.0.113.10", 443)), "203.0.113.10:443"},
		{"socks5 ipv6", socks5(socks5IP("2001:db8::10", 443)), "[2001:db8::10]:443"},
		{"socks5 ipv4-mapped ipv6", socks5(socks5IP("::ffff:203.0.113.30", 8443)), "203.0.113.30:8443"},
		{"socks5 domain", socks5(socks5Domain("example.test", 80)), "203.0.113.20:80"},
		{"socks5 ip literal as domain", socks5(socks5Domain("203.0.113.31", 80)), "203.0.113.31:80"},
		{"socks4", socks4(socks4Request(socks4Connect, [4]byte{203, 0, 113, 40}, 80, "user", "")), "203.0.113.40:80"},
		{"socks4a", socks4(socks4Request(socks4Connect, [4]byte{0, 0, 0, 1}, 443, "", "example.test")), "203.0.113.20:443"},
		{"socks4a ip literal", socks4(socks4Request(socks4Connect, [4]byte{0, 0, 0, 255}, 80, "u", "203.0.113.41")), "203.0.113.41:80"},
		{"http domain with headers", httpConnect("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: Basic eDp5\r\n\r\n"), "203.0.113.20:443"},
		{"http ipv6 http/1.0", httpConnect("CONNECT [2001:db8::10]:443 HTTP/1.0\r\n\r\n"), "[2001:db8::10]:443"},
		{"http bare LF", httpConnect("CONNECT 203.0.113.50:8080 HTTP/1.1\nHost: x\n\n"), "203.0.113.50:8080"},
	}
	upstream := startUpstream(t, pong)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dials recorder
			s := startServer(t, Options{Dial: redirectTo(upstream, &dials)}, &fakeResolver{hosts: exampleHosts})
			c := dialProxy(t, s)
			tc.handshake(t, c)
			exchange(t, c, "ping "+tc.name)
			if got := dials.list(); !slices.Equal(got, []string{tc.dial}) {
				t.Errorf("dialed %q, want %q", got, tc.dial)
			}
		})
	}
}

// curl offers no-auth and GSSAPI and sends hostnames for socks5h.
func TestSOCKS5CurlStyleHandshake(t *testing.T) {
	var dials recorder
	s := startServer(t, Options{Dial: redirectTo(startUpstream(t, pong), &dials)}, &fakeResolver{hosts: exampleHosts})
	c := dialProxy(t, s)
	if _, err := c.Write(socks5Greeting(socks5NoAuth, 0x01)); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("method reply %x, %v", method, err)
	}
	if _, err := c.Write(socks5Domain("example.test", 443)); err != nil {
		t.Fatal(err)
	}
	if code, _ := readSOCKS5Reply(t, c); code != socks5Succeeded {
		t.Fatalf("reply code %#x", code)
	}
	exchange(t, c, "GET / HTTP/1.1\r\n\r\n")
	if got := dials.list(); !slices.Equal(got, []string{"203.0.113.20:443"}) {
		t.Errorf("dialed %q", got)
	}
}

// Greeting, request and payload in one segment: the payload read along with the
// request must still reach the destination.
func TestSOCKS5PipelinedRequest(t *testing.T) {
	s := startServer(t, Options{Dial: redirectTo(startUpstream(t, pong), nil)}, &fakeResolver{hosts: exampleHosts})
	c := dialProxy(t, s)
	msg := slices.Concat(socks5Greeting(socks5NoAuth), socks5Domain("example.test", 80), []byte("early"))
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil {
		t.Fatal(err)
	}
	if code, _ := readSOCKS5Reply(t, c); code != socks5Succeeded {
		t.Fatalf("reply code %#x", code)
	}
	if got, err := io.ReadAll(c); err != nil || string(got) != "pong:early" {
		t.Fatalf("relay returned %q, %v", got, err)
	}
	waitFor(t, "byte counters", func() bool { return s.Stats().GetSnapshot().BytesClientToUp == int64(len("early")) })
}

// Bytes sent right behind the HTTP head (here with the write side already
// closed) were read into the handshake buffer and must be forwarded first.
func TestHTTPConnectPipelinedBytes(t *testing.T) {
	s := startServer(t, Options{Dial: redirectTo(startUpstream(t, pong), nil)}, &fakeResolver{hosts: exampleHosts})
	c := dialProxy(t, s)
	const early = "\x16\x03\x01 client hello"
	if _, err := c.Write([]byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n" + early)); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectEstablished(t, c)
	if got, err := io.ReadAll(c); err != nil || string(got) != "pong:"+early {
		t.Fatalf("relay returned %q, %v", got, err)
	}
	waitFor(t, "byte counters", func() bool {
		st := s.Stats().GetSnapshot()
		return st.BytesClientToUp == int64(len(early)) && st.BytesUpToClient == int64(len("pong:"+early))
	})
}

func TestXNetProxySOCKS5Client(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	var dials recorder
	s := startServer(t, Options{Dial: redirectTo(startUpstream(t, acceptInto(accepted)), &dials)},
		&fakeResolver{hosts: exampleHosts})
	d, err := xproxy.SOCKS5("tcp", s.Addr().String(), nil, xproxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	for target, want := range map[string]string{
		"example.test:443":   "203.0.113.20:443", // sent as a domain name (socks5h behaviour)
		"203.0.113.10:443":   "203.0.113.10:443",
		"[2001:db8::10]:443": "[2001:db8::10]:443",
	} {
		c, err := d.(xproxy.ContextDialer).DialContext(ctx, "tcp", target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		up := receive(t, accepted)
		if bound := c.(interface{ BoundAddr() net.Addr }).BoundAddr(); bound.String() != up.RemoteAddr().String() {
			t.Errorf("%s: bound address %v, upstream sees %v", target, bound, up.RemoteAddr())
		}
		echo(t, c, up, "hello "+target)
		echo(t, up, c, "world "+target)
		c.Close()
		if got := dials.list(); got[len(got)-1] != want {
			t.Errorf("%s: dialed %q, want %q", target, got[len(got)-1], want)
		}
	}
}

// TestCurlClients drives the proxy with the curl binary, the reference client
// for socks5h, socks4a and HTTP CONNECT tunnels.
func TestCurlClients(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl not installed")
	}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s", r.Host)
	}))
	defer web.Close()
	var dials recorder
	s := startServer(t, Options{Dial: redirectTo(web.Listener.Addr().String(), &dials)}, &fakeResolver{hosts: exampleHosts})
	proxy := s.Addr().String()
	cases := []struct {
		name string
		args []string
		host string
		dial string
	}{
		{"socks5h", []string{"--proxy", "socks5h://" + proxy, "http://example.test/"}, "example.test", "203.0.113.20:80"},
		{"socks5", []string{"--socks5", proxy, "http://203.0.113.21/"}, "203.0.113.21", "203.0.113.21:80"},
		{"socks4", []string{"--socks4", proxy, "http://203.0.113.22:8080/"}, "203.0.113.22:8080", "203.0.113.22:8080"},
		{"socks4a", []string{"--socks4a", proxy, "http://example.test/"}, "example.test", "203.0.113.20:80"},
		{"http connect", []string{"--proxytunnel", "--proxy", "http://" + proxy, "http://example.test/"}, "example.test", "203.0.113.20:80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-q", "--silent", "--show-error", "--max-time", "5"}, tc.args...)
			cmd := exec.Command(curl, args...)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")} // no *_proxy variables
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("curl: %v: %s", err, out)
			}
			if string(out) != "host="+tc.host {
				t.Errorf("curl got %q", out)
			}
			if got := dials.list(); got[len(got)-1] != tc.dial {
				t.Errorf("dialed %q, want %q", got[len(got)-1], tc.dial)
			}
		})
	}
}

// TestProtocolRejections checks the reply to requests the proxy does not
// serve, that the connection is closed afterwards, and that nothing is dialed.
func TestProtocolRejections(t *testing.T) {
	greeting := socks5Greeting(socks5NoAuth)
	accepted := []byte{socks5Version, socks5NoAuth}
	socks5Fail := func(code byte) []byte {
		return slices.Concat(accepted, []byte{5, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	}
	socks4Fail := []byte{0, socks4Rejected, 0, 0, 0, 0, 0, 0}
	ipv4 := []byte{203, 0, 113, 1}
	cases := []struct {
		name string
		send []byte
		want []byte // exact bytes before the server closes
		http int    // or the HTTP status
	}{
		{name: "socks5 no acceptable method", send: socks5Greeting(0x02), want: []byte{5, 0xff}},
		{name: "socks5 no methods", send: socks5Greeting(), want: []byte{5, 0xff}},
		{name: "socks5 bind", send: slices.Concat(greeting, socks5Request(0x02, atypIPv4, ipv4, 80)), want: socks5Fail(0x07)},
		{name: "socks5 udp associate", send: slices.Concat(greeting, socks5Request(0x03, atypIPv4, ipv4, 80)), want: socks5Fail(0x07)},
		{name: "socks5 unknown command", send: slices.Concat(greeting, socks5Request(0x09, atypDomain, []byte("\x01a"), 80)), want: socks5Fail(0x07)},
		{name: "socks5 unknown address type", send: slices.Concat(greeting, []byte{5, 1, 0, 0x02}), want: socks5Fail(0x08)},
		{name: "socks5 empty domain", send: slices.Concat(greeting, socks5Domain("", 80)), want: socks5Fail(0x01)},
		{name: "socks5 NUL in domain", send: slices.Concat(greeting, socks5Domain("evil\x00.test", 80)), want: socks5Fail(0x01)},
		{name: "socks5 bad request version", send: slices.Concat(greeting, []byte{4, 1, 0, 1}), want: socks5Fail(0x01)},
		{name: "socks4 bind", send: socks4Request(0x02, [4]byte{203, 0, 113, 1}, 80, "", ""), want: socks4Fail},
		{name: "socks4a empty hostname", send: append(socks4Request(socks4Connect, [4]byte{0, 0, 0, 1}, 80, "u", ""), 0), want: socks4Fail},
		{name: "socks4a hostname too long", send: socks4Request(socks4Connect, [4]byte{0, 0, 0, 1}, 80, "", strings.Repeat("a", 256)), want: socks4Fail},
		{name: "http GET", send: []byte("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"), http: http.StatusMethodNotAllowed},
		{name: "http target without port", send: []byte("CONNECT example.test HTTP/1.1\r\n\r\n"), http: http.StatusBadRequest},
		{name: "http port 0", send: []byte("CONNECT example.test:0 HTTP/1.1\r\n\r\n"), http: http.StatusBadRequest},
		{name: "http/2 version", send: []byte("CONNECT example.test:443 HTTP/2.0\r\n\r\n"), http: http.StatusBadRequest},
		{name: "http malformed version", send: []byte("CONNECT example.test:443 HTTP/1.1x\r\n\r\n"), http: http.StatusBadRequest},
		{name: "http empty request line", send: []byte("\r\n\r\n"), http: http.StatusBadRequest},
		{name: "http head too large", send: []byte("CONNECT example.test:443 HTTP/1.1\r\n" +
			strings.Repeat("X-Pad: "+strings.Repeat("p", 60)+"\r\n", 130) + "\r\n"), http: http.StatusRequestHeaderFieldsTooLarge},
		{name: "http line too long", send: []byte("CONNECT " + strings.Repeat("a", maxHTTPHead) + ":443 HTTP/1.1\r\n\r\n"), http: http.StatusRequestHeaderFieldsTooLarge},
	}
	var dials recorder
	resolver := &fakeResolver{hosts: map[string][]netip.Addr{
		"example.test.": addrs("203.0.113.20"),
		// Malformed names are refused before DNS, whatever it would answer.
		".":                            addrs("203.0.113.20"),
		strings.Repeat("a", 256) + ".": addrs("203.0.113.20"),
	}}
	s := startServer(t, Options{Dial: redirectTo(startUpstream(t, pong), &dials)}, resolver)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := dialProxy(t, s)
			if _, err := c.Write(tc.send); err != nil {
				t.Fatal(err)
			}
			if tc.http != 0 {
				resp := readResponse(t, c)
				if resp.StatusCode != tc.http {
					t.Fatalf("status %d, want %d", resp.StatusCode, tc.http)
				}
				if tc.http == http.StatusMethodNotAllowed && resp.Header.Get("Allow") != "CONNECT" {
					t.Errorf("Allow header %q", resp.Header.Get("Allow"))
				}
				expectClosed(t, c)
				return
			}
			// The server may reset the connection after replying when it left
			// request bytes unread, so keep what arrived before any error.
			got, err := io.ReadAll(c)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %x (%v), want %x", got, err, tc.want)
			}
		})
	}
	if got := dials.list(); len(got) != 0 {
		t.Errorf("rejected requests dialed %q", got)
	}
}

// TestConnectFailureReplies maps each connect failure to its reply code in all
// three protocols.
func TestConnectFailureReplies(t *testing.T) {
	refused := dialErr(syscall.ECONNREFUSED)
	cases := []struct {
		name    string
		host    string
		dialErr error // nil: the dial hangs until its context ends
		socks5  byte
		http    int
	}{
		{"refused", "203.0.113.1", refused, 0x05, http.StatusBadGateway},
		{"host unreachable", "203.0.113.1", dialErr(syscall.EHOSTUNREACH), 0x04, http.StatusBadGateway},
		{"network unreachable", "2001:db8::1", dialErr(syscall.ENETUNREACH), 0x04, http.StatusBadGateway},
		{"timeout", "203.0.113.1", nil, 0x06, http.StatusGatewayTimeout},
		{"other error", "203.0.113.1", errors.New("boom"), 0x01, http.StatusBadGateway},
		{"unknown host", "missing.test", refused, 0x04, http.StatusBadGateway},
		{"dns timeout", "slow.test", refused, 0x06, http.StatusGatewayTimeout},
		{"policy", "10.0.0.1", refused, 0x02, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
				if tc.dialErr != nil {
					return nil, tc.dialErr
				}
				<-ctx.Done()
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
			}
			resolver := &fakeResolver{errs: map[string]error{
				"slow.test.": &net.DNSError{Err: "i/o timeout", Name: "slow.test.", IsTimeout: true},
			}}
			s := startServer(t, Options{Dial: dial, DialTimeout: 100 * time.Millisecond}, resolver)

			socks5Code, socks4Code, status := probe(t, s, tc.host, 443)
			if socks5Code != tc.socks5 {
				t.Errorf("socks5 reply %#x, want %#x", socks5Code, tc.socks5)
			}
			if socks4Code != socks4Rejected {
				t.Errorf("socks4a reply %#x", socks4Code)
			}
			if status != tc.http {
				t.Errorf("http status %d, want %d", status, tc.http)
			}

			wantRejected := int64(0)
			if tc.socks5 == 0x02 {
				wantRejected = 3
			}
			waitFor(t, "connections to finish", func() bool { return s.Stats().GetSnapshot().ActiveConns == 0 })
			if got := s.Stats().GetSnapshot().Rejected; got != wantRejected {
				t.Errorf("rejected counter %d, want %d", got, wantRejected)
			}
		})
	}
}

// Candidates are tried in resolver order; the reply reflects the last failure.
func TestDialFallback(t *testing.T) {
	refused, unreachable := dialErr(syscall.ECONNREFUSED), dialErr(syscall.EHOSTUNREACH)
	connect := redirectTo(startUpstream(t, pong), nil)
	resolver := &fakeResolver{hosts: map[string][]netip.Addr{
		"multi.test.": addrs("203.0.113.1", "2001:db8::2", "203.0.113.3"),
	}}
	all := []string{"203.0.113.1:80", "[2001:db8::2]:80", "203.0.113.3:80"}
	cases := []struct {
		name  string
		fails map[string]error // by address; others connect
		code  byte
		dials []string
	}{
		{"second succeeds", map[string]error{all[0]: refused}, socks5Succeeded, all[:2]},
		{"last error wins: unreachable", map[string]error{all[0]: refused, all[1]: refused, all[2]: unreachable}, 0x04, all},
		{"last error wins: refused", map[string]error{all[0]: unreachable, all[1]: unreachable, all[2]: refused}, 0x05, all},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dials recorder
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.add(address)
				if err := tc.fails[address]; err != nil {
					return nil, err
				}
				return connect(ctx, network, address)
			}
			s := startServer(t, Options{Dial: dial}, resolver)
			c := dialProxy(t, s)
			code, _ := socks5Connect(t, c, socks5Domain("multi.test", 80))
			if code != tc.code {
				t.Fatalf("reply %#x, want %#x", code, tc.code)
			}
			if code == socks5Succeeded {
				exchange(t, c, "fallback")
			}
			if got := dials.list(); !slices.Equal(got, tc.dials) {
				t.Errorf("dialed %q, want %q", got, tc.dials)
			}
		})
	}
}

// Each attempt gets an even share of what is left of DialTimeout, so a
// black-holed first address cannot use up the budget of the others.
func TestDialBudgetIsShared(t *testing.T) {
	budgets := make(chan time.Duration, 2)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		dl, _ := ctx.Deadline()
		budgets <- time.Until(dl)
		return nil, dialErr(syscall.ECONNREFUSED)
	}
	resolver := &fakeResolver{hosts: map[string][]netip.Addr{"multi.test.": addrs("203.0.113.1", "203.0.113.2")}}
	s := startServer(t, Options{Dial: dial, DialTimeout: 10 * time.Second}, resolver)
	c := dialProxy(t, s)
	if code, _ := socks5Connect(t, c, socks5Domain("multi.test", 80)); code != 0x05 {
		t.Fatalf("reply %#x", code)
	}
	first, second := <-budgets, <-budgets
	if first > 5*time.Second || first < 4*time.Second || second < 9*time.Second {
		t.Fatalf("attempt budgets %v and %v, want about 5s and 10s", first, second)
	}
}

package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestBlocked(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1": true, "127.255.255.254": true, "::1": true,
		"::ffff:127.0.0.1": true, "::ffff:10.1.2.3": true, "::ffff:192.168.0.1": true, "::ffff:1.1.1.1": false,
		"::ffff:100.64.0.1": true, "::ffff:0.0.0.1": true, "::ffff:255.255.255.255": true, // prefixes need Unmap
		"10.0.0.1": true, "10.255.255.255": true, "11.0.0.1": false,
		"172.16.0.1": true, "172.31.255.255": true, "172.15.255.255": false, "172.32.0.1": false,
		"192.168.0.1": true, "192.168.255.255": true, "192.169.0.1": false,
		"100.64.0.1": true, "100.127.255.255": true, "100.63.255.255": false, "100.128.0.0": false,
		"169.254.169.254": true, "169.255.0.1": false,
		"fe80::1": true, "fe80::1%eth0": true, "febf::1": true,
		"fc00::1": true, "fd12:3456::1": true, "fe00::1": false,
		"0.0.0.0": true, "0.1.2.3": true, "::": true,
		"224.0.0.1": true, "239.255.255.250": true, "ff02::1": true, "ff0e::1": true, "255.255.255.255": true,
		"1.1.1.1": false, "203.0.113.1": false, "2606:4700:4700::1111": false, "2001:db8::1": false,
	}
	for ip, want := range cases {
		if got := blocked(netip.MustParseAddr(ip)); got != want {
			t.Errorf("blocked(%s) = %v, want %v", ip, got, want)
		}
	}
	if !blocked(netip.Addr{}) {
		t.Error("the zero Addr must be blocked")
	}
}

func TestParseIPHost(t *testing.T) {
	cases := map[string]string{ // "" = not an address, left to the resolver
		"127.0.0.1": "127.0.0.1", "[::1]": "::1", "::ffff:127.0.0.1": "::ffff:127.0.0.1", "fe80::1%eth0": "fe80::1%eth0",
		"2130706433": "127.0.0.1", "0x7f.1": "127.0.0.1", "127.1": "127.0.0.1", "127.0.1": "127.0.0.1",
		"0177.0.0.1": "127.0.0.1", "0x7f000001": "127.0.0.1", "017700000001": "127.0.0.1", "0X7F.0.0.1": "127.0.0.1",
		"127.0.0.1.": "127.0.0.1", "127.1.": "127.0.0.1", "10.0x10.1": "10.16.0.1", "0": "0.0.0.0", "16843009": "1.1.1.1",
		"example.com": "", "1e100.net": "", "256.0.0.1": "", "1.2.3.4.5": "", "4294967296": "", "0x100.1": "",
		"08.1": "", "0x": "", "1..1": "", "-1": "", "+1": "", "1_000": "", "": "", ".": "", "127.0.0.1..": "",
		"1.2.3.256": "", "1.2.65536": "", "1.16777216": "", // the last part overflows the bytes left
	}
	for host, want := range cases {
		ip, ok := parseIPHost(host)
		if ok && ip.String() != want || !ok && want != "" {
			t.Errorf("parseIPHost(%q) = %v, %v; want %q", host, ip, ok, want)
		}
	}
}

func TestIsLocalhost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "LocalHost": true, "localhost.": true, "a.localhost": true, "a.b.LOCALHOST.": true,
		"localhost.example.com": false, "notlocalhost": false, "mylocalhost.": false, "": false,
	} {
		if got := isLocalhost(host); got != want {
			t.Errorf("isLocalhost(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestPolicyRefusesInternalDestinations sends every internal destination
// through all three protocols: each gets the policy reply, nothing is dialed,
// and numeric or localhost names never reach the resolver.
func TestPolicyRefusesInternalDestinations(t *testing.T) {
	literals := []string{
		"127.0.0.1", "::1", "::ffff:127.0.0.1", "::ffff:10.1.2.3", "10.0.0.1", "172.16.5.4", "172.31.255.255",
		"192.168.1.1", "100.64.0.1", "100.127.255.254", "169.254.169.254", "fe80::1", "fc00::1", "fd12::1",
		"0.0.0.0", "0.1.2.3", "::", "224.0.0.1", "239.255.255.250", "ff02::1", "255.255.255.255",
	}
	names := []string{
		"2130706433", "0x7f.1", "127.1", "0177.0.0.1", "0x7f000001", "127.0.0.1.", "0", "[::1]",
		"localhost", "LOCALHOST.", "foo.localhost", "internal.test", "docker.test", "mapped.test",
	}
	resolved := []string{"internal.test", "docker.test", "mapped.test"}
	resolver := &fakeResolver{hosts: map[string][]netip.Addr{
		"internal.test": addrs("10.0.0.5", "fd00::5"),
		"docker.test":   addrs("172.18.0.2"),
		"mapped.test":   addrs("::ffff:192.168.1.1"),
		// DNS must not be able to turn localhost into something else.
		"localhost":     addrs("203.0.113.66"),
		"foo.localhost": addrs("203.0.113.66"),
	}}
	var dials recorder
	s := startServer(t, Options{Dial: redirectTo(startUpstream(t, pong), &dials)}, resolver)

	rejections := 0
	for _, ip := range literals {
		c := dialProxy(t, s)
		if code, _ := socks5Connect(t, c, socks5IP(ip, 80)); code != 0x02 {
			t.Errorf("socks5 IP %s: reply %#x, want 0x02", ip, code)
		}
		rejections++
		if a := netip.MustParseAddr(ip); a.Is4() {
			c := dialProxy(t, s)
			if _, err := c.Write(socks4Request(socks4Connect, a.As4(), 80, "", "")); err != nil {
				t.Fatal(err)
			}
			if code := readSOCKS4Reply(t, c); code != socks4Rejected {
				t.Errorf("socks4 %s: reply %#x", ip, code)
			}
			rejections++
		}
	}
	for _, host := range slices.Concat(literals, names) {
		socks5Code, socks4Code, status := probe(t, s, host, 80)
		if socks5Code != 0x02 || socks4Code != socks4Rejected || status != http.StatusForbidden {
			t.Errorf("%q: replies %#x, %#x, %d; want 0x02, 0x5b, 403", host, socks5Code, socks4Code, status)
		}
		rejections += 3
	}

	if got := dials.list(); len(got) != 0 {
		t.Errorf("dialed %q", got)
	}
	for _, name := range resolver.asked.list() {
		if !slices.Contains(resolved, name) {
			t.Errorf("resolver was asked for %q", name)
		}
	}
	waitFor(t, "connections to finish", func() bool { return s.Stats().GetSnapshot().ActiveConns == 0 })
	if got := s.Stats().GetSnapshot().Rejected; got != int64(rejections) {
		t.Errorf("rejected counter %d, want %d", got, rejections)
	}
}

// Only the allowed candidates of a mixed answer are dialed, in resolver order.
func TestPolicyDialsOnlyAllowedCandidates(t *testing.T) {
	resolver := &fakeResolver{hosts: map[string][]netip.Addr{
		"mixed.test": addrs("10.0.0.1", "203.0.113.7", "::1", "2001:db8::8", "192.168.0.9"),
	}}

	var dials recorder
	s := startServer(t, Options{Dial: redirectTo(startUpstream(t, pong), &dials)}, resolver)
	c := dialProxy(t, s)
	mustSOCKS5(t, c, socks5Domain("mixed.test", 443))
	exchange(t, c, "mixed")
	if got := dials.list(); !slices.Equal(got, []string{"203.0.113.7:443"}) {
		t.Errorf("dialed %q", got)
	}

	var failed recorder
	refuse := func(_ context.Context, _, address string) (net.Conn, error) {
		failed.add(address)
		return nil, dialErr(syscall.ECONNREFUSED)
	}
	s = startServer(t, Options{Dial: refuse}, resolver)
	c = dialProxy(t, s)
	if code, _ := socks5Connect(t, c, socks5Domain("mixed.test", 443)); code != 0x05 {
		t.Fatalf("reply %#x, want 0x05", code)
	}
	if got := failed.list(); !slices.Equal(got, []string{"203.0.113.7:443", "[2001:db8::8]:443"}) {
		t.Errorf("dialed %q", got)
	}
	if got := s.Stats().GetSnapshot().Rejected; got != 0 {
		t.Errorf("a dial failure counted as %d rejection(s)", got)
	}
}

// With AllowPrivate the real default dialer reaches loopback.
func TestAllowPrivate(t *testing.T) {
	upstream := startUpstream(t, pong)
	port := netip.MustParseAddrPort(upstream).Port()
	resolver := &fakeResolver{hosts: map[string][]netip.Addr{
		"internal.test": addrs("127.0.0.3", "127.0.0.1"), // nothing listens on .3: refused, then fallback
	}}
	s := startServer(t, Options{AllowPrivate: true, DialTimeout: testTimeout}, resolver)
	for _, req := range [][]byte{
		socks5IP("127.0.0.1", port),
		socks5IP("::ffff:127.0.0.1", port),
		socks5Domain("localhost", port),
		socks5Domain("2130706433", port),
		socks5Domain("internal.test", port),
	} {
		c := dialProxy(t, s)
		mustSOCKS5(t, c, req)
		exchange(t, c, "private")
	}
	if got := s.Stats().GetSnapshot().Rejected; got != 0 {
		t.Errorf("rejected counter %d", got)
	}
}

// The default dialer refuses internal addresses on its own, behind the checks
// in connect. The listener is on 127.0.0.2 because a connection there is not
// also a self-connection, which refuseSelf would catch instead of Control.
func TestDefaultDialerRechecksPolicy(t *testing.T) {
	upstream := startUpstreamAt(t, "127.0.0.2:0", func(net.Conn) {})
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	_, err := NewServer(Options{}).dial(ctx, "tcp", upstream)
	if !errors.Is(err, errBlocked) || classify(err) != failPolicy {
		t.Fatalf("default dialer reached %s: %v", upstream, err)
	}
	c, err := NewServer(Options{AllowPrivate: true}).dial(ctx, "tcp", upstream)
	if err != nil {
		t.Fatalf("AllowPrivate dialer: %v", err)
	}
	c.Close()
}

// A connection to one of this host's own addresses has the same local and
// remote IP. 127.0.0.2 shows the other case: the kernel picks 127.0.0.1 as
// the source for every loopback address but the primary one.
func TestRefuseSelf(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	var d net.Dialer
	dial := refuseSelf(d.DialContext)

	_, err := dial(ctx, "tcp", startUpstream(t, pong))
	if !errors.Is(err, errBlocked) || classify(err) != failPolicy {
		t.Errorf("connection to an own address: %v", err)
	}
	c, err := dial(ctx, "tcp", startUpstreamAt(t, "127.0.0.2:0", func(net.Conn) {}))
	if err != nil {
		t.Fatalf("connection from 127.0.0.1 to 127.0.0.2 refused: %v", err)
	}
	c.Close()
}

func TestParseDNSServer(t *testing.T) {
	for in, want := range map[string]string{
		"1.1.1.1": "1.1.1.1:53", "1.1.1.1:5353": "1.1.1.1:5353",
		"2606:4700::1111": "[2606:4700::1111]:53", "[2606:4700::1111]:853": "[2606:4700::1111]:853",
	} {
		if got, err := parseDNSServer(in); err != nil || got != want {
			t.Errorf("parseDNSServer(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"dns.google", "1.1.1.1:0", "1.1.1.1:dns", "[::1]", "1.1.1.1:53:53"} {
		if got, err := parseDNSServer(in); err == nil {
			t.Errorf("parseDNSServer(%q) = %q, want an error", in, got)
		}
	}

	s := NewServer(Options{ListenAddr: "127.0.0.1:0", DNSServers: []string{"1.1.1.1", "dns.google"}})
	if err := s.Listen(); err == nil || !strings.Contains(err.Error(), "dns.google") {
		t.Errorf("Listen with an invalid DNS server: %v", err)
	}
	if err := s.Serve(); err == nil {
		t.Error("Serve after a failed Listen returned nil")
	}
	if err := s.Stop(); err != nil {
		t.Error(err)
	}
}

// TestDNSServers resolves through the configured servers: a refusing one (closed
// port) and a failing one (SERVFAIL) are passed over within the first lookup,
// and later lookups start at the server that answered.
func TestDNSServers(t *testing.T) {
	live := startDNSServer(t, map[string]netip.Addr{"public.test.": netip.MustParseAddr("203.0.113.9")}, dnsmessage.RCodeNameError)
	failing := startDNSServer(t, nil, dnsmessage.RCodeServerFailure)
	var dials recorder
	s := startServer(t, Options{
		DNSServers: []string{closedUDPPort(t), failing.addr, live.addr},
		Dial:       redirectTo(startUpstream(t, pong), &dials),
	}, nil)

	c := dialProxy(t, s)
	mustSOCKS5(t, c, socks5Domain("public.test", 80))
	exchange(t, c, "dns")
	if got := dials.list(); !slices.Equal(got, []string{"203.0.113.9:80"}) {
		t.Errorf("dialed %q", got)
	}
	if failing.queries.Load() == 0 {
		t.Error("the failing server was skipped, not tried")
	}

	failed, answered := failing.queries.Load(), live.queries.Load()
	mustSOCKS5(t, dialProxy(t, s), socks5Domain("public.test", 80))
	if failing.queries.Load() != failed || live.queries.Load() == answered {
		t.Error("the second lookup did not start at the server that answered")
	}
	c = dialProxy(t, s)
	if code, _ := socks5Connect(t, c, socks5Domain("missing.test", 80)); code != 0x04 {
		t.Errorf("unknown name: reply %#x, want 0x04", code)
	}
	if failing.queries.Load() != failed {
		t.Error("a name that does not exist moved on to the next server")
	}
}

type dnsServer struct {
	addr    string
	queries atomic.Int64
}

// startDNSServer answers A queries for names (FQDNs) and every other query
// with rcode.
func startDNSServer(t *testing.T, names map[string]netip.Addr, rcode dnsmessage.RCode) *dnsServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	srv := &dnsServer{addr: pc.LocalAddr().String()}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			srv.queries.Add(1)
			ip, known := names[q.Name.String()]
			rh := dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true}
			if !known {
				rh.RCode = rcode
			}
			b := dnsmessage.NewBuilder(nil, rh)
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			if known && q.Type == dnsmessage.TypeA {
				_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.AResource{A: ip.As4()})
			}
			if msg, err := b.Finish(); err == nil {
				_, _ = pc.WriteTo(msg, from)
			}
		}
	}()
	return srv
}

func closedUDPPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

//go:build linux && integration

package tunnel

// These tests need root and a throwaway network namespace:
//
//	go test -c -race -tags integration -o /tmp/tunnel/tunnel.test ./pkg/tunnel
//	sudo unshare --net /tmp/tunnel/tunnel.test -test.v -test.count=1
//
// Each test fails when it finds itself in the init network namespace. Kernel
// mode subtests skip when the kernel has no WireGuard, unless
// TUNNEL_REQUIRE_KERNEL_WIREGUARD=1 turns that into a failure (CI).
//
// Topology, built per test inside that namespace ("client", rp_filter=1):
//
//	client netns                              peer netns
//	wgt-c 10.200.0.1/24 ── veth ─────────── wgt-p 10.200.0.2/24
//	      198.18.0.1/24                             198.18.0.2/24     (connected, not private)
//	      2001:db8:1::1/64                          2001:db8:1::2/64
//	default via 10.200.0.2, 2001:db8:1::2     lo: 203.0.113.1 (WireGuard endpoint), 192.0.2.50 (remote client)
//	warp0 172.16.0.2/32, fd00::2/128 ═ WG ═   wgpeer 172.16.0.1/24, fd00::1/64 (wireguard-go)
//	                                          lo: 198.51.100.10, 2001:db8::10; echo on :7777
//
// The peer reaches the client's subnet with source 203.0.113.1, so WireGuard
// answers from the endpoint address and the client never roams to another
// one. The echo server answers with the source address it saw, which tells
// whether a connection went through the tunnel (172.16.0.2 / fd00::2) or not.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	endpoint     = "203.0.113.1:51820"
	deadEndpoint = "203.0.113.9:51820" // routed to the peer, which drops it
	unresolvable = "unresolvable.invalid:51820"
	publicV4     = "198.51.100.10"
	publicV6     = "2001:db8::10"
	remoteClient = "192.0.2.50"
	peerVeth4    = "10.200.0.2"
	clientVeth4  = "10.200.0.1"
	peerGUA4     = "198.18.0.2"
	clientGUA4   = "198.18.0.1"
	peerGUA6     = "2001:db8:1::2"
	clientGUA6   = "2001:db8:1::1"
	clientInner4 = "172.16.0.2"
	clientInner6 = "fd00::2"
	echoPort     = "7777"

	marked   = DefaultMark
	unmarked = 0
)

func requireIsolatedNetns(t *testing.T) {
	t.Helper()
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("inspect own network namespace: %v", err)
	}
	init, err := os.Stat("/proc/1/ns/net")
	if err != nil {
		t.Fatalf("inspect init network namespace (run as root under `unshare --net`): %v", err)
	}
	if os.SameFile(self, init) {
		t.Fatal("refusing to run in the init network namespace; run the test binary under `sudo unshare --net`")
	}
}

// onThrowawayThread runs fn on an OS thread that is locked and never unlocked,
// so the runtime discards it afterwards; fn may switch it to another netns.
func onThrowawayThread(fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		errc <- fn()
	}()
	return <-errc
}

func inNetns(ns netns.NsHandle, fn func() error) error {
	return onThrowawayThread(func() error {
		if err := netns.Set(ns); err != nil {
			return err
		}
		return fn()
	})
}

func newNetns(t *testing.T) (ns netns.NsHandle) {
	t.Helper()
	err := onThrowawayThread(func() (err error) {
		ns, err = netns.New()
		return err
	})
	if err != nil {
		t.Fatalf("create network namespace: %v", err)
	}
	return ns
}

type testbed struct {
	clientKey wgtypes.Key
	peerKey   wgtypes.Key
	peerNs    netns.NsHandle
}

func newTestbed(t *testing.T) *testbed {
	requireIsolatedNetns(t)
	b := &testbed{clientKey: testKey(t), peerKey: testKey(t), peerNs: newNetns(t)}
	t.Cleanup(func() { b.peerNs.Close() })

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "wgt-c"}, PeerName: "wgt-p",
		PeerNamespace: netlink.NsFd(b.peerNs)}
	must(t, netlink.LinkAdd(veth))
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	lo, err := netlink.LinkByName("lo")
	must(t, err)
	must(t, netlink.LinkSetUp(lo))
	must(t, addAddrs(veth, clientVeth4+"/24", clientGUA4+"/24", clientGUA6+"/64"))
	must(t, netlink.LinkSetUp(veth))
	must(t, netlink.RouteAdd(&netlink.Route{LinkIndex: veth.Attrs().Index, Gw: net.ParseIP(peerVeth4)}))
	must(t, netlink.RouteAdd(&netlink.Route{LinkIndex: veth.Attrs().Index, Gw: net.ParseIP(peerGUA6)}))
	// Strict reverse-path filtering, as on CIS-hardened hosts.
	for _, iface := range []string{"all", "default", "wgt-c"} {
		setSysctl(t, "/proc/sys/net/ipv4/conf/"+iface+"/rp_filter", "1")
	}

	var peerDev *device.Device
	var echo net.Listener
	err = inNetns(b.peerNs, func() (err error) {
		peerDev, echo, err = b.setupPeer()
		return err
	})
	if peerDev != nil {
		t.Cleanup(peerDev.Close)
	}
	must(t, err)
	t.Cleanup(func() { echo.Close() })
	go serveEcho(echo)
	return b
}

// setupPeer runs inside the peer netns, so every socket and link it creates
// lives there.
func (b *testbed) setupPeer() (*device.Device, net.Listener, error) {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return nil, nil, err
	}
	if err := addAddrs(lo, "203.0.113.1/32", remoteClient+"/32", publicV4+"/32", publicV6+"/128"); err != nil {
		return nil, nil, err
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return nil, nil, err
	}
	veth, err := netlink.LinkByName("wgt-p")
	if err != nil {
		return nil, nil, err
	}
	if err := addAddrs(veth, peerVeth4+"/24", peerGUA4+"/24", peerGUA6+"/64"); err != nil {
		return nil, nil, err
	}
	if err := netlink.LinkSetUp(veth); err != nil {
		return nil, nil, err
	}
	err = netlink.RouteReplace(&netlink.Route{LinkIndex: veth.Attrs().Index, Scope: netlink.SCOPE_LINK,
		Dst: ipNet(netip.MustParsePrefix("10.200.0.0/24")), Src: net.ParseIP("203.0.113.1")})
	if err != nil {
		return nil, nil, err
	}

	tdev, err := tun.CreateTUN("wgpeer", 1280)
	if err != nil {
		return nil, nil, err
	}
	dev := device.NewDevice(newQuietTUN(tdev), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	client := b.clientKey.PublicKey()
	err = dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=51820\npublic_key=%s\n"+
		"allowed_ip=172.16.0.2/32\nallowed_ip=fd00::2/128\n",
		hex.EncodeToString(b.peerKey[:]), hex.EncodeToString(client[:])))
	if err != nil {
		return dev, nil, err
	}
	link, err := netlink.LinkByName("wgpeer")
	if err != nil {
		return dev, nil, err
	}
	if err := addAddrs(link, "172.16.0.1/24", "fd00::1/64"); err != nil {
		return dev, nil, err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return dev, nil, err
	}
	if err := dev.Up(); err != nil {
		return dev, nil, err
	}
	echo, err := net.Listen("tcp", ":"+echoPort)
	return dev, echo, err
}

// quietTUN hides link up/down events from the peer's wireguard-go: acting on
// them would rebind its sockets from a thread outside the peer netns.
type quietTUN struct {
	tun.Device
	events chan tun.Event
	once   sync.Once
}

func newQuietTUN(d tun.Device) *quietTUN {
	go func() {
		for range d.Events() {
		}
	}()
	return &quietTUN{Device: d, events: make(chan tun.Event)}
}

func (q *quietTUN) Events() <-chan tun.Event { return q.events }

func (q *quietTUN) Close() error {
	q.once.Do(func() { close(q.events) })
	return q.Device.Close()
}

func serveEcho(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		src := c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
		_, _ = io.WriteString(c, src.String())
		c.Close()
	}
}

// echoReply dials addr and returns what the echo server answered: the
// source address it saw.
func echoReply(d net.Dialer, addr string) (string, error) {
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(d.Timeout))
	b, err := io.ReadAll(c)
	return string(b), err
}

// sourceSeenBy connects to the echo server on dst from a socket carrying mark
// (0: none) and returns the source address the server saw.
func sourceSeenBy(dst string, mark uint32, timeout time.Duration) (string, error) {
	d := net.Dialer{Timeout: timeout}
	if mark != 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var err error
			if cerr := c.Control(func(fd uintptr) {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			}); cerr != nil {
				return cerr
			}
			return err
		}
	}
	return echoReply(d, net.JoinHostPort(dst, echoPort))
}

func expectSource(t *testing.T, dst string, mark uint32, want string) {
	t.Helper()
	got, err := sourceSeenBy(dst, mark, 15*time.Second)
	if err != nil || got != want {
		t.Fatalf("connection to %s (mark %#x): peer saw %q (err %v), want %s", dst, mark, got, err, want)
	}
}

func expectUnreachable(t *testing.T, dst string, mark uint32) {
	t.Helper()
	got, err := sourceSeenBy(dst, mark, 5*time.Second)
	if !errors.Is(err, unix.ENETUNREACH) && !errors.Is(err, unix.EHOSTUNREACH) {
		t.Fatalf("connection to %s (mark %#x): peer saw %q (err %v), want unreachable", dst, mark, got, err)
	}
}

// expectRemoteClient checks that a client outside the connected subnets gets
// replies from a server in the client netns, as proxy clients behind Docker's
// published ports do.
func (b *testbed) expectRemoteClient(t *testing.T, server string) {
	t.Helper()
	var got string
	err := inNetns(b.peerNs, func() (err error) {
		got, err = echoReply(net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(remoteClient)}}, server)
		return err
	})
	if err != nil || got != remoteClient {
		t.Fatalf("remote client to %s: got %q (err %v)", server, got, err)
	}
}

func (b *testbed) config(t *testing.T, mode Mode, endpoints ...string) Config {
	return Config{
		Mode:          mode,
		PrivateKey:    b.clientKey.String(),
		PeerPublicKey: b.peerKey.PublicKey().String(),
		Endpoints:     endpoints,
		Addresses:     []netip.Prefix{netip.MustParsePrefix(clientInner4 + "/32"), netip.MustParsePrefix(clientInner6 + "/128")},
		Logger:        slog.New(slog.NewTextHandler(t.Output(), nil)),
	}
}

func up(t *testing.T, cfg Config) *Tunnel {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tn, err := Up(ctx, cfg)
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	t.Cleanup(func() { _ = tn.Close() })
	return tn
}

func kernelWireGuard(t *testing.T) bool {
	t.Helper()
	requireIsolatedNetns(t)
	attrs := netlink.NewLinkAttrs()
	attrs.Name = "wgprobe"
	link := &netlink.Wireguard{LinkAttrs: attrs}
	err := netlink.LinkAdd(link)
	if err == nil {
		must(t, netlink.LinkDel(link))
		return true
	}
	if errors.Is(err, unix.EOPNOTSUPP) {
		return false
	}
	t.Fatalf("probe kernel WireGuard: %v", err)
	return false
}

func skipWithoutKernelWireGuard(t *testing.T) {
	t.Helper()
	const reason = "kernel has no WireGuard support (EOPNOTSUPP creating a wireguard link)"
	if os.Getenv("TUNNEL_REQUIRE_KERNEL_WIREGUARD") == "1" {
		t.Fatal(reason)
	}
	t.Skip(reason)
}

// forModes runs fn for userspace and, when the kernel has WireGuard, kernel mode.
func forModes(t *testing.T, fn func(t *testing.T, mode Mode)) {
	t.Run("userspace", func(t *testing.T) { fn(t, ModeUserspace) })
	t.Run("kernel", func(t *testing.T) {
		if !kernelWireGuard(t) {
			skipWithoutKernelWireGuard(t)
		}
		fn(t, ModeKernel)
	})
}

func ownRules(t *testing.T, family int) []netlink.Rule {
	t.Helper()
	rules, err := netlink.RuleList(family)
	must(t, err)
	var out []netlink.Rule
	for _, r := range rules {
		if ownRule(r, DefaultTable) {
			out = append(out, r)
		}
	}
	return out
}

func listTable(t *testing.T, family int) []netlink.Route {
	t.Helper()
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: DefaultTable}, netlink.RT_FILTER_TABLE)
	must(t, err)
	return routes
}

// assertRouting checks the installed rules and tunnel table; v6 says whether
// the tunnel carries IPv6.
func assertRouting(t *testing.T, v6 bool) {
	t.Helper()
	link, err := netlink.LinkByName(defaultInterface)
	must(t, err)
	if link.Attrs().Alias != linkAlias {
		t.Fatalf("interface alias %q", link.Attrs().Alias)
	}
	for _, f := range []struct {
		family    int
		from      string
		viaTunnel bool
	}{{netlink.FAMILY_V4, clientInner4 + "/32", true}, {netlink.FAMILY_V6, clientInner6 + "/128", v6}} {
		family, viaTunnel := f.family, f.viaTunnel
		// Always the mark rule; with the tunnel carrying the family also the from rule.
		rules := ownRules(t, family)
		want := 1
		if viaTunnel {
			want = 2
		}
		if len(rules) != want || rules[0].Priority != priorityMark || rules[0].Mark != DefaultMark ||
			viaTunnel && (rules[1].Priority != priorityFrom || rules[1].Src.String() != f.from) {
			t.Fatalf("family %d rules: %v", family, rules)
		}
		var tunnel, unreachable int
		for _, r := range listTable(t, family) {
			switch {
			case r.Type == unix.RTN_UNREACHABLE:
				unreachable++
			case r.LinkIndex == link.Attrs().Index:
				tunnel++
			default:
				t.Fatalf("unexpected route in the tunnel table: %v", r)
			}
		}
		if unreachable != 1 || viaTunnel != (tunnel == 1) {
			t.Fatalf("family %d table: %d tunnel and %d unreachable routes", family, tunnel, unreachable)
		}
	}
}

func assertRemoved(t *testing.T) {
	t.Helper()
	if _, err := netlink.LinkByName(defaultInterface); !notExist(err) {
		t.Fatalf("interface still present after Close (err %v)", err)
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if rules, routes := ownRules(t, family), listTable(t, family); len(rules) != 0 || len(routes) != 0 {
			t.Fatalf("left behind: rules %v routes %v", rules, routes)
		}
	}
}

func TestEndToEnd(t *testing.T) {
	forModes(t, func(t *testing.T, mode Mode) {
		b := newTestbed(t)
		server, err := net.Listen("tcp", net.JoinHostPort(clientVeth4, "8080"))
		must(t, err)
		t.Cleanup(func() { server.Close() })
		go serveEcho(server)

		tn := up(t, b.config(t, mode, endpoint, deadEndpoint))
		st, err := tn.Status()
		must(t, err)
		if st.Mode != mode || st.Interface != defaultInterface || st.Endpoint != endpoint || !st.IPv6 {
			t.Fatalf("status after Up: %+v", st)
		}
		assertRouting(t, true)

		// Only marked sockets use the tunnel, including towards connected
		// subnets that are not private.
		expectSource(t, publicV4, marked, clientInner4)
		expectSource(t, publicV4, unmarked, clientVeth4)
		expectSource(t, publicV6, marked, clientInner6)
		expectSource(t, publicV6, unmarked, clientGUA6)
		expectSource(t, peerGUA4, marked, clientInner4)
		expectSource(t, peerGUA4, unmarked, clientGUA4)
		expectSource(t, peerGUA6, marked, clientInner6)
		b.expectRemoteClient(t, server.Addr().String())

		st, err = tn.Status()
		must(t, err)
		if st.LastHandshake.IsZero() || time.Since(st.LastHandshake) > time.Minute || st.RxBytes == 0 || st.TxBytes == 0 {
			t.Fatalf("no handshake or traffic recorded: %+v", st)
		}
		expectSource(t, publicV4, marked, clientInner4)
		later, err := tn.Status()
		must(t, err)
		if later.RxBytes <= st.RxBytes || later.TxBytes <= st.TxBytes {
			t.Fatalf("counters did not grow: %+v then %+v", st, later)
		}

		// The peer answers from the endpoint address, and once its last
		// packets have arrived nothing makes WireGuard roam back, so the
		// dead endpoint must show.
		waitQuiet(t, tn)
		if ep, err := tn.RotateEndpoint(); err != nil || ep != deadEndpoint {
			t.Fatalf("rotate: %q %v", ep, err)
		}
		if _, err := sourceSeenBy(publicV4, marked, 500*time.Millisecond); err == nil {
			t.Fatal("traffic flowed through a dead endpoint")
		}
		if ep, err := tn.RotateEndpoint(); err != nil || ep != endpoint {
			t.Fatalf("rotation did not wrap: %q %v", ep, err)
		}
		expectSource(t, publicV4, marked, clientInner4)

		must(t, tn.Close())
		assertRemoved(t)
		must(t, tn.Close())
		if _, err := tn.Status(); err == nil {
			t.Fatal("Status after Close succeeded")
		}
		if _, err := tn.RotateEndpoint(); err == nil {
			t.Fatal("RotateEndpoint after Close succeeded")
		}
		expectSource(t, publicV4, unmarked, clientVeth4)
	})
}

func TestAutoMode(t *testing.T) {
	want := ModeUserspace
	if kernelWireGuard(t) {
		want = ModeKernel
	}
	b := newTestbed(t)
	tn := up(t, b.config(t, ModeAuto, endpoint))
	if st, err := tn.Status(); err != nil || st.Mode != want {
		t.Fatalf("status: %+v %v, want mode %s", st, err, want)
	}
	expectSource(t, publicV4, marked, clientInner4)
}

// waitQuiet waits until nothing arrives from the peer any more: any
// authenticated packet, e.g. the end of a TCP close, makes WireGuard roam.
func waitQuiet(t *testing.T, tn *Tunnel) {
	t.Helper()
	last := int64(-1)
	for range 20 {
		st, err := tn.Status()
		must(t, err)
		if st.RxBytes == last {
			return
		}
		last = st.RxBytes
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("traffic from the peer did not stop")
}

func TestMarkedIPv6NeverLeaks(t *testing.T) {
	forModes(t, func(t *testing.T, mode Mode) {
		b := newTestbed(t)
		cfg := b.config(t, mode, endpoint)
		cfg.Addresses = cfg.Addresses[:1] // the tunnel has no IPv6
		tn := up(t, cfg)
		if st, err := tn.Status(); err != nil || st.IPv6 {
			t.Fatalf("status: %+v %v", st, err)
		}
		assertRouting(t, false)
		expectUnreachable(t, publicV6, marked) // main has an IPv6 default route
		expectUnreachable(t, peerGUA6, marked) // and a connected IPv6 subnet
		expectSource(t, publicV6, unmarked, clientGUA6)
		expectSource(t, publicV4, marked, clientInner4)
	})
}

func TestIPv6Disabled(t *testing.T) {
	requireIsolatedNetns(t)
	cases := map[string]struct{ all, def string }{
		"all":     {"1", "1"}, // the netns has IPv6 disabled
		"default": {"0", "1"}, // new links come up without IPv6, so the address cannot be added
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			forModes(t, func(t *testing.T, mode Mode) {
				b := newTestbed(t)
				setSysctl(t, "/proc/sys/net/ipv6/conf/all/disable_ipv6", tc.all)
				setSysctl(t, "/proc/sys/net/ipv6/conf/default/disable_ipv6", tc.def)
				tn := up(t, b.config(t, mode, endpoint))
				st, err := tn.Status()
				if err != nil || st.IPv6 {
					t.Fatalf("status: %+v %v", st, err)
				}
				assertRouting(t, false)
				expectSource(t, publicV4, marked, clientInner4)
				must(t, tn.Close())
				assertRemoved(t)
			})
		})
	}
}

func TestRotateSkipsUnresolvableHostname(t *testing.T) {
	oldTimeout, oldBudget := resolveTimeout, resolveBudget
	resolveTimeout, resolveBudget = 500*time.Millisecond, 2*time.Second
	t.Cleanup(func() { resolveTimeout, resolveBudget = oldTimeout, oldBudget })
	forModes(t, func(t *testing.T, mode Mode) {
		b := newTestbed(t)
		// The resolver's queries go out via the main table and are dropped
		// by the peer, so the hostname candidate times out.
		tn := up(t, b.config(t, mode, deadEndpoint, unresolvable, endpoint))
		if _, err := sourceSeenBy(publicV4, marked, 500*time.Millisecond); err == nil {
			t.Fatal("traffic flowed through a dead endpoint")
		}
		start := time.Now()
		ep, err := tn.RotateEndpoint()
		if elapsed := time.Since(start); elapsed > resolveBudget+time.Second {
			t.Fatalf("RotateEndpoint took %v", elapsed)
		}
		if err != nil || ep != endpoint {
			t.Fatalf("rotate: %q %v", ep, err)
		}
		expectSource(t, publicV4, marked, clientInner4)
	})
}

func TestUpRefusesForeignLink(t *testing.T) {
	requireIsolatedNetns(t)
	foreignLinks := map[string]func() netlink.Link{
		"tun": func() netlink.Link {
			return &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: defaultInterface}, Mode: netlink.TUNTAP_MODE_TUN}
		},
		"veth": func() netlink.Link {
			return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: defaultInterface}, PeerName: "warp0-peer"}
		},
		"wireguard": func() netlink.Link {
			return &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: defaultInterface}}
		},
	}
	b := &testbed{clientKey: testKey(t), peerKey: testKey(t)} // Up fails before using the topology
	for name, newLink := range foreignLinks {
		t.Run(name, func(t *testing.T) {
			if name == "wireguard" && !kernelWireGuard(t) {
				skipWithoutKernelWireGuard(t)
			}
			must(t, netlink.LinkAdd(newLink()))
			foreign, err := netlink.LinkByName(defaultInterface)
			must(t, err)
			t.Cleanup(func() { _ = netlink.LinkDel(foreign) })

			_, err = Up(context.Background(), b.config(t, ModeAuto, endpoint))
			if err == nil || !strings.Contains(err.Error(), "not created by warp-proxy") {
				t.Fatalf("Up over a foreign %s named %s: %v", name, defaultInterface, err)
			}
			if link, err := netlink.LinkByName(defaultInterface); err != nil || link.Attrs().Index != foreign.Attrs().Index ||
				link.Attrs().Alias != "" {
				t.Fatalf("foreign interface touched: %v %v", link, err)
			}
			if rules := ownRules(t, netlink.FAMILY_V4); len(rules) != 0 {
				t.Fatalf("rules installed by a failed Up: %v", rules)
			}
		})
	}
}

func TestUpKeepsForeignRulesAndCleansOwnStale(t *testing.T) {
	forModes(t, func(t *testing.T, mode Mode) {
		b := newTestbed(t)
		rule := func(family, priority, table int, mut func(r *netlink.Rule)) netlink.Rule {
			r := netlink.NewRule()
			r.Family, r.Priority, r.Table = family, priority, table
			mut(r)
			return *r
		}
		foreign := []netlink.Rule{
			// a host's wg-quick, as seen with --network host
			rule(netlink.FAMILY_V4, 32764, unix.RT_TABLE_MAIN, func(r *netlink.Rule) { r.SuppressPrefixlen = 0 }),
			rule(netlink.FAMILY_V4, 32765, 51820, func(r *netlink.Rule) { r.Mark, r.Invert = 0xca6c, true }),
			rule(netlink.FAMILY_V6, 32765, 51820, func(r *netlink.Rule) { r.Mark, r.Invert = 0xca6c, true }),
			// an untagged rule into our table
			rule(netlink.FAMILY_V4, 100, DefaultTable, func(r *netlink.Rule) { r.Mark = DefaultMark }),
		}
		stale := []netlink.Rule{
			rule(netlink.FAMILY_V4, 200, DefaultTable, func(r *netlink.Rule) {
				r.Protocol, r.Src = ownerProtocol, ipNet(netip.MustParsePrefix("10.9.9.9/32"))
			}),
			rule(netlink.FAMILY_V6, 201, DefaultTable, func(r *netlink.Rule) { r.Protocol, r.Mark = ownerProtocol, DefaultMark }),
		}
		for _, r := range slices.Concat(foreign, stale) {
			must(t, netlink.RuleAdd(&r))
		}
		t.Cleanup(func() {
			for _, r := range foreign {
				_ = netlink.RuleDel(&r)
			}
		})
		must(t, netlink.LinkAdd(&netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: defaultInterface}, Mode: netlink.TUNTAP_MODE_TUN}))
		staleLink, err := netlink.LinkByName(defaultInterface)
		must(t, err)
		must(t, netlink.LinkSetAlias(staleLink, linkAlias))
		t.Cleanup(func() { _ = netlink.LinkDel(staleLink) })

		tn := up(t, b.config(t, mode, endpoint))
		if link, err := netlink.LinkByName(defaultInterface); err != nil || link.Attrs().Index == staleLink.Attrs().Index {
			t.Fatalf("stale interface not replaced: %v %v", link, err)
		}
		assertRouting(t, true) // exactly our current rules: the stale tagged ones are gone
		assertForeignRules(t, foreign)
		expectSource(t, publicV4, marked, clientInner4)
		must(t, tn.Close())
		assertRemoved(t)
		assertForeignRules(t, foreign)
	})
}

func assertForeignRules(t *testing.T, want []netlink.Rule) {
	t.Helper()
	for _, w := range want {
		rules, err := netlink.RuleListFiltered(w.Family, &w, netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_MARK)
		must(t, err)
		if len(rules) != 1 {
			t.Fatalf("foreign rule %v: found %v", w, rules)
		}
	}
}

func TestSecondTunnelRefused(t *testing.T) {
	b := newTestbed(t)
	first := up(t, b.config(t, ModeUserspace, endpoint))
	second := b.config(t, ModeUserspace, endpoint)
	second.Interface = "warp1"
	if _, err := Up(context.Background(), second); err == nil || !strings.Contains(err.Error(), "another warp-proxy tunnel") {
		t.Fatalf("second Up in the same netns: %v", err)
	}
	assertRouting(t, true) // the first tunnel is untouched
	expectSource(t, publicV4, marked, clientInner4)
	must(t, first.Close())
	up(t, second) // the lock is released by Close
	expectSource(t, publicV4, marked, clientInner4)
}

func TestConcurrentUse(t *testing.T) {
	b := newTestbed(t)
	cfg := b.config(t, ModeUserspace, endpoint, deadEndpoint)
	cfg.Logger = slog.New(slog.DiscardHandler) // one line per rotation otherwise
	tn := up(t, cfg)
	expectSource(t, publicV4, marked, clientInner4)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for {
				if _, err := tn.Status(); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for {
				if _, err := tn.RotateEndpoint(); err != nil {
					return
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	must(t, tn.Close())
	wg.Wait()
	assertRemoved(t)
}

func setSysctl(t *testing.T, path, value string) {
	t.Helper()
	old, err := os.ReadFile(path)
	must(t, err)
	must(t, os.WriteFile(path, []byte(value), 0o644))
	t.Cleanup(func() { _ = os.WriteFile(path, old, 0o644) })
}

// addAddrs adds addresses without duplicate address detection, so IPv6
// addresses are usable at once.
func addAddrs(link netlink.Link, prefixes ...string) error {
	for _, p := range prefixes {
		addr, err := netlink.ParseAddr(p)
		if err == nil {
			addr.Flags = unix.IFA_F_NODAD
			err = netlink.AddrAdd(link, addr)
		}
		if err != nil {
			return fmt.Errorf("add %s to %s: %w", p, link.Attrs().Name, err)
		}
	}
	return nil
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

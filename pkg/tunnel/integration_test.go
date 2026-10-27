//go:build linux && integration

package tunnel

// These tests need root and a throwaway network namespace:
//
//	GOTOOLCHAIN=go1.27.1 go test -c -race -tags integration -o /tmp/tunnel/tunnel.test ./pkg/tunnel
//	sudo unshare --net /tmp/tunnel/tunnel.test -test.v -test.count=1
//
// Each test fails when it finds itself in the init network namespace. Kernel
// mode subtests skip when the kernel has no WireGuard, unless
// TUNNEL_REQUIRE_KERNEL_WIREGUARD=1 turns that into a failure (CI).
//
// Topology, built per test inside that namespace ("client"):
//
//	client netns                              peer netns
//	wgt-c 10.200.0.1/24 ── veth ─────────── wgt-p 10.200.0.2/24
//	default via 10.200.0.2                    lo: 203.0.113.1, 203.0.113.2 (WireGuard endpoints)
//	wg0 172.16.0.2/32, fd00::2/128  ═ WG ═    wgpeer 172.16.0.1/24, fd00::1/64 (wireguard-go)
//	                                          lo: 198.51.100.10, 2001:db8::10; echo on :7777 for all
//
// The echo server answers with the source address it saw, which tells whether
// a connection went through the tunnel (172.16.0.2 / fd00::2) or not (10.200.0.1).

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
	"strings"
	"sync"
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
	endpointA    = "203.0.113.1:51820"
	endpointB    = "203.0.113.2:51820"
	deadEndpoint = "10.200.0.99:51820" // on the veth subnet, nobody there
	publicV4     = "198.51.100.10"
	publicV6     = "2001:db8::10"
	peerDirect   = "10.200.0.2"
	clientOuter  = "10.200.0.1"
	clientInner4 = "172.16.0.2"
	clientInner6 = "fd00::2"
	echoPort     = "7777"
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
}

func newTestbed(t *testing.T) *testbed {
	requireIsolatedNetns(t)
	b := &testbed{clientKey: testKey(t), peerKey: testKey(t)}
	peerNs := newNetns(t)
	t.Cleanup(func() { peerNs.Close() })

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "wgt-c"}, PeerName: "wgt-p",
		PeerNamespace: netlink.NsFd(peerNs)}
	must(t, netlink.LinkAdd(veth))
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	lo, err := netlink.LinkByName("lo")
	must(t, err)
	must(t, netlink.LinkSetUp(lo))
	must(t, addAddrs(veth, "10.200.0.1/24"))
	must(t, netlink.LinkSetUp(veth))
	must(t, netlink.RouteAdd(&netlink.Route{LinkIndex: veth.Attrs().Index, Gw: net.ParseIP(peerDirect)}))

	var peerDev *device.Device
	var echo net.Listener
	err = inNetns(peerNs, func() (err error) {
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
	if err := addAddrs(lo, "203.0.113.1/32", "203.0.113.2/32", publicV4+"/32", publicV6+"/128"); err != nil {
		return nil, nil, err
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return nil, nil, err
	}
	veth, err := netlink.LinkByName("wgt-p")
	if err != nil {
		return nil, nil, err
	}
	if err := addAddrs(veth, "10.200.0.2/24"); err != nil {
		return nil, nil, err
	}
	if err := netlink.LinkSetUp(veth); err != nil {
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

// sourceSeenBy connects to the echo server on dst and returns the source
// address the server saw.
func sourceSeenBy(dst string, timeout time.Duration) (string, error) {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(dst, echoPort), timeout)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	b, err := io.ReadAll(c)
	return string(b), err
}

func expectSource(t *testing.T, dst, want string) {
	t.Helper()
	got, err := sourceSeenBy(dst, 15*time.Second)
	if err != nil || got != want {
		t.Fatalf("connection to %s: peer saw %q (err %v), want %s", dst, got, err, want)
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

// ownRules returns the rules this package would treat as its own.
func ownRules(t *testing.T, family int) []netlink.Rule {
	t.Helper()
	rules, err := netlink.RuleList(family)
	must(t, err)
	var out []netlink.Rule
	for _, r := range rules {
		if staleRule(r, defaultTable, defaultFwMark) {
			out = append(out, r)
		}
	}
	return out
}

func tableRoutes(t *testing.T, family int) []netlink.Route {
	t.Helper()
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: defaultTable}, netlink.RT_FILTER_TABLE)
	must(t, err)
	return routes
}

func assertRouting(t *testing.T, v6 bool) {
	t.Helper()
	link, err := netlink.LinkByName(defaultInterface)
	must(t, err)
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, routes := ownRules(t, family), tableRoutes(t, family)
		if family == netlink.FAMILY_V6 && !v6 {
			if len(rules) != 0 || len(routes) != 0 {
				t.Fatalf("IPv6 routing installed while disabled: rules %v routes %v", rules, routes)
			}
			continue
		}
		if len(rules) != 2 || rules[0].Priority != prioritySuppress || rules[1].Priority != priorityTunnel ||
			rules[1].Mark != defaultFwMark || !rules[1].Invert || rules[0].SuppressPrefixlen != 0 {
			t.Fatalf("family %d rules: %v", family, rules)
		}
		if len(routes) != 1 || routes[0].LinkIndex != link.Attrs().Index {
			t.Fatalf("family %d table routes: %v", family, routes)
		}
	}
}

func assertRemoved(t *testing.T) {
	t.Helper()
	if _, err := netlink.LinkByName(defaultInterface); !notExist(err) {
		t.Fatalf("interface still present after Close (err %v)", err)
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if rules, routes := ownRules(t, family), tableRoutes(t, family); len(rules) != 0 || len(routes) != 0 {
			t.Fatalf("left behind: rules %v routes %v", rules, routes)
		}
	}
}

func TestEndToEnd(t *testing.T) {
	requireIsolatedNetns(t)
	kernel := kernelWireGuard(t)
	auto := ModeUserspace
	if kernel {
		auto = ModeKernel
	}
	cases := []struct {
		mode Mode
		want Mode
	}{
		{ModeUserspace, ModeUserspace},
		{ModeKernel, ModeKernel},
		{ModeAuto, auto},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			if tc.mode == ModeKernel && !kernel {
				skipWithoutKernelWireGuard(t)
			}
			b := newTestbed(t)
			tn := up(t, b.config(t, tc.mode, endpointA, endpointB))
			st, err := tn.Status()
			must(t, err)
			if st.Mode != tc.want || st.Interface != "wg0" || st.Endpoint != endpointA || !st.IPv6 {
				t.Fatalf("status after Up: %+v", st)
			}
			assertRouting(t, true)

			expectSource(t, publicV4, clientInner4)
			expectSource(t, publicV6, clientInner6)
			expectSource(t, peerDirect, clientOuter) // connected subnet bypasses the tunnel

			st, err = tn.Status()
			must(t, err)
			if st.LastHandshake.IsZero() || time.Since(st.LastHandshake) > time.Minute || st.RxBytes == 0 || st.TxBytes == 0 {
				t.Fatalf("no handshake or traffic recorded: %+v", st)
			}
			expectSource(t, publicV4, clientInner4)
			later, err := tn.Status()
			must(t, err)
			if later.RxBytes <= st.RxBytes || later.TxBytes <= st.TxBytes {
				t.Fatalf("counters did not grow: %+v then %+v", st, later)
			}

			ep, err := tn.RotateEndpoint()
			if err != nil || ep != endpointB {
				t.Fatalf("rotate: %q %v", ep, err)
			}
			expectSource(t, publicV4, clientInner4)
			if st, err = tn.Status(); err != nil || st.Endpoint != endpointB {
				t.Fatalf("status after rotation: %+v %v", st, err)
			}
			if ep, err = tn.RotateEndpoint(); err != nil || ep != endpointA {
				t.Fatalf("rotation did not wrap: %q %v", ep, err)
			}
			expectSource(t, publicV4, clientInner4)

			must(t, tn.Close())
			assertRemoved(t)
			must(t, tn.Close())
			if _, err := tn.Status(); err == nil {
				t.Fatal("Status after Close succeeded")
			}
			if _, err := tn.RotateEndpoint(); err == nil {
				t.Fatal("RotateEndpoint after Close succeeded")
			}
			expectSource(t, publicV4, clientOuter) // main table default route again
		})
	}
}

// The handshake after rotating has no cached source address, so it only
// reaches the peer if WireGuard's UDP carries the fwmark.
func TestRotateAwayFromDeadEndpoint(t *testing.T) {
	forModes(t, func(t *testing.T, mode Mode) {
		b := newTestbed(t)
		tn := up(t, b.config(t, mode, deadEndpoint, endpointA))
		if _, err := sourceSeenBy(publicV4, 2*time.Second); err == nil {
			t.Fatal("traffic flowed through a dead endpoint")
		}
		ep, err := tn.RotateEndpoint()
		if err != nil || ep != endpointA {
			t.Fatalf("rotate: %q %v", ep, err)
		}
		expectSource(t, publicV4, clientInner4)
	})
}

func TestUpReplacesStaleState(t *testing.T) {
	forModes(t, func(t *testing.T, mode Mode) {
		b := newTestbed(t)
		stale := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: defaultInterface}, Mode: netlink.TUNTAP_MODE_TUN}
		must(t, netlink.LinkAdd(stale))
		staleLink, err := netlink.LinkByName(defaultInterface)
		must(t, err)
		t.Cleanup(func() { _ = netlink.LinkDel(staleLink) })
		staleIndex := staleLink.Attrs().Index
		for i, r := range []netlink.Rule{routingRules(netlink.FAMILY_V4, defaultTable, defaultFwMark)[1],
			routingRules(netlink.FAMILY_V4, defaultTable, defaultFwMark)[0],
			routingRules(netlink.FAMILY_V6, defaultTable, defaultFwMark)[1]} {
			if r.Table == defaultTable {
				r.Priority = 100 + i // a previous build may have used other priorities
			}
			must(t, netlink.RuleAdd(&r))
		}

		tn := up(t, b.config(t, mode, endpointA))
		if link, err := netlink.LinkByName(defaultInterface); err != nil || link.Attrs().Index == staleIndex {
			t.Fatalf("stale link not replaced: %v %v", link, err)
		}
		assertRouting(t, true)
		expectSource(t, publicV4, clientInner4)
		must(t, tn.Close())
		assertRemoved(t)
	})
}

func TestUpKeepsForeignInterface(t *testing.T) {
	requireIsolatedNetns(t)
	b := newTestbed(t)
	foreign := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: defaultInterface}, PeerName: "wg0-peer"}
	must(t, netlink.LinkAdd(foreign))
	t.Cleanup(func() { _ = netlink.LinkDel(foreign) })

	_, err := Up(context.Background(), b.config(t, ModeUserspace, endpointA))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Up over a veth named %s: %v", defaultInterface, err)
	}
	if link, err := netlink.LinkByName(defaultInterface); err != nil || link.Type() != "veth" {
		t.Fatalf("foreign interface touched: %v %v", link, err)
	}
	if rules := ownRules(t, netlink.FAMILY_V4); len(rules) != 0 {
		t.Fatalf("rules installed by a failed Up: %v", rules)
	}
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
				tn := up(t, b.config(t, mode, endpointA))
				st, err := tn.Status()
				if err != nil || st.IPv6 {
					t.Fatalf("status: %+v %v", st, err)
				}
				assertRouting(t, false)
				expectSource(t, publicV4, clientInner4)
				must(t, tn.Close())
				assertRemoved(t)
			})
		})
	}
}

func TestConcurrentUse(t *testing.T) {
	b := newTestbed(t)
	cfg := b.config(t, ModeUserspace, endpointA, endpointB)
	cfg.Logger = slog.New(slog.DiscardHandler) // one line per rotation otherwise
	tn := up(t, cfg)
	expectSource(t, publicV4, clientInner4)

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

func addAddrs(link netlink.Link, prefixes ...string) error {
	for _, p := range prefixes {
		addr, err := netlink.ParseAddr(p)
		if err == nil {
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

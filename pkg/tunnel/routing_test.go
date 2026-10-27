//go:build linux

package tunnel

import (
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestRoutingRules(t *testing.T) {
	addrs := []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32"), netip.MustParsePrefix("2606:4700:110::2/64")}
	cases := []struct {
		family int
		addrs  []netip.Prefix
		from   []string
	}{
		{netlink.FAMILY_V4, addrs, []string{"172.16.0.2/32"}},
		{netlink.FAMILY_V6, addrs, []string{"2606:4700:110::2/128"}}, // the host address, not its prefix
		{netlink.FAMILY_V6, nil, nil},                                // tunnel without IPv6: mark rule only
	}
	for _, tc := range cases {
		rules := routingRules(tc.family, 22337, 0x57415250, tc.addrs)
		if len(rules) != 1+len(tc.from) {
			t.Fatalf("family %d: got %d rules", tc.family, len(rules))
		}
		marked := rules[0]
		if marked.Priority != priorityMark || marked.Mark != 0x57415250 || marked.Mask != nil || marked.Src != nil || marked.Invert {
			t.Fatalf("mark rule: %+v", marked)
		}
		for i, want := range tc.from {
			from := rules[1+i]
			if from.Priority != priorityFrom || from.Mark != 0 || from.Src.String() != want {
				t.Fatalf("from rule: %+v, want from %s", from, want)
			}
		}
		for _, r := range rules {
			if r.Family != tc.family || r.Table != 22337 || r.Protocol != ownerProtocol {
				t.Fatalf("rule not ours or wrong family: %+v", r)
			}
			// netlink.Rule zero values mean "goto 0" and "flow 0"; the rules must come from NewRule.
			if r.Goto != -1 || r.Flow != -1 || r.SuppressIfgroup != -1 || r.SuppressPrefixlen != -1 {
				t.Fatalf("rule carries unintended attributes: %+v", r)
			}
		}
	}
	if !(priorityMark < priorityFrom && priorityFrom < 32766) {
		t.Fatal("rules must be evaluated before the main table")
	}
}

func TestTableRoutes(t *testing.T) {
	for _, tc := range []struct {
		family  int
		wantDst string
	}{{netlink.FAMILY_V4, "0.0.0.0/0"}, {netlink.FAMILY_V6, "::/0"}} {
		family, wantDst := tc.family, tc.wantDst
		routes := tableRoutes(family, 22337, 7, true)
		if len(routes) != 2 {
			t.Fatalf("got %d routes", len(routes))
		}
		tunnel, unreachable := routes[0], routes[1]
		if tunnel.Dst.String() != wantDst || tunnel.LinkIndex != 7 || tunnel.Table != 22337 || tunnel.Family != family ||
			tunnel.Type != 0 || tunnel.Gw != nil || tunnel.Protocol != ownerProtocol {
			t.Fatalf("tunnel route: %+v", tunnel)
		}
		if unreachable.Dst.String() != wantDst || unreachable.Type != unix.RTN_UNREACHABLE || unreachable.LinkIndex != 0 ||
			unreachable.Table != 22337 || unreachable.Priority != math.MaxInt32 || unreachable.Protocol != ownerProtocol {
			t.Fatalf("unreachable route: %+v", unreachable)
		}
		if only := tableRoutes(family, 22337, 7, false); len(only) != 1 || only[0].Type != unix.RTN_UNREACHABLE {
			t.Fatalf("without the tunnel only the unreachable route remains: %+v", only)
		}
	}
}

func TestOwnRule(t *testing.T) {
	rules := routingRules(netlink.FAMILY_V4, 22337, 0x57415250, []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32")})
	for _, r := range rules {
		if !ownRule(r, 22337) {
			t.Fatalf("own rule not recognised: %+v", r)
		}
	}
	untagged, otherTable := rules[0], rules[0]
	untagged.Protocol = 0
	otherTable.Table = 51820
	if ownRule(untagged, 22337) || ownRule(otherTable, 22337) {
		t.Fatal("a rule must carry our tag and our table to be ours")
	}
}

func TestAddressConflict(t *testing.T) {
	want := []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32"), netip.MustParsePrefix("2606:4700:110::2/128")}
	addr := func(s string, link int) netlink.Addr {
		a, err := netlink.ParseAddr(s)
		if err != nil {
			t.Fatal(err)
		}
		a.LinkIndex = link
		return *a
	}
	free := []netlink.Addr{addr("127.0.0.1/8", 1), addr("10.0.0.2/24", 2), addr("172.16.0.3/32", 3), addr("::1/128", 1)}
	if a, ok := addressConflict(free, want); ok {
		t.Fatalf("unexpected conflict with %v", a)
	}
	// A host's own WARP tunnel holds the same address, whatever its prefix length.
	for _, taken := range []netlink.Addr{addr("172.16.0.2/32", 9), addr("172.16.0.2/12", 9), addr("2606:4700:110::2/64", 9)} {
		a, ok := addressConflict(append(free, taken), want)
		if !ok || a.LinkIndex != 9 {
			t.Fatalf("conflict with %v not found", taken)
		}
	}
}

func TestIPv6Confinement(t *testing.T) {
	cases := []struct {
		stack, policyRouting, disabled bool
		confine, fails                 bool
	}{
		{stack: false, confine: false},                                    // no IPv6 at all: nothing can leak
		{stack: true, policyRouting: true, confine: true},                 // the normal case
		{stack: true, policyRouting: true, disabled: true, confine: true}, // still confined, cheaply
		{stack: true, policyRouting: false, disabled: true, confine: false},
		{stack: true, policyRouting: false, disabled: false, fails: true}, // would leak: refuse
	}
	for _, tc := range cases {
		confine, err := ipv6Confinement(tc.stack, tc.policyRouting, tc.disabled)
		if confine != tc.confine || (err != nil) != tc.fails {
			t.Fatalf("%+v: got %v %v", tc, confine, err)
		}
		if err != nil && !strings.Contains(err.Error(), "net.ipv6.conf.all.disable_ipv6=1") {
			t.Fatalf("error does not tell the operator what to do: %v", err)
		}
	}
}

func TestOwnLink(t *testing.T) {
	ours, other := testKey(t), testKey(t)
	link := func(kind, alias string) netlink.Link {
		attrs := netlink.LinkAttrs{Name: "warp0", Alias: alias}
		if kind == "wireguard" {
			return &netlink.Wireguard{LinkAttrs: attrs}
		}
		return &netlink.Tuntap{LinkAttrs: attrs}
	}
	key := func(k wgtypes.Key) func(string) (wgtypes.Key, error) {
		return func(string) (wgtypes.Key, error) { return k, nil }
	}
	noDevice := func(string) (wgtypes.Key, error) { return wgtypes.Key{}, errors.New("no such device") }
	cases := []struct {
		name      string
		link      netlink.Link
		deviceKey func(string) (wgtypes.Key, error)
		own       bool
	}{
		{"tagged tun", link("tuntap", linkAlias), noDevice, true},
		{"tagged wireguard", link("wireguard", linkAlias), key(other), true},
		{"untagged wireguard with our key", link("wireguard", ""), key(ours), true},
		{"untagged wireguard with another key", link("wireguard", ""), key(other), false},
		{"untagged wireguard without a key", link("wireguard", ""), key(wgtypes.Key{}), false},
		{"untagged wireguard, unreadable", link("wireguard", ""), noDevice, false},
		{"untagged tun", link("tuntap", ""), key(ours), false},
		{"other alias", link("wireguard", "wg-quick"), key(other), false},
	}
	for _, tc := range cases {
		if got := ownLink(tc.link, ours, tc.deviceKey); got != tc.own {
			t.Fatalf("%s: got %v", tc.name, got)
		}
	}
}

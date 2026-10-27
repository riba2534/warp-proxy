//go:build linux

package tunnel

import (
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestRoutingRules(t *testing.T) {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules := routingRules(family, 51820, 0xca6c)
		if len(rules) != 2 {
			t.Fatalf("got %d rules", len(rules))
		}
		suppress, tunnel := rules[0], rules[1]
		if suppress.Family != family || suppress.Table != unix.RT_TABLE_MAIN || suppress.SuppressPrefixlen != 0 ||
			suppress.Invert || suppress.Mark != 0 {
			t.Fatalf("suppress rule: %+v", suppress)
		}
		if tunnel.Family != family || tunnel.Table != 51820 || tunnel.Mark != 0xca6c || !tunnel.Invert ||
			tunnel.SuppressPrefixlen != -1 {
			t.Fatalf("tunnel rule: %+v", tunnel)
		}
		// Connected subnets must be looked up before traffic is sent into the
		// tunnel, and both before the main table rule at 32766.
		if !(suppress.Priority < tunnel.Priority && tunnel.Priority < 32766 && suppress.Priority > 0) {
			t.Fatalf("priorities %d, %d", suppress.Priority, tunnel.Priority)
		}
		// netlink.Rule zero values mean "goto 0" and "flow 0"; the rules must come from NewRule.
		for _, r := range rules {
			if r.Goto != -1 || r.Flow != -1 || r.SuppressIfgroup != -1 || r.Mask != nil {
				t.Fatalf("rule carries unintended attributes: %+v", r)
			}
		}
	}
}

func TestDefaultRoute(t *testing.T) {
	v4 := defaultRoute(netlink.FAMILY_V4, 7, 51820)
	if v4.Dst.String() != "0.0.0.0/0" || v4.LinkIndex != 7 || v4.Table != 51820 || v4.Family != netlink.FAMILY_V4 ||
		v4.Scope != netlink.SCOPE_LINK || v4.Gw != nil {
		t.Fatalf("v4 route: %+v", v4)
	}
	v6 := defaultRoute(netlink.FAMILY_V6, 7, 51820)
	if v6.Dst.String() != "::/0" || v6.LinkIndex != 7 || v6.Table != 51820 || v6.Family != netlink.FAMILY_V6 {
		t.Fatalf("v6 route: %+v", v6)
	}
}

func TestStaleRule(t *testing.T) {
	ours := routingRules(netlink.FAMILY_V4, 51820, 0xca6c)
	for _, r := range ours {
		if !staleRule(r, 51820, 0xca6c) {
			t.Fatalf("own rule not recognised: %+v", r)
		}
	}
	movedTunnel := ours[1]
	movedTunnel.Priority = 100
	if !staleRule(movedTunnel, 51820, 0xca6c) {
		t.Fatal("tunnel rule at another priority not recognised")
	}
	foreignMark := netlink.NewRule()
	foreignMark.Mark, foreignMark.Invert, foreignMark.Table, foreignMark.Priority = 0xca6c, true, 200, 50
	if !staleRule(*foreignMark, 51820, 0xca6c) {
		t.Fatal("rule matching not-fwmark not recognised")
	}

	keep := []netlink.Rule{}
	for _, mut := range []func(r *netlink.Rule){
		func(r *netlink.Rule) { r.Priority, r.Table = 0, unix.RT_TABLE_LOCAL },
		func(r *netlink.Rule) { r.Priority, r.Table = 32766, unix.RT_TABLE_MAIN },
		func(r *netlink.Rule) { r.Priority, r.Table = 32767, unix.RT_TABLE_DEFAULT },
		// someone else's suppress rule at another priority
		func(r *netlink.Rule) { r.Priority, r.Table, r.SuppressPrefixlen = 1000, unix.RT_TABLE_MAIN, 0 },
		// matching mark that is not inverted
		func(r *netlink.Rule) { r.Priority, r.Table, r.Mark = 1001, 300, 0xca6c },
	} {
		r := netlink.NewRule()
		mut(r)
		keep = append(keep, *r)
	}
	for _, r := range keep {
		if staleRule(r, 51820, 0xca6c) {
			t.Fatalf("unrelated rule treated as stale: %+v", r)
		}
	}
}

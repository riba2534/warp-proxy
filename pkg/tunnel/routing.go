//go:build linux

package tunnel

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Only sockets carrying the mark, and packets sourced from a tunnel address,
// use the tunnel table; everything else in the netns keeps the main table.
// Both rules sit before the main table rule (32766).
const (
	priorityMark = 32760 // fwmark Mark lookup Table
	priorityFrom = 32761 // from <tunnel address> lookup Table

	// ownerProtocol tags the rules and routes we add (unassigned in rt_protos).
	ownerProtocol = 87
	// linkAlias marks the links we create; nothing else is ever deleted.
	linkAlias = "warp-proxy"
)

// routingRules returns the policy rules for one address family. The "from"
// rules route kernel-generated packets of tunnel flows and let strict
// reverse-path filtering accept decrypted packets arriving on the tunnel.
func routingRules(family, table int, mark uint32, addrs []netip.Prefix) []netlink.Rule {
	rule := func(priority int) netlink.Rule {
		r := netlink.NewRule()
		r.Family, r.Table, r.Priority, r.Protocol = family, table, priority, ownerProtocol
		return *r
	}
	marked := rule(priorityMark)
	marked.Mark = mark
	rules := []netlink.Rule{marked}
	for _, p := range addrs {
		if p.Addr().Is4() != (family == netlink.FAMILY_V4) {
			continue
		}
		from := rule(priorityFrom)
		from.Src = ipNet(netip.PrefixFrom(p.Addr(), p.Addr().BitLen()))
		rules = append(rules, from)
	}
	return rules
}

// tableRoutes returns the routes of the tunnel table for one family: the
// tunnel when it carries the family, and always an unreachable default with
// the highest metric so marked traffic can never fall through to the main table.
func tableRoutes(family, table, linkIndex int, viaTunnel bool) []netlink.Route {
	dst := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	if family == netlink.FAMILY_V6 {
		dst = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	base := netlink.Route{Family: family, Dst: ipNet(dst), Table: table, Protocol: ownerProtocol}
	unreachable := base
	unreachable.Type, unreachable.Priority = unix.RTN_UNREACHABLE, math.MaxInt32
	if !viaTunnel {
		return []netlink.Route{unreachable}
	}
	tunnel := base
	tunnel.LinkIndex, tunnel.Scope = linkIndex, netlink.SCOPE_LINK
	return []netlink.Route{tunnel, unreachable}
}

// ownRule reports whether r was added by this package for table.
func ownRule(r netlink.Rule, table int) bool {
	return r.Protocol == ownerProtocol && r.Table == table
}

func removeStaleRules(table int, log *slog.Logger) error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			if family == netlink.FAMILY_V6 && errors.Is(err, unix.EAFNOSUPPORT) {
				continue
			}
			return fmt.Errorf("list routing rules: %w", err)
		}
		for _, r := range rules {
			if !ownRule(r, table) {
				continue
			}
			if err := netlink.RuleDel(&r); err != nil && !notExist(err) {
				return fmt.Errorf("delete stale rule %v: %w", r, err)
			}
			log.Info("removed stale routing rule", "rule", r.String())
		}
	}
	return nil
}

// lockNetns allows one tunnel per network namespace. Abstract unix sockets
// belong to the netns and are released when their process dies, so objects
// tagged as ours that exist while we hold the lock are stale.
func lockNetns() (io.Closer, error) {
	c, err := net.ListenPacket("unixgram", "@warp-proxy-tunnel")
	if errors.Is(err, unix.EADDRINUSE) {
		return nil, errors.New("another warp-proxy tunnel is running in this network namespace")
	}
	return c, err
}

// removeStaleLink deletes a link with our name only if we created it.
func removeStaleLink(name string, private wgtypes.Key, log *slog.Logger) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if notExist(err) {
			return nil
		}
		return fmt.Errorf("look up interface %s: %w", name, err)
	}
	if !ownLink(link, private, wireguardPrivateKey) {
		return fmt.Errorf("interface %s already exists and was not created by warp-proxy (%s link, alias %q)",
			name, link.Type(), link.Attrs().Alias)
	}
	if err := netlink.LinkDel(link); err != nil && !notExist(err) {
		return fmt.Errorf("delete stale interface %s: %w", name, err)
	}
	log.Info("removed stale interface", "type", link.Type())
	return nil
}

// ownLink reports whether link is ours: tagged with our alias, or a kernel
// WireGuard device holding our private key (older builds tagged it only
// after configuring it, so a crash in between left it untagged).
func ownLink(link netlink.Link, private wgtypes.Key, deviceKey func(name string) (wgtypes.Key, error)) bool {
	if link.Attrs().Alias == linkAlias {
		return true
	}
	if link.Type() != "wireguard" {
		return false
	}
	key, err := deviceKey(link.Attrs().Name)
	return err == nil && key == private
}

func wireguardPrivateKey(name string) (wgtypes.Key, error) {
	c, err := wgctrl.New()
	if err != nil {
		return wgtypes.Key{}, err
	}
	defer c.Close()
	d, err := c.Device(name)
	if err != nil {
		return wgtypes.Key{}, err
	}
	return d.PrivateKey, nil
}

// tagLink marks a link we just created as ours. The kernel ignores
// IFLA_IFALIAS when creating a link, so this must follow creation at once.
func tagLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err == nil {
		err = netlink.LinkSetAlias(link, linkAlias)
	}
	if err != nil {
		return fmt.Errorf("tag interface %s: %w", name, err)
	}
	return nil
}

// checkAddressesFree refuses tunnel addresses that are already assigned in
// this netns: every WARP device gets 172.16.0.2, and our "from" rule would
// capture the traffic of a host's own WARP tunnel using it.
func checkAddressesFree(want []netip.Prefix) error {
	assigned, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	a, ok := addressConflict(assigned, want)
	if !ok {
		return nil
	}
	name := strconv.Itoa(a.LinkIndex)
	if link, err := netlink.LinkByIndex(a.LinkIndex); err == nil {
		name = link.Attrs().Name
	}
	return fmt.Errorf("tunnel address %s is already assigned to %s in this network namespace, "+
		"probably another WireGuard tunnel; refusing to capture its traffic", a.IP, name)
}

func addressConflict(assigned []netlink.Addr, want []netip.Prefix) (netlink.Addr, bool) {
	for _, a := range assigned {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		for _, p := range want {
			if ip.Unmap() == p.Addr() {
				return a, true
			}
		}
	}
	return netlink.Addr{}, false
}

// ipv6Confinement decides whether marked IPv6 gets our rules and unreachable
// route. Without IPv6 policy routing (CONFIG_IPV6_MULTIPLE_TABLES=n) a route
// for our table would land in the main table, and marked IPv6 would leak;
// that is only acceptable when IPv6 is disabled in the netns.
func ipv6Confinement(stack, policyRouting, disabled bool) (bool, error) {
	switch {
	case !stack:
		return false, nil
	case policyRouting:
		return true, nil
	case disabled:
		return false, nil
	}
	return false, errors.New("the kernel has no IPv6 policy routing (CONFIG_IPV6_MULTIPLE_TABLES), so marked " +
		"IPv6 cannot be kept in the tunnel; disable IPv6 in the container with net.ipv6.conf.all.disable_ipv6=1")
}

// ipv6PolicyRouting reports whether the kernel supports IPv6 rules; tests
// replace it to simulate a kernel without them.
var ipv6PolicyRouting = func() bool {
	_, err := netlink.RuleList(netlink.FAMILY_V6)
	return !errors.Is(err, unix.EAFNOSUPPORT)
}

func ipv6Sysctl(iface string) string {
	b, _ := os.ReadFile("/proc/sys/net/ipv6/conf/" + iface + "/disable_ipv6")
	return strings.TrimSpace(string(b))
}

func ipv6Enabled() bool { return ipv6Sysctl("all") == "0" }

// ipv6Disabled reports whether no interface, present or future, has IPv6.
func ipv6Disabled() bool { return ipv6Sysctl("all") == "1" && ipv6Sysctl("default") == "1" }

// ipv6Stack reports whether this netns can open IPv6 sockets at all, i.e.
// whether marked IPv6 traffic exists that must be kept out of the main table.
func ipv6Stack() bool {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return !errors.Is(err, unix.EAFNOSUPPORT)
	}
	unix.Close(fd)
	return true
}

func notExist(err error) bool {
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) ||
		errors.Is(err, unix.ENODEV)
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

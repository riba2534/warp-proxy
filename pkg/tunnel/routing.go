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
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
func removeStaleLink(name string, log *slog.Logger) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if notExist(err) {
			return nil
		}
		return fmt.Errorf("look up interface %s: %w", name, err)
	}
	if alias := link.Attrs().Alias; alias != linkAlias {
		return fmt.Errorf("interface %s already exists and was not created by warp-proxy (%s link, alias %q)",
			name, link.Type(), alias)
	}
	if err := netlink.LinkDel(link); err != nil && !notExist(err) {
		return fmt.Errorf("delete stale interface %s: %w", name, err)
	}
	log.Info("removed stale interface", "type", link.Type())
	return nil
}

func ipv6Enabled() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	return err == nil && strings.TrimSpace(string(b)) == "0"
}

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

//go:build linux

package tunnel

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Rule priorities sit just before the main table (32766). The suppress rule
// must be evaluated before the tunnel rule so that directly connected subnets
// and other specific main-table routes bypass the tunnel.
const (
	prioritySuppress = 32764 // lookup main suppress_prefixlength 0
	priorityTunnel   = 32765 // not fwmark FwMark lookup Table
)

// routingRules returns the wg-quick style policy rules for one address family,
// in the order they must be installed.
func routingRules(family int, table int, mark uint32) []netlink.Rule {
	suppress := netlink.NewRule()
	suppress.Family = family
	suppress.Priority = prioritySuppress
	suppress.Table = unix.RT_TABLE_MAIN
	suppress.SuppressPrefixlen = 0

	tunnel := netlink.NewRule()
	tunnel.Family = family
	tunnel.Priority = priorityTunnel
	tunnel.Table = table
	tunnel.Mark = mark
	tunnel.Invert = true
	return []netlink.Rule{*suppress, *tunnel}
}

// defaultRoute returns the default route via the tunnel link in table.
func defaultRoute(family, linkIndex, table int) netlink.Route {
	dst := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	if family == netlink.FAMILY_V6 {
		dst = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netlink.Route{
		Family:    family,
		LinkIndex: linkIndex,
		Dst:       ipNet(dst),
		Table:     table,
		Scope:     netlink.SCOPE_LINK,
	}
}

// staleRule reports whether r looks like a rule a previous Up left behind.
func staleRule(r netlink.Rule, table int, mark uint32) bool {
	return r.Table == table ||
		(r.Invert && r.Mark == mark) ||
		(r.Table == unix.RT_TABLE_MAIN && r.SuppressPrefixlen == 0 && r.Priority == prioritySuppress)
}

func removeStaleRules(table int, mark uint32, log *slog.Logger) error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			if family == netlink.FAMILY_V6 && errors.Is(err, unix.EAFNOSUPPORT) {
				continue
			}
			return fmt.Errorf("list routing rules: %w", err)
		}
		for _, r := range rules {
			if !staleRule(r, table, mark) {
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

// removeStaleLink deletes a WireGuard or TUN link with our name. Any other
// link type is left alone: the name is then most likely a configuration error.
func removeStaleLink(name string, log *slog.Logger) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if notExist(err) {
			return nil
		}
		return fmt.Errorf("look up interface %s: %w", name, err)
	}
	if t := link.Type(); t != "wireguard" && t != "tuntap" {
		return fmt.Errorf("interface %s already exists as a %s link", name, t)
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

// enableSrcValidMark lets reverse-path filtering see WireGuard's fwmark, as
// wg-quick does. /proc/sys is often read-only in containers, so it is optional.
func enableSrcValidMark(log *slog.Logger) {
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/src_valid_mark", []byte("1"), 0o644); err != nil {
		log.Debug("cannot set net.ipv4.conf.all.src_valid_mark", "error", err)
	}
}

func notExist(err error) bool {
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) ||
		errors.Is(err, unix.ENODEV)
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

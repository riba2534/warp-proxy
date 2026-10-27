//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/vishvananda/netlink"
)

var errClosed = errors.New("tunnel closed")

type Tunnel struct {
	cfg      Config
	log      *slog.Logger
	resolver resolver

	// Set by Up, read-only afterwards.
	mode      Mode
	ipv6      bool
	linkIndex int
	rules     []netlink.Rule

	rotateMu sync.Mutex // serialises RotateEndpoint
	mu       sync.Mutex // guards the fields below and every call into dev
	dev      wgDevice
	current  int // index into cfg.Endpoints
	endpoint netip.AddrPort
	closed   bool
}

// Up creates the interface, configures the peer, addresses and policy routing,
// and returns without waiting for a handshake.
func Up(ctx context.Context, cfg Config) (_ *Tunnel, err error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	private, peer, _ := cfg.keys()
	t := &Tunnel{
		cfg:      cfg,
		log:      cfg.Logger.With("interface", cfg.Interface),
		resolver: newResolver(cfg.FwMark),
	}
	if err := removeStaleLink(cfg.Interface, t.log); err != nil {
		return nil, err
	}
	if err := removeStaleRules(cfg.Table, cfg.FwMark, t.log); err != nil {
		return nil, err
	}
	if t.current, t.endpoint, err = pickEndpoint(ctx, cfg.Endpoints, 0, t.resolver.resolve); err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			_ = t.Close()
		}
	}()
	t.dev, t.mode, err = createDevice(cfg.Mode, deviceParams{
		name:      cfg.Interface,
		mtu:       cfg.MTU,
		private:   private,
		peer:      peer,
		endpoint:  t.endpoint,
		mark:      cfg.FwMark,
		keepalive: cfg.PersistentKeepalive,
	}, t.log)
	if err != nil {
		return nil, err
	}
	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("look up interface %s: %w", cfg.Interface, err)
	}
	t.linkIndex = link.Attrs().Index
	if err := t.addAddresses(link); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("set %s up: %w", cfg.Interface, err)
	}
	if err := t.addRouting(); err != nil {
		return nil, err
	}
	enableSrcValidMark(t.log)
	if err := t.dev.start(); err != nil {
		return nil, fmt.Errorf("start WireGuard device: %w", err)
	}
	t.log.Info("WireGuard tunnel up", "mode", t.mode, "endpoint", t.endpoint, "ipv6", t.ipv6)
	return t, nil
}

// addAddresses assigns every IPv4 address, and the IPv6 addresses only while
// this netns has IPv6 enabled; IPv6 is skipped with a single warning otherwise.
func (t *Tunnel) addAddresses(link netlink.Link) error {
	var v6 []netip.Prefix
	for _, p := range t.cfg.Addresses {
		if p.Addr().Is6() {
			v6 = append(v6, p)
			continue
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet(p)}); err != nil {
			return fmt.Errorf("add address %v: %w", p, err)
		}
	}
	if len(v6) == 0 {
		return nil
	}
	if !ipv6Enabled() {
		t.log.Warn("IPv6 is disabled in this network namespace, tunnel carries IPv4 only")
		return nil
	}
	for _, p := range v6 {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet(p)}); err != nil {
			t.log.Warn("cannot add IPv6 address, tunnel carries IPv4 only", "address", p, "error", err)
			return nil
		}
	}
	t.ipv6 = true
	return nil
}

// addRouting routes IPv4 through the tunnel and, when it is configured, IPv6.
// IPv6 is optional: if its routing fails the tunnel carries IPv4 only.
func (t *Tunnel) addRouting() error {
	if err := t.routeFamily(netlink.FAMILY_V4); err != nil {
		return err
	}
	if t.ipv6 {
		if err := t.routeFamily(netlink.FAMILY_V6); err != nil {
			t.log.Warn("cannot route IPv6 through the tunnel, tunnel carries IPv4 only", "error", err)
			t.ipv6 = false
		}
	}
	return nil
}

// routeFamily installs the table's default route before the rules that send
// traffic to it, and the suppress rule before the tunnel rule. Routes need no
// bookkeeping: deleting the link removes them.
func (t *Tunnel) routeFamily(family int) error {
	route := defaultRoute(family, t.linkIndex, t.cfg.Table)
	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("add default route to table %d: %w", t.cfg.Table, err)
	}
	for _, rule := range routingRules(family, t.cfg.Table, t.cfg.FwMark) {
		if err := netlink.RuleAdd(&rule); err != nil {
			return fmt.Errorf("add routing rule %v: %w", rule, err)
		}
		t.rules = append(t.rules, rule)
	}
	return nil
}

func (t *Tunnel) Status() (Status, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return Status{}, errClosed
	}
	p, err := t.dev.peer()
	if err != nil {
		return Status{}, fmt.Errorf("read WireGuard peer: %w", err)
	}
	return Status{
		Mode:          t.mode,
		Interface:     t.cfg.Interface,
		Endpoint:      t.endpoint.String(),
		LastHandshake: p.lastHandshake,
		RxBytes:       p.rx,
		TxBytes:       p.tx,
		IPv6:          t.ipv6,
	}, nil
}

// RotateEndpoint moves to the next candidate (wrapping) that resolves and
// updates the peer in place. On failure the current endpoint is kept.
func (t *Tunnel) RotateEndpoint() (string, error) {
	t.rotateMu.Lock()
	defer t.rotateMu.Unlock()
	t.mu.Lock()
	closed, next := t.closed, t.current+1
	t.mu.Unlock()
	if closed {
		return "", errClosed
	}

	idx, ep, err := pickEndpoint(context.Background(), t.cfg.Endpoints, next, t.resolver.resolve)
	if err != nil {
		return "", err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return "", errClosed
	}
	if err := t.dev.setEndpoint(ep); err != nil {
		return "", fmt.Errorf("set endpoint %v: %w", ep, err)
	}
	t.current, t.endpoint = idx, ep
	t.log.Info("WireGuard endpoint rotated", "candidate", t.cfg.Endpoints[idx], "endpoint", ep)
	return ep.String(), nil
}

// Close removes the rules and the link (with its routes) Up created. It is
// idempotent.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	var errs []error
	// Reverse order: the tunnel rule goes before the suppress rule.
	for i := len(t.rules) - 1; i >= 0; i-- {
		if err := netlink.RuleDel(&t.rules[i]); err != nil && !notExist(err) {
			errs = append(errs, fmt.Errorf("delete rule %v: %w", t.rules[i], err))
		}
	}
	if t.dev != nil {
		if err := t.dev.close(); err != nil {
			errs = append(errs, err)
		}
	}
	if t.linkIndex > 0 {
		link, err := netlink.LinkByIndex(t.linkIndex)
		if err == nil && link.Attrs().Name == t.cfg.Interface {
			err = netlink.LinkDel(link)
		}
		if err != nil && !notExist(err) {
			errs = append(errs, fmt.Errorf("delete interface %s: %w", t.cfg.Interface, err))
		}
	}
	t.log.Info("WireGuard tunnel closed")
	return errors.Join(errs...)
}

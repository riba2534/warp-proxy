//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	lock     io.Closer

	// Set by Up, read-only afterwards.
	mode      Mode
	ipv6      bool
	linkIndex int
	routes    []netlink.Route
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
	lock, err := lockNetns()
	if err != nil {
		return nil, err
	}
	t := &Tunnel{
		cfg:      cfg,
		log:      cfg.Logger.With("interface", cfg.Interface),
		resolver: newResolver(),
		lock:     lock,
	}
	defer func() {
		if err != nil {
			_ = t.Close()
		}
	}()
	if err := removeStaleLink(cfg.Interface, t.log); err != nil {
		return nil, err
	}
	if err := removeStaleRules(cfg.Table, t.log); err != nil {
		return nil, err
	}
	if t.current, t.endpoint, err = pickEndpoint(ctx, cfg.Endpoints, 0, t.resolver.resolve); err != nil {
		return nil, err
	}
	t.dev, t.mode, err = createDevice(cfg.Mode, deviceParams{
		name:      cfg.Interface,
		mtu:       cfg.MTU,
		private:   private,
		peer:      peer,
		endpoint:  t.endpoint,
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
	// Kernel links already carry the alias from creation; a TUN cannot, but
	// it disappears with this process anyway.
	if err := netlink.LinkSetAlias(link, linkAlias); err != nil {
		return nil, fmt.Errorf("tag interface %s: %w", cfg.Interface, err)
	}
	if err := t.addAddresses(link); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("set %s up: %w", cfg.Interface, err)
	}
	if err := t.addRouting(); err != nil {
		return nil, err
	}
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

// addRouting sends marked IPv4 through the tunnel, and marked IPv6 through the
// tunnel or, when the tunnel has no IPv6, into the unreachable route. Without
// an IPv6 stack there is no IPv6 traffic to confine.
func (t *Tunnel) addRouting() error {
	if err := t.routeFamily(netlink.FAMILY_V4, true); err != nil {
		return err
	}
	if !ipv6Stack() {
		return nil
	}
	return t.routeFamily(netlink.FAMILY_V6, t.ipv6)
}

// routeFamily fills the tunnel table before adding the rules that use it.
func (t *Tunnel) routeFamily(family int, viaTunnel bool) error {
	for _, route := range tableRoutes(family, t.cfg.Table, t.linkIndex, viaTunnel) {
		if err := netlink.RouteReplace(&route); err != nil {
			return fmt.Errorf("add route %v: %w", route, err)
		}
		t.routes = append(t.routes, route)
	}
	var addrs []netip.Prefix // tunnel addresses of this family, when assigned
	if viaTunnel {
		addrs = t.cfg.Addresses
	}
	for _, rule := range routingRules(family, t.cfg.Table, t.cfg.Mark, addrs) {
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
// replaces the peer with one using it, so a handshake with the new endpoint
// starts at once; the per-peer counters restart. Link and routing stay as
// they are. On failure the current endpoint is kept.
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
	if err := t.dev.replacePeer(ep); err != nil {
		return "", fmt.Errorf("replace peer for endpoint %v: %w", ep, err)
	}
	t.current, t.endpoint = idx, ep
	t.log.Info("WireGuard endpoint rotated", "candidate", t.cfg.Endpoints[idx], "endpoint", ep)
	return ep.String(), nil
}

// Close removes the rules, routes and link Up created. It is idempotent.
// Marked sockets still open afterwards use the main table, so the proxy must
// be stopped first.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	var errs []error
	for i := range t.rules {
		if err := netlink.RuleDel(&t.rules[i]); err != nil && !notExist(err) {
			errs = append(errs, fmt.Errorf("delete rule %v: %w", t.rules[i], err))
		}
	}
	for i := range t.routes {
		if err := netlink.RouteDel(&t.routes[i]); err != nil && !notExist(err) {
			errs = append(errs, fmt.Errorf("delete route %v: %w", t.routes[i], err))
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
	if t.dev != nil {
		t.log.Info("WireGuard tunnel closed")
	}
	if err := t.lock.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

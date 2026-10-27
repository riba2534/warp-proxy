package tunnel

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Mode string

const (
	ModeAuto      Mode = "auto" // kernel, falling back to userspace when the kernel has no WireGuard
	ModeKernel    Mode = "kernel"
	ModeUserspace Mode = "userspace" // wireguard-go over /dev/net/tun; the kernel TCP stack is still used
)

type Config struct {
	Interface           string         // default "warp0"
	Mode                Mode           // default ModeAuto
	PrivateKey          string         // base64
	PeerPublicKey       string         // base64
	Endpoints           []string       // "host:port" candidates; Up uses the first that resolves
	Addresses           []netip.Prefix // v4 and optionally v6
	MTU                 int            // default 1280
	PersistentKeepalive time.Duration  // default 25s
	Mark                uint32         // sockets carrying this mark are routed through the tunnel; default DefaultMark
	Table               int            // default DefaultTable
	Logger              *slog.Logger
}

// Defaults distinct from wg-quick's 0xca6c/51820, so a host's own WireGuard is
// never mistaken for ours.
const (
	DefaultMark  uint32 = 0x57415250 // "WARP"
	DefaultTable        = 22337      // 0x5741
)

const (
	defaultInterface = "warp0"
	defaultMTU       = 1280
	defaultKeepalive = 25 * time.Second
)

func (c Config) withDefaults() Config {
	if c.Interface == "" {
		c.Interface = defaultInterface
	}
	if c.Mode == "" {
		c.Mode = ModeAuto
	}
	if c.MTU == 0 {
		c.MTU = defaultMTU
	}
	if c.PersistentKeepalive == 0 {
		c.PersistentKeepalive = defaultKeepalive
	}
	if c.Mark == 0 {
		c.Mark = DefaultMark
	}
	if c.Table == 0 {
		c.Table = DefaultTable
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// validate expects defaults to be applied already.
func (c Config) validate() error {
	if len(c.Interface) > 15 || c.Interface == "." || c.Interface == ".." || // IFNAMSIZ-1
		strings.ContainsAny(c.Interface, "/: \t\n") {
		return fmt.Errorf("invalid interface name %q", c.Interface)
	}
	switch c.Mode {
	case ModeAuto, ModeKernel, ModeUserspace:
	default:
		return fmt.Errorf("invalid mode %q", c.Mode)
	}
	if _, _, err := c.keys(); err != nil {
		return err
	}
	if len(c.Endpoints) == 0 {
		return errors.New("no endpoint candidates")
	}
	for _, ep := range c.Endpoints {
		if _, _, err := splitEndpoint(ep); err != nil {
			return err
		}
	}
	hasV4 := false
	for _, p := range c.Addresses {
		if !p.IsValid() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return fmt.Errorf("invalid interface address %v", p)
		}
		hasV4 = hasV4 || p.Addr().Is4()
	}
	if !hasV4 {
		return errors.New("an IPv4 interface address is required")
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("MTU %d out of range [576, 65535]", c.MTU)
	}
	if c.PersistentKeepalive < time.Second || c.PersistentKeepalive > 65535*time.Second {
		return fmt.Errorf("persistent keepalive %v out of range [1s, 65535s]", c.PersistentKeepalive)
	}
	switch c.Table {
	case 253, 254, 255: // default, main, local
		return fmt.Errorf("routing table %d is reserved", c.Table)
	}
	if c.Table < 0 {
		return fmt.Errorf("invalid routing table %d", c.Table)
	}
	return nil
}

func (c Config) keys() (private, peer wgtypes.Key, err error) {
	if private, err = wgtypes.ParseKey(c.PrivateKey); err != nil {
		return private, peer, fmt.Errorf("invalid private key: %w", err)
	}
	if peer, err = wgtypes.ParseKey(c.PeerPublicKey); err != nil {
		return private, peer, fmt.Errorf("invalid peer public key: %w", err)
	}
	return private, peer, nil
}

func splitEndpoint(ep string) (host string, port uint16, err error) {
	host, p, err := net.SplitHostPort(ep)
	if err != nil {
		return "", 0, fmt.Errorf("invalid endpoint %q: %w", ep, err)
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if host == "" || err != nil || n == 0 {
		return "", 0, fmt.Errorf("invalid endpoint %q", ep)
	}
	return host, uint16(n), nil
}

//go:build linux

package tunnel

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgDevice is the WireGuard implementation behind the link: the kernel module
// or wireguard-go. Links, addresses and routes are handled by Tunnel.
type wgDevice interface {
	// start begins packet processing once the link is up.
	start() error
	setEndpoint(netip.AddrPort) error
	peer() (peerStatus, error)
	close() error
}

type peerStatus struct {
	lastHandshake time.Time
	rx, tx        int64
}

type deviceParams struct {
	name      string
	mtu       int
	private   wgtypes.Key
	peer      wgtypes.Key
	endpoint  netip.AddrPort
	mark      uint32
	keepalive time.Duration
}

var errNoKernelWireGuard = errors.New("kernel has no WireGuard support")

func createDevice(mode Mode, p deviceParams, log *slog.Logger) (wgDevice, Mode, error) {
	if mode != ModeUserspace {
		d, err := newKernelDevice(p)
		if mode == ModeKernel || !errors.Is(err, errNoKernelWireGuard) {
			return d, ModeKernel, err
		}
		log.Warn("kernel WireGuard unavailable, falling back to userspace wireguard-go", "error", err)
	}
	d, err := newUserspaceDevice(p, log)
	return d, ModeUserspace, err
}

type kernelDevice struct {
	name   string
	peerPK wgtypes.Key
	client *wgctrl.Client
}

func newKernelDevice(p deviceParams) (wgDevice, error) {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = p.name
	attrs.MTU = p.mtu
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			return nil, fmt.Errorf("%w: create %s: %v", errNoKernelWireGuard, p.name, err)
		}
		return nil, fmt.Errorf("create WireGuard link %s: %w", p.name, err)
	}
	d := &kernelDevice{name: p.name, peerPK: p.peer}
	err := d.configure(p)
	if err != nil {
		_ = d.close()
		if link, lerr := netlink.LinkByName(p.name); lerr == nil {
			_ = netlink.LinkDel(link)
		}
		return nil, err
	}
	return d, nil
}

func (d *kernelDevice) configure(p deviceParams) (err error) {
	if d.client, err = wgctrl.New(); err != nil {
		return fmt.Errorf("open WireGuard netlink: %w", err)
	}
	mark := int(p.mark)
	keepalive := p.keepalive
	err = d.client.ConfigureDevice(d.name, wgtypes.Config{
		PrivateKey:   &p.private,
		FirewallMark: &mark,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   p.peer,
			Endpoint:                    net.UDPAddrFromAddrPort(p.endpoint),
			PersistentKeepaliveInterval: &keepalive,
			ReplaceAllowedIPs:           true,
			AllowedIPs: []net.IPNet{
				*ipNet(netip.PrefixFrom(netip.IPv4Unspecified(), 0)),
				*ipNet(netip.PrefixFrom(netip.IPv6Unspecified(), 0)),
			},
		}},
	})
	if err != nil {
		return fmt.Errorf("configure WireGuard device %s: %w", d.name, err)
	}
	return nil
}

func (d *kernelDevice) start() error { return nil }

func (d *kernelDevice) setEndpoint(ep netip.AddrPort) error {
	return d.client.ConfigureDevice(d.name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey:  d.peerPK,
		UpdateOnly: true,
		Endpoint:   net.UDPAddrFromAddrPort(ep),
	}}})
}

func (d *kernelDevice) peer() (peerStatus, error) {
	dev, err := d.client.Device(d.name)
	if err != nil {
		return peerStatus{}, err
	}
	for _, p := range dev.Peers {
		if p.PublicKey != d.peerPK {
			continue
		}
		return peerStatus{lastHandshake: p.LastHandshakeTime, rx: p.ReceiveBytes, tx: p.TransmitBytes}, nil
	}
	return peerStatus{}, errors.New("peer not configured")
}

// close releases the control socket; Tunnel deletes the link.
func (d *kernelDevice) close() error {
	if d.client == nil {
		return nil
	}
	return d.client.Close()
}

type userspaceDevice struct {
	dev    *device.Device
	peerPK wgtypes.Key
}

func newUserspaceDevice(p deviceParams, log *slog.Logger) (wgDevice, error) {
	tdev, err := tun.CreateTUN(p.name, p.mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN %s: %w", p.name, err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), wireguardLogger(log))
	if err := dev.IpcSet(uapiConfig(p)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure wireguard-go: %w", err)
	}
	return &userspaceDevice{dev: dev, peerPK: p.peer}, nil
}

func (d *userspaceDevice) start() error { return d.dev.Up() }

func (d *userspaceDevice) setEndpoint(ep netip.AddrPort) error {
	return d.dev.IpcSet(uapiEndpoint(d.peerPK, ep))
}

func (d *userspaceDevice) peer() (peerStatus, error) {
	s, err := d.dev.IpcGet()
	if err != nil {
		return peerStatus{}, err
	}
	return parseUAPIPeer(s, d.peerPK)
}

// close shuts wireguard-go down; closing the TUN removes the link.
func (d *userspaceDevice) close() error {
	d.dev.Close()
	return nil
}

func wireguardLogger(log *slog.Logger) *device.Logger {
	logf := func(format string, args ...any) {
		if log.Enabled(context.Background(), slog.LevelDebug) {
			log.Debug(fmt.Sprintf(format, args...), "source", "wireguard-go")
		}
	}
	return &device.Logger{Verbosef: logf, Errorf: logf}
}

// uapiConfig renders the wireguard-go configuration (cross-platform UAPI "set").
func uapiConfig(p deviceParams) string {
	return fmt.Sprintf("private_key=%s\nfwmark=%d\nreplace_peers=true\n"+
		"public_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\n"+
		"replace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		hex.EncodeToString(p.private[:]), p.mark, hex.EncodeToString(p.peer[:]), p.endpoint,
		int(p.keepalive/time.Second))
}

func uapiEndpoint(peer wgtypes.Key, ep netip.AddrPort) string {
	return fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", hex.EncodeToString(peer[:]), ep)
}

// parseUAPIPeer extracts the statistics of peer from a UAPI "get" response.
func parseUAPIPeer(s string, peer wgtypes.Key) (peerStatus, error) {
	want := hex.EncodeToString(peer[:])
	var st peerStatus
	var found, current bool
	var sec, nsec int64
	for line := range strings.SplitSeq(s, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			current = value == want
			found = found || current
			continue
		}
		if !current {
			continue
		}
		var err error
		switch key {
		case "last_handshake_time_sec":
			sec, err = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nsec, err = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			st.rx, err = strconv.ParseInt(value, 10, 64)
		case "tx_bytes":
			st.tx, err = strconv.ParseInt(value, 10, 64)
		}
		if err != nil {
			return peerStatus{}, fmt.Errorf("parse %s: %w", key, err)
		}
	}
	if !found {
		return peerStatus{}, errors.New("peer not configured")
	}
	if sec > 0 || nsec > 0 {
		st.lastHandshake = time.Unix(sec, nsec)
	}
	return st, nil
}

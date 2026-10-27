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
	// replacePeer drops the peer, with its session, and adds it back with
	// endpoint: a session is bound to the endpoint that accepted it, and
	// WireGuard would otherwise keep using it until it gives up (15s+). The
	// new peer's persistent keepalive starts a handshake at once.
	replacePeer(endpoint netip.AddrPort) error
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
	name      string
	peerPK    wgtypes.Key
	keepalive time.Duration
	client    *wgctrl.Client
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
	d := &kernelDevice{name: p.name, peerPK: p.peer, keepalive: p.keepalive}
	err := tagLink(p.name) // before anything else, so a crash rarely leaves an untagged link
	if err == nil {
		err = d.configure(p)
	}
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
	cfg := d.peerConfig(p.endpoint)
	cfg.PrivateKey = &p.private
	if err := d.client.ConfigureDevice(d.name, cfg); err != nil {
		return fmt.Errorf("configure WireGuard device %s: %w", d.name, err)
	}
	return nil
}

// peerConfig replaces all peers with ours, so it also drops an old session.
func (d *kernelDevice) peerConfig(endpoint netip.AddrPort) wgtypes.Config {
	keepalive := d.keepalive
	return wgtypes.Config{
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   d.peerPK,
			Endpoint:                    net.UDPAddrFromAddrPort(endpoint),
			PersistentKeepaliveInterval: &keepalive,
			ReplaceAllowedIPs:           true,
			AllowedIPs: []net.IPNet{
				*ipNet(netip.PrefixFrom(netip.IPv4Unspecified(), 0)),
				*ipNet(netip.PrefixFrom(netip.IPv6Unspecified(), 0)),
			},
		}},
	}
}

func (d *kernelDevice) start() error { return nil }

func (d *kernelDevice) replacePeer(ep netip.AddrPort) error {
	return d.client.ConfigureDevice(d.name, d.peerConfig(ep))
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
	dev       *device.Device
	peerPK    wgtypes.Key
	keepalive time.Duration
}

func newUserspaceDevice(p deviceParams, log *slog.Logger) (wgDevice, error) {
	tdev, err := tun.CreateTUN(p.name, p.mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN %s: %w", p.name, err)
	}
	if err := tagLink(p.name); err != nil {
		tdev.Close()
		return nil, err
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), wireguardLogger(log))
	d := &userspaceDevice{dev: dev, peerPK: p.peer, keepalive: p.keepalive}
	if err := dev.IpcSet("private_key=" + hex.EncodeToString(p.private[:]) + "\n" + d.uapiPeer(p.endpoint)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure wireguard-go: %w", err)
	}
	return d, nil
}

func (d *userspaceDevice) start() error { return d.dev.Up() }

func (d *userspaceDevice) replacePeer(ep netip.AddrPort) error {
	return d.dev.IpcSet(d.uapiPeer(ep))
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

// uapiPeer renders a wireguard-go UAPI "set" that replaces all peers with
// ours, so it also drops an old session.
func (d *userspaceDevice) uapiPeer(endpoint netip.AddrPort) string {
	return fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\n"+
		"replace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		hex.EncodeToString(d.peerPK[:]), endpoint, int(d.keepalive/time.Second))
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

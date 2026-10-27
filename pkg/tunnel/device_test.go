//go:build linux

package tunnel

import (
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestUAPIPeer(t *testing.T) {
	peer := testKey(t).PublicKey()
	d := &userspaceDevice{peerPK: peer, keepalive: 25 * time.Second}
	// Also what RotateEndpoint applies: replacing the peer drops its session,
	// and the new peer's keepalive starts a handshake. No fwmark: WireGuard's
	// own UDP must keep using the main table.
	got := d.uapiPeer(netip.MustParseAddrPort("[2606:4700:d0::a29f:c001]:2408"))
	want := "replace_peers=true\n" +
		"public_key=" + hex.EncodeToString(peer[:]) + "\n" +
		"endpoint=[2606:4700:d0::a29f:c001]:2408\n" +
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=0.0.0.0/0\n" +
		"allowed_ip=::/0\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestKernelPeerConfig(t *testing.T) {
	peer := testKey(t).PublicKey()
	d := &kernelDevice{peerPK: peer, keepalive: 25 * time.Second}
	cfg := d.peerConfig(netip.MustParseAddrPort("162.159.192.1:500"))
	if !cfg.ReplacePeers || cfg.PrivateKey != nil || cfg.FirewallMark != nil || len(cfg.Peers) != 1 {
		t.Fatalf("device config: %+v", cfg)
	}
	p := cfg.Peers[0]
	if p.PublicKey != peer || p.UpdateOnly || p.Endpoint.String() != "162.159.192.1:500" ||
		*p.PersistentKeepaliveInterval != 25*time.Second || !p.ReplaceAllowedIPs || len(p.AllowedIPs) != 2 ||
		p.AllowedIPs[0].String() != "0.0.0.0/0" || p.AllowedIPs[1].String() != "::/0" {
		t.Fatalf("peer config: %+v", p)
	}
}

func TestParseUAPIPeer(t *testing.T) {
	ours, other := testKey(t).PublicKey(), testKey(t).PublicKey()
	peerBlock := func(k wgtypes.Key, endpoint string, sec, nsec, rx, tx int) string {
		return "public_key=" + hex.EncodeToString(k[:]) + "\n" +
			"preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n" +
			"protocol_version=1\nendpoint=" + endpoint + "\n" +
			"last_handshake_time_sec=" + strconv.Itoa(sec) + "\nlast_handshake_time_nsec=" + strconv.Itoa(nsec) + "\n" +
			"tx_bytes=" + strconv.Itoa(tx) + "\nrx_bytes=" + strconv.Itoa(rx) + "\n" +
			"persistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n"
	}
	dump := "private_key=abcd\nlisten_port=41000\nfwmark=51820\n" +
		peerBlock(other, "198.51.100.1:1", 1, 0, 1, 1) +
		peerBlock(ours, "162.159.192.1:2408", 1761571200, 500, 4096, 2048) + "errno=0\n\n"
	st, err := parseUAPIPeer(dump, ours)
	if err != nil {
		t.Fatal(err)
	}
	if st.rx != 4096 || st.tx != 2048 ||
		!st.lastHandshake.Equal(time.Unix(1761571200, 500)) {
		t.Fatalf("unexpected status %+v", st)
	}

	st, err = parseUAPIPeer(peerBlock(ours, "162.159.192.1:2408", 0, 0, 0, 0), ours)
	if err != nil || !st.lastHandshake.IsZero() {
		t.Fatalf("no handshake must give a zero time: %+v %v", st, err)
	}
	if _, err := parseUAPIPeer(peerBlock(other, "198.51.100.1:1", 0, 0, 0, 0), ours); err == nil {
		t.Fatal("missing peer not reported")
	}
	bad := strings.Replace(peerBlock(ours, "162.159.192.1:2408", 0, 0, 0, 0), "rx_bytes=0", "rx_bytes=x", 1)
	if _, err := parseUAPIPeer(bad, ours); err == nil {
		t.Fatal("malformed counter accepted")
	}
}

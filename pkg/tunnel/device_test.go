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

func TestUAPIConfig(t *testing.T) {
	private, peer := testKey(t), testKey(t).PublicKey()
	got := uapiConfig(deviceParams{
		name:      "wg0",
		mtu:       1280,
		private:   private,
		peer:      peer,
		endpoint:  netip.MustParseAddrPort("[2606:4700:d0::a29f:c001]:2408"),
		keepalive: 25 * time.Second,
	})
	// No fwmark: WireGuard's own UDP must keep using the main table.
	want := "private_key=" + hex.EncodeToString(private[:]) + "\n" +
		"replace_peers=true\n" +
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

func TestUAPIEndpoint(t *testing.T) {
	peer := testKey(t).PublicKey()
	got := uapiEndpoint(peer, netip.MustParseAddrPort("162.159.192.1:500"))
	want := "public_key=" + hex.EncodeToString(peer[:]) + "\nupdate_only=true\nendpoint=162.159.192.1:500\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
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

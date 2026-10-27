//go:build linux

package tunnel

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func validConfig(t *testing.T) Config {
	return Config{
		PrivateKey:    testKey(t).String(),
		PeerPublicKey: testKey(t).PublicKey().String(),
		Endpoints:     []string{"engage.cloudflareclient.com:2408", "162.159.192.1:2408"},
		Addresses:     []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32"), netip.MustParsePrefix("2606:4700:110::2/128")},
	}
}

func TestConfigDefaults(t *testing.T) {
	c := Config{}.withDefaults()
	if c.Interface != "wg0" || c.Mode != ModeAuto || c.MTU != 1280 || c.PersistentKeepalive != 25*time.Second ||
		c.FwMark != 0xca6c || c.Table != 51820 || c.Logger == nil {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	custom := Config{Interface: "warp", Mode: ModeUserspace, MTU: 1420, PersistentKeepalive: time.Second, FwMark: 7, Table: 100}
	if got := custom.withDefaults(); got.Interface != "warp" || got.Mode != ModeUserspace || got.MTU != 1420 ||
		got.PersistentKeepalive != time.Second || got.FwMark != 7 || got.Table != 100 {
		t.Fatalf("explicit values overridden: %+v", got)
	}
}

func TestConfigValidate(t *testing.T) {
	if err := validConfig(t).withDefaults().validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"long interface", func(c *Config) { c.Interface = "abcdefghijklmnop" }, "interface name"},
		{"slash in interface", func(c *Config) { c.Interface = "wg/0" }, "interface name"},
		{"unknown mode", func(c *Config) { c.Mode = "magic" }, "mode"},
		{"bad private key", func(c *Config) { c.PrivateKey = "nope" }, "private key"},
		{"bad peer key", func(c *Config) { c.PeerPublicKey = "" }, "peer public key"},
		{"no endpoints", func(c *Config) { c.Endpoints = nil }, "no endpoint"},
		{"endpoint without port", func(c *Config) { c.Endpoints = []string{"162.159.192.1"} }, "invalid endpoint"},
		{"endpoint port zero", func(c *Config) { c.Endpoints = []string{"162.159.192.1:0"} }, "invalid endpoint"},
		{"endpoint without host", func(c *Config) { c.Endpoints = []string{":2408"} }, "invalid endpoint"},
		{"no IPv4 address", func(c *Config) { c.Addresses = c.Addresses[1:] }, "IPv4"},
		{"invalid address", func(c *Config) { c.Addresses = append(c.Addresses, netip.Prefix{}) }, "invalid interface address"},
		{"mapped address", func(c *Config) {
			c.Addresses = append(c.Addresses, netip.MustParsePrefix("::ffff:172.16.0.3/128"))
		}, "invalid interface address"},
		{"MTU too small", func(c *Config) { c.MTU = 500 }, "MTU"},
		{"negative keepalive", func(c *Config) { c.PersistentKeepalive = -time.Second }, "keepalive"},
		{"main table", func(c *Config) { c.Table = 254 }, "reserved"},
		{"negative table", func(c *Config) { c.Table = -1 }, "routing table"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig(t)
			tc.mutate(&c)
			err := c.withDefaults().validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

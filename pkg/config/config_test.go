package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestConfigLoadDefaults(t *testing.T) {
	// 清理可能存在的环境变量
	for _, k := range []string{"WARP_PROXY_HOST", "WARP_PROXY_PORT", "PORT", "WARP_LICENSE_KEY", "HEALTH_PORT",
		"WARP_DATA_DIR", "WG_MODE", "WG_INTERFACE", "WG_MTU", "WG_ENDPOINT", "DNS_SERVERS", "ALLOW_PRIVATE_DESTINATIONS", "DIAL_TIMEOUT"} {
		os.Unsetenv(k)
	}

	cfg := LoadFromEnv()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}

	if cfg.ProxyHost != "0.0.0.0" {
		t.Errorf("expected ProxyHost 0.0.0.0, got %s", cfg.ProxyHost)
	}
	if cfg.ProxyPort != 1080 {
		t.Errorf("expected ProxyPort 1080, got %d", cfg.ProxyPort)
	}
	if cfg.HealthPort != 8080 {
		t.Errorf("expected HealthPort 8080, got %d", cfg.HealthPort)
	}
	if cfg.ProxyListenAddr() != "0.0.0.0:1080" {
		t.Errorf("expected ProxyListenAddr 0.0.0.0:1080, got %s", cfg.ProxyListenAddr())
	}
	if cfg.LocalProxyAddr() != "127.0.0.1:1080" {
		t.Errorf("expected LocalProxyAddr 127.0.0.1:1080, got %s", cfg.LocalProxyAddr())
	}
	if cfg.RegistrationPath() != "/var/lib/cloudflare-warp/wireguard-account.json" {
		t.Errorf("unexpected registration path %s", cfg.RegistrationPath())
	}
	if cfg.WGMode != "auto" || cfg.WGInterface != "warp0" || cfg.WGMTU != 1280 || len(cfg.WGEndpoints) != 0 {
		t.Errorf("unexpected WireGuard defaults: %+v", cfg)
	}
	if !reflect.DeepEqual(cfg.DNSServers, []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"}) {
		t.Errorf("unexpected DNS defaults %v", cfg.DNSServers)
	}
	if cfg.AllowPrivateDestinations {
		t.Error("private destinations must be refused by default")
	}
	if cfg.DialTimeout != 10*time.Second {
		t.Errorf("expected DialTimeout 10s, got %v", cfg.DialTimeout)
	}
	if cfg.ConnectTimeout != 90*time.Second {
		t.Errorf("expected ConnectTimeout 90s, got %v", cfg.ConnectTimeout)
	}
}

func TestConfigLoadFromEnv(t *testing.T) {
	t.Setenv("WARP_PROXY_PORT", "1088")
	t.Setenv("WARP_LICENSE_KEY", "test-license-key-1234")
	t.Setenv("HEALTH_PORT", "9090")
	t.Setenv("CONNECT_TIMEOUT", "30s")
	t.Setenv("WG_MODE", "Kernel")
	t.Setenv("WG_ENDPOINT", " 162.159.192.1:2408 , engage.cloudflareclient.com:500,")
	t.Setenv("DNS_SERVERS", "9.9.9.9,[2620:fe::fe]:53")
	t.Setenv("ALLOW_PRIVATE_DESTINATIONS", "true")
	t.Setenv("WARP_DATA_DIR", "/data")

	cfg := LoadFromEnv()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	if cfg.ProxyPort != 1088 {
		t.Errorf("expected ProxyPort 1088, got %d", cfg.ProxyPort)
	}
	if cfg.LicenseKey != "test-license-key-1234" {
		t.Errorf("expected LicenseKey test-license-key-1234, got %s", cfg.LicenseKey)
	}
	if cfg.HealthPort != 9090 {
		t.Errorf("expected HealthPort 9090, got %d", cfg.HealthPort)
	}
	if cfg.ConnectTimeout != 30*time.Second {
		t.Errorf("expected ConnectTimeout 30s, got %v", cfg.ConnectTimeout)
	}
	if cfg.WGMode != "kernel" {
		t.Errorf("expected lower-cased WG_MODE, got %q", cfg.WGMode)
	}
	if !reflect.DeepEqual(cfg.WGEndpoints, []string{"162.159.192.1:2408", "engage.cloudflareclient.com:500"}) {
		t.Errorf("unexpected endpoints %v", cfg.WGEndpoints)
	}
	if !reflect.DeepEqual(cfg.DNSServers, []string{"9.9.9.9", "[2620:fe::fe]:53"}) {
		t.Errorf("unexpected DNS servers %v", cfg.DNSServers)
	}
	if !cfg.AllowPrivateDestinations {
		t.Error("expected AllowPrivateDestinations")
	}
	if cfg.RegistrationPath() != "/data/wireguard-account.json" {
		t.Errorf("unexpected registration path %s", cfg.RegistrationPath())
	}
}

func TestConfigPortCompatibility(t *testing.T) {
	os.Unsetenv("WARP_PROXY_PORT")
	t.Setenv("PORT", "2080")

	cfg := LoadFromEnv()
	if cfg.ProxyPort != 2080 {
		t.Errorf("expected ProxyPort 2080 from PORT env, got %d", cfg.ProxyPort)
	}
}

func TestConfigValidateRejects(t *testing.T) {
	cases := map[string]func(*Config){
		"WARP_PROXY_PORT": func(c *Config) { c.ProxyPort = 0 },
		"WG_MODE":         func(c *Config) { c.WGMode = "masque" },
		"WG_INTERFACE":    func(c *Config) { c.WGInterface = "interface-name-too-long" },
		"WG_MTU":          func(c *Config) { c.WGMTU = 576 },
		"WG_ENDPOINT":     func(c *Config) { c.WGEndpoints = []string{"162.159.192.1"} },
		"DNS_SERVERS":     func(c *Config) { c.DNSServers = []string{"one.one.one.one"} },
		"timeouts":        func(c *Config) { c.DialTimeout = 0 },
		"WARP_DATA_DIR":   func(c *Config) { c.DataDir = "" },
	}
	for want, mutate := range cases {
		cfg := LoadFromEnv()
		mutate(cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: expected validation error, got %v", want, err)
		}
	}
}

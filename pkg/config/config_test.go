package config

import (
	"os"
	"testing"
	"time"
)

func TestConfigLoadDefaults(t *testing.T) {
	// 清理可能存在的环境变量
	os.Unsetenv("WARP_PROXY_HOST")
	os.Unsetenv("WARP_PROXY_PORT")
	os.Unsetenv("PORT")
	os.Unsetenv("WARP_SVC_PORT")
	os.Unsetenv("WARP_LICENSE_KEY")
	os.Unsetenv("HEALTH_PORT")

	cfg := LoadFromEnv()

	if cfg.ProxyHost != "0.0.0.0" {
		t.Errorf("expected ProxyHost 0.0.0.0, got %s", cfg.ProxyHost)
	}
	if cfg.ProxyPort != 1080 {
		t.Errorf("expected ProxyPort 1080, got %d", cfg.ProxyPort)
	}
	if cfg.WarpSvcPort != 40000 {
		t.Errorf("expected WarpSvcPort 40000, got %d", cfg.WarpSvcPort)
	}
	if cfg.HealthPort != 8080 {
		t.Errorf("expected HealthPort 8080, got %d", cfg.HealthPort)
	}
	if cfg.ProxyListenAddr() != "0.0.0.0:1080" {
		t.Errorf("expected ProxyListenAddr 0.0.0.0:1080, got %s", cfg.ProxyListenAddr())
	}
	if cfg.WarpSvcTargetAddr() != "127.0.0.1:40000" {
		t.Errorf("expected WarpSvcTargetAddr 127.0.0.1:40000, got %s", cfg.WarpSvcTargetAddr())
	}
	if cfg.LocalProxyAddr() != "127.0.0.1:1080" {
		t.Errorf("expected LocalProxyAddr 127.0.0.1:1080, got %s", cfg.LocalProxyAddr())
	}
}

func TestConfigLoadFromEnv(t *testing.T) {
	t.Setenv("WARP_PROXY_PORT", "1088")
	t.Setenv("WARP_SVC_PORT", "40001")
	t.Setenv("WARP_LICENSE_KEY", "test-license-key-1234")
	t.Setenv("HEALTH_PORT", "9090")
	t.Setenv("CONNECT_TIMEOUT", "30s")

	cfg := LoadFromEnv()

	if cfg.ProxyPort != 1088 {
		t.Errorf("expected ProxyPort 1088, got %d", cfg.ProxyPort)
	}
	if cfg.WarpSvcPort != 40001 {
		t.Errorf("expected WarpSvcPort 40001, got %d", cfg.WarpSvcPort)
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
}

func TestConfigPortCompatibility(t *testing.T) {
	os.Unsetenv("WARP_PROXY_PORT")
	t.Setenv("PORT", "2080")

	cfg := LoadFromEnv()
	if cfg.ProxyPort != 2080 {
		t.Errorf("expected ProxyPort 2080 from PORT env, got %d", cfg.ProxyPort)
	}
}

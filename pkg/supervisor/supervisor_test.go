package supervisor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/riba2534/warp-proxy/pkg/cfwarp"
	"github.com/riba2534/warp-proxy/pkg/config"
	"github.com/riba2534/warp-proxy/pkg/health"
	"github.com/riba2534/warp-proxy/pkg/tunnel"
)

type fakeTunnel struct {
	mu        sync.Mutex
	status    tunnel.Status
	rotations int
	closed    int
}

func (f *fakeTunnel) Status() (tunnel.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, nil
}

func (f *fakeTunnel) RotateEndpoint() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rotations++
	f.status.Endpoint = "162.159.193.10:500"
	return f.status.Endpoint, nil
}

func (f *fakeTunnel) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

func (f *fakeTunnel) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rotations, f.closed
}

// runWithin runs s.Run and fails the test if it does not return in time.
func runWithin(t *testing.T, s *Supervisor, d time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.Run() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		s.cancel()
		t.Fatalf("Run did not return within %v", d)
		return nil
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func testConfig(t *testing.T) *config.Config {
	cfg := config.LoadFromEnv()
	cfg.ProxyHost = "127.0.0.1"
	cfg.ProxyPort = freePort(t)
	cfg.HealthPort = 0
	cfg.DataDir = t.TempDir()
	cfg.ConnectTimeout = 2 * time.Second
	cfg.RecoveryFailures = 0
	return cfg
}

var testProfile = &cfwarp.Profile{
	PrivateKey:    "priv",
	PeerPublicKey: "peer",
	Endpoints:     []string{"engage.cloudflareclient.com:2408", "162.159.192.1:2408"},
	AddressV4:     netip.MustParsePrefix("172.16.0.2/32"),
	AddressV6:     netip.MustParsePrefix("2606:4700:110:8000::1/128"),
	DeviceID:      "dev",
}

func TestRunWiresRegistrationIntoTunnelAndProxy(t *testing.T) {
	cfg := testConfig(t)
	cfg.LicenseKey = "lic"
	cfg.WGMode = "userspace"
	cfg.WGEndpoints = []string{"162.159.192.1:2408", "198.51.100.1:500"}
	s := NewSupervisor(cfg)
	ft := &fakeTunnel{status: tunnel.Status{Mode: tunnel.ModeUserspace, Endpoint: "162.159.192.1:2408"}}
	var gotOpts cfwarp.Options
	var gotCfg tunnel.Config
	s.loadProfile = func(ctx context.Context, opts cfwarp.Options) (*cfwarp.Profile, error) {
		gotOpts = opts
		return testProfile, nil
	}
	s.tunnelUp = func(ctx context.Context, c tunnel.Config) (tunnelHandle, error) {
		gotCfg = c
		return ft, nil
	}
	ready := make(chan struct{})
	var once sync.Once
	s.probe = func(ctx context.Context) *health.Result {
		once.Do(func() { close(ready) })
		return &health.Result{Healthy: true, TraceWarp: "on"}
	}
	done := make(chan error, 1)
	go func() { done <- s.Run() }()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor never probed readiness")
	}
	conn, err := net.DialTimeout("tcp", cfg.ProxyListenAddr(), time.Second)
	if err != nil {
		t.Fatalf("proxy not listening: %v", err)
	}
	conn.Close()
	s.cancel()
	if err := <-done; err != nil {
		t.Fatalf("clean stop returned %v", err)
	}

	if gotOpts.Path != cfg.RegistrationPath() || gotOpts.LicenseKey != "lic" {
		t.Errorf("registration options not passed through: %+v", gotOpts)
	}
	wantEndpoints := []string{"162.159.192.1:2408", "198.51.100.1:500", "engage.cloudflareclient.com:2408"}
	if !reflect.DeepEqual(gotCfg.Endpoints, wantEndpoints) {
		t.Errorf("endpoints: got %v want %v (overrides first, deduplicated)", gotCfg.Endpoints, wantEndpoints)
	}
	if !reflect.DeepEqual(gotCfg.Addresses, []netip.Prefix{testProfile.AddressV4, testProfile.AddressV6}) {
		t.Errorf("addresses: %v", gotCfg.Addresses)
	}
	if gotCfg.Mode != tunnel.ModeUserspace || gotCfg.Interface != "wg0" || gotCfg.MTU != 1280 ||
		gotCfg.PrivateKey != "priv" || gotCfg.PeerPublicKey != "peer" {
		t.Errorf("tunnel config: %+v", gotCfg)
	}
	if _, closed := ft.counts(); closed != 1 {
		t.Errorf("tunnel closed %d times on shutdown", closed)
	}
}

func TestRunFailsAndCleansUpWhenTunnelNeverWorks(t *testing.T) {
	cfg := testConfig(t)
	cfg.ConnectTimeout = 300 * time.Millisecond
	s := NewSupervisor(cfg)
	ft := &fakeTunnel{}
	s.loadProfile = func(context.Context, cfwarp.Options) (*cfwarp.Profile, error) { return testProfile, nil }
	s.tunnelUp = func(context.Context, tunnel.Config) (tunnelHandle, error) { return ft, nil }
	s.probe = func(context.Context) *health.Result { return &health.Result{Error: "trace timeout"} }
	err := runWithin(t, s, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "not usable") || !strings.Contains(err.Error(), "trace timeout") {
		t.Fatalf("expected readiness failure, got %v", err)
	}
	if _, closed := ft.counts(); closed != 1 {
		t.Errorf("tunnel not torn down after failed start (closed=%d)", closed)
	}
	if conn, err := net.DialTimeout("tcp", cfg.ProxyListenAddr(), 200*time.Millisecond); err == nil {
		conn.Close()
		t.Error("proxy still listening after failed start")
	}
}

func TestRunReportsRegistrationAndTunnelErrors(t *testing.T) {
	cfg := testConfig(t)
	s := NewSupervisor(cfg)
	s.loadProfile = func(context.Context, cfwarp.Options) (*cfwarp.Profile, error) { return nil, errors.New("api down") }
	if err := runWithin(t, s, 5*time.Second); err == nil || !strings.Contains(err.Error(), "WARP registration: api down") {
		t.Fatalf("got %v", err)
	}

	s = NewSupervisor(testConfig(t))
	s.loadProfile = func(context.Context, cfwarp.Options) (*cfwarp.Profile, error) { return testProfile, nil }
	s.tunnelUp = func(context.Context, tunnel.Config) (tunnelHandle, error) { return nil, errors.New("no CAP_NET_ADMIN") }
	if err := runWithin(t, s, 5*time.Second); err == nil || !strings.Contains(err.Error(), "WireGuard tunnel: no CAP_NET_ADMIN") {
		t.Fatalf("got %v", err)
	}
}

func TestRotateIfStale(t *testing.T) {
	s := NewSupervisor(testConfig(t))
	ft := &fakeTunnel{status: tunnel.Status{Endpoint: "162.159.192.1:2408"}}
	s.tun = ft

	// A fresh endpoint gets time for its first handshake.
	s.lastSwitch = time.Now()
	s.rotateIfStale("test")
	if r, _ := ft.counts(); r != 0 {
		t.Fatalf("rotated inside the grace period")
	}

	// A recent handshake means the endpoint works.
	s.lastSwitch = time.Now().Add(-time.Hour)
	ft.status.LastHandshake = time.Now().Add(-30 * time.Second)
	s.rotateIfStale("test")
	if r, _ := ft.counts(); r != 0 {
		t.Fatalf("rotated despite a recent handshake")
	}

	// No handshake for longer than WireGuard's rekey cycle: move on.
	ft.status.LastHandshake = time.Now().Add(-staleHandshake - time.Second)
	s.rotateIfStale("test")
	if r, _ := ft.counts(); r != 1 {
		t.Fatalf("stale handshake did not rotate")
	}
	if time.Since(s.lastSwitch) > time.Second {
		t.Fatal("rotation did not restart the grace period")
	}
}

func TestRecoveryThreshold(t *testing.T) {
	cfg := testConfig(t)
	cfg.RecoveryGrace = 0
	cfg.RecoveryInterval = 10 * time.Millisecond
	cfg.RecoveryFailures = 3
	s := NewSupervisor(cfg)
	defer s.shutdown()
	ft := &fakeTunnel{}
	s.tun, s.lastSwitch = ft, time.Now().Add(-time.Hour)
	s.checker = health.NewChecker("127.0.0.1:1", 10*time.Millisecond)
	go s.monitorHealth()
	select {
	case err := <-s.failures:
		if !strings.Contains(err.Error(), "3 consecutive") {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("persistent failure did not trigger recovery")
	}
	if r, _ := ft.counts(); r == 0 {
		t.Error("stale endpoint was never rotated before giving up")
	}
}

func TestMonitorHonorsCancellation(t *testing.T) {
	cfg := testConfig(t)
	cfg.RecoveryGrace = time.Hour
	s := NewSupervisor(cfg)
	defer s.shutdown()
	done := make(chan struct{})
	go func() { s.monitorHealth(); close(done) }()
	s.cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor ignored cancellation")
	}
}

func TestRunReturnsStartupError(t *testing.T) {
	cfg := config.LoadFromEnv()
	cfg.ProxyPort = -1
	s := NewSupervisor(cfg)
	if err := runWithin(t, s, 5*time.Second); err == nil || !strings.Contains(err.Error(), "WARP_PROXY_PORT") {
		t.Fatalf("startup error swallowed by shutdown: %v", err)
	}
}

func TestStatusBeforeTunnel(t *testing.T) {
	s := NewSupervisor(testConfig(t))
	if _, err := s.Status(); err == nil {
		t.Fatal("expected an error before the tunnel exists")
	}
}

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
	mu          sync.Mutex
	status      tunnel.Status
	handshaking bool // report a handshake that just happened
	onRotate    func(*fakeTunnel)
	rotateCtx   context.Context
	rotations   int
	closed      int
}

func (f *fakeTunnel) Status() (tunnel.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.status
	if f.handshaking {
		st.LastHandshake = time.Now()
	}
	return st, nil
}

func (f *fakeTunnel) RotateEndpoint(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rotations++
	f.rotateCtx = ctx
	f.status.Endpoint = "162.159.193.10:500"
	if f.onRotate != nil {
		f.onRotate(f)
	}
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
	ft := &fakeTunnel{status: tunnel.Status{Mode: tunnel.ModeUserspace, Endpoint: "162.159.192.1:2408"}, handshaking: true}
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
	if gotCfg.Mode != tunnel.ModeUserspace || gotCfg.Interface != "warp0" || gotCfg.MTU != 1280 ||
		gotCfg.PrivateKey != "priv" || gotCfg.PeerPublicKey != "peer" || gotCfg.Mark != tunnel.DefaultMark {
		t.Errorf("tunnel config: %+v", gotCfg)
	}
	if _, closed := ft.counts(); closed != 1 {
		t.Errorf("tunnel closed %d times on shutdown", closed)
	}
}

func TestRunFailsAndCleansUpWhenTraceNeverWorks(t *testing.T) {
	cfg := testConfig(t)
	cfg.ConnectTimeout = 300 * time.Millisecond
	s := NewSupervisor(cfg)
	ft := &fakeTunnel{handshaking: true}
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

func TestStartupRotatesEndpointsWithoutHandshake(t *testing.T) {
	cfg := testConfig(t)
	cfg.ConnectTimeout = 2500 * time.Millisecond // readiness is checked once a second
	s := NewSupervisor(cfg)
	s.grace = 50 * time.Millisecond
	ft := &fakeTunnel{}
	probes := 0
	s.loadProfile = func(context.Context, cfwarp.Options) (*cfwarp.Profile, error) { return testProfile, nil }
	s.tunnelUp = func(context.Context, tunnel.Config) (tunnelHandle, error) { return ft, nil }
	s.probe = func(context.Context) *health.Result { probes++; return &health.Result{Error: "unreachable"} }
	err := runWithin(t, s, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "no WireGuard handshake yet") {
		t.Fatalf("expected a handshake error, got %v", err)
	}
	if r, closed := ft.counts(); r == 0 || closed != 1 {
		t.Errorf("rotations=%d closed=%d; want endpoint rotation and teardown", r, closed)
	}
	if probes != 0 {
		t.Errorf("probed %d times without a handshake; a blocked endpoint must not cost a trace timeout", probes)
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

func TestRotateRespectsGrace(t *testing.T) {
	s := NewSupervisor(testConfig(t))
	ft := &fakeTunnel{status: tunnel.Status{Endpoint: "162.159.192.1:2408"}}
	s.tun = ft

	// A fresh endpoint gets time for its first handshake.
	s.lastSwitch = time.Now()
	if s.rotate("test") {
		t.Fatal("rotated inside the grace period")
	}
	s.lastSwitch = time.Now().Add(-time.Hour)
	if !s.rotate("test") {
		t.Fatal("did not rotate after the grace period")
	}
	if r, _ := ft.counts(); r != 1 {
		t.Fatalf("rotations=%d", r)
	}
	if time.Since(s.lastSwitch) > time.Second {
		t.Fatal("rotation did not restart the grace period")
	}
}

func TestHandshakeDuringUpCounts(t *testing.T) {
	cfg := testConfig(t)
	cfg.ConnectTimeout = 2 * time.Second
	s := NewSupervisor(cfg)
	s.grace = time.Hour // a missed handshake would never be rotated away from
	ft := &fakeTunnel{}
	probed := make(chan struct{}, 1)
	s.loadProfile = func(context.Context, cfwarp.Options) (*cfwarp.Profile, error) { return testProfile, nil }
	s.tunnelUp = func(context.Context, tunnel.Config) (tunnelHandle, error) {
		// Kernel WireGuard can complete the first handshake before Up returns.
		ft.status.LastHandshake = time.Now()
		time.Sleep(5 * time.Millisecond)
		return ft, nil
	}
	s.probe = func(context.Context) *health.Result {
		select {
		case probed <- struct{}{}:
		default:
		}
		return &health.Result{Healthy: true}
	}
	done := make(chan error, 1)
	go func() { done <- s.Run() }()
	select {
	case <-probed:
	case err := <-done:
		t.Fatalf("handshake completed during Up was ignored: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("never probed")
	}
	s.cancel()
	<-done
}

func TestHandshakeDuringRotationCounts(t *testing.T) {
	s := NewSupervisor(testConfig(t))
	ft := &fakeTunnel{onRotate: func(f *fakeTunnel) { f.status.LastHandshake = time.Now() }}
	s.tun, s.lastSwitch = ft, time.Now().Add(-time.Hour)
	time.Sleep(2 * time.Millisecond)
	if !s.rotate("test") {
		t.Fatal("did not rotate")
	}
	if !s.handshakeSinceSwitch() {
		t.Fatal("handshake completed during RotateEndpoint was ignored")
	}
	// Shutdown must be able to cut a rotation short (its DNS lookups take up to 10s).
	s.cancel()
	if ft.rotateCtx == nil || ft.rotateCtx.Err() == nil {
		t.Fatal("RotateEndpoint did not get the supervisor's context")
	}
}

func TestHandshakeSinceSwitch(t *testing.T) {
	s := NewSupervisor(testConfig(t))
	if s.handshakeSinceSwitch() {
		t.Fatal("no tunnel cannot have a handshake")
	}
	ft := &fakeTunnel{}
	s.tun, s.lastSwitch = ft, time.Now()
	if s.handshakeSinceSwitch() {
		t.Fatal("zero handshake counted")
	}
	// A handshake with the previous endpoint says nothing about the new one.
	ft.status.LastHandshake = s.lastSwitch.Add(-time.Second)
	if s.handshakeSinceSwitch() {
		t.Fatal("handshake from before the switch counted")
	}
	ft.status.LastHandshake = s.lastSwitch.Add(time.Second)
	if !s.handshakeSinceSwitch() {
		t.Fatal("handshake after the switch not counted")
	}
}

// monitorFixture runs monitorHealth against a probe that always fails.
func monitorFixture(t *testing.T, recoveryFailures int) (*Supervisor, *fakeTunnel, *int) {
	cfg := testConfig(t)
	cfg.RecoveryGrace = 0
	cfg.RecoveryInterval = 10 * time.Millisecond
	cfg.RecoveryFailures = recoveryFailures
	s := NewSupervisor(cfg)
	t.Cleanup(s.shutdown)
	s.grace = 0
	ft := &fakeTunnel{}
	s.tun, s.lastSwitch = ft, time.Now().Add(-time.Hour)
	var mu sync.Mutex
	probes := new(int)
	s.probe = func(context.Context) *health.Result {
		mu.Lock()
		defer mu.Unlock()
		*probes++
		return &health.Result{Error: "trace failed"}
	}
	go s.monitorHealth()
	return s, ft, probes
}

func TestRecoveryRotatesBeforeExit(t *testing.T) {
	s, ft, _ := monitorFixture(t, 3)
	select {
	case err := <-s.failures:
		if !strings.Contains(err.Error(), "3 consecutive") {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("persistent failure did not trigger recovery")
	}
	// Rotation starts with the second failure; the third one exits.
	if r, _ := ft.counts(); r != 1 {
		t.Errorf("rotations before exit = %d, want 1", r)
	}
}

func TestRecoveryExitsOnlyAfterRotation(t *testing.T) {
	s, ft, probes := monitorFixture(t, 1)
	select {
	case err := <-s.failures:
		if !strings.Contains(err.Error(), "2 consecutive") {
			t.Fatalf("RECOVERY_FAILURES=1 must still try one rotation first: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no exit")
	}
	if r, _ := ft.counts(); r != 1 || *probes != 2 {
		t.Errorf("rotations=%d probes=%d, want 1 and 2", r, *probes)
	}
}

func TestRecoveryDisabledKeepsRotating(t *testing.T) {
	s, ft, _ := monitorFixture(t, 0)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if r, _ := ft.counts(); r >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("RECOVERY_FAILURES=0 stopped rotating endpoints")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-s.failures:
		t.Fatalf("RECOVERY_FAILURES=0 must never exit: %v", err)
	default:
	}
}

func TestRecoveryWaitsForRotatedEndpoint(t *testing.T) {
	cfg := testConfig(t)
	cfg.RecoveryGrace = 0
	cfg.RecoveryInterval = 10 * time.Millisecond
	cfg.RecoveryFailures = 2
	s := NewSupervisor(cfg)
	t.Cleanup(s.shutdown)
	s.grace = 300 * time.Millisecond
	ft := &fakeTunnel{}
	s.tun, s.lastSwitch = ft, time.Now().Add(-time.Hour)
	s.probe = func(context.Context) *health.Result { return &health.Result{Error: "trace failed"} }
	start := time.Now()
	go s.monitorHealth()
	select {
	case <-s.failures:
		// The rotation happens at the second probe (~20ms); exiting before the
		// new endpoint had its grace would give up on it untried.
		if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
			t.Fatalf("exited %v after start, before the rotated endpoint's grace", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no exit")
	}
}

func TestRecoveryStreakResetsAfterSuccess(t *testing.T) {
	cfg := testConfig(t)
	cfg.RecoveryGrace = 0
	cfg.RecoveryInterval = 10 * time.Millisecond
	cfg.RecoveryFailures = 2
	s := NewSupervisor(cfg)
	t.Cleanup(s.shutdown)
	s.grace = 0
	ft := &fakeTunnel{}
	s.tun, s.lastSwitch = ft, time.Now().Add(-time.Hour)
	// fail, fail (rotate), recover, then fail for good: the new streak must rotate
	// again before exiting instead of reusing the earlier rotation.
	script := []bool{false, false, true}
	n := 0
	s.probe = func(context.Context) *health.Result {
		defer func() { n++ }()
		if n < len(script) && script[n] {
			return &health.Result{Healthy: true}
		}
		return &health.Result{Error: "trace failed"}
	}
	go s.monitorHealth()
	select {
	case err := <-s.failures:
		if !strings.Contains(err.Error(), "3 consecutive") {
			t.Fatalf("second streak exited too early: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no exit")
	}
	if r, _ := ft.counts(); r != 2 {
		t.Errorf("rotations=%d, want one per failure streak", r)
	}
}

func TestRunMonitorsEvenWithoutRecoveryExit(t *testing.T) {
	cfg := testConfig(t)
	cfg.RecoveryFailures = 0
	cfg.RecoveryGrace = 0
	cfg.RecoveryInterval = 10 * time.Millisecond
	s := NewSupervisor(cfg)
	s.grace = 0
	ft := &fakeTunnel{handshaking: true}
	s.loadProfile = func(context.Context, cfwarp.Options) (*cfwarp.Profile, error) { return testProfile, nil }
	s.tunnelUp = func(context.Context, tunnel.Config) (tunnelHandle, error) { return ft, nil }
	var mu sync.Mutex
	ready := false
	s.probe = func(context.Context) *health.Result {
		mu.Lock()
		defer mu.Unlock()
		if !ready { // the startup probe succeeds, everything after fails
			ready = true
			return &health.Result{Healthy: true}
		}
		return &health.Result{Error: "trace failed"}
	}
	done := make(chan error, 1)
	go func() { done <- s.Run() }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if r, _ := ft.counts(); r > 0 {
			break
		}
		if time.Now().After(deadline) {
			s.cancel()
			<-done
			t.Fatal("RECOVERY_FAILURES=0 must still monitor and rotate")
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.cancel()
	if err := <-done; err != nil {
		t.Fatalf("RECOVERY_FAILURES=0 must not exit: %v", err)
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

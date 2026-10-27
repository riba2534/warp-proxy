package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/riba2534/warp-proxy/pkg/cfwarp"
	"github.com/riba2534/warp-proxy/pkg/config"
	"github.com/riba2534/warp-proxy/pkg/health"
	"github.com/riba2534/warp-proxy/pkg/proxy"
	"github.com/riba2534/warp-proxy/pkg/tunnel"
)

// staleHandshake 超过该时长没有握手即视为当前接入点不可用。
// WireGuard 在有流量（含 25s keepalive）时每 2 分钟重新握手一次。
const staleHandshake = 3 * time.Minute

// readyPollInterval 是启动阶段检查握手与探测的间隔
const readyPollInterval = time.Second

// switchGrace 是建隧道或切换接入点后等待首次握手的时间。WireGuard 每 5 秒重发
// 一次握手发起包，6 秒足够容下一次丢包重试。
const switchGrace = 6 * time.Second

type tunnelHandle interface {
	Status() (tunnel.Status, error)
	RotateEndpoint() (string, error)
	Close() error
}

type Supervisor struct {
	cfg       *config.Config
	proxy     *proxy.Server
	healthSrv *health.Server
	checker   *health.Checker
	ctx       context.Context
	cancel    context.CancelFunc
	failures  chan error
	workers   sync.WaitGroup

	tunMu      sync.Mutex
	tun        tunnelHandle
	lastSwitch time.Time
	grace      time.Duration // switchGrace; tests shorten it

	// 测试替身：注册、建隧道与连通性探测
	loadProfile func(ctx context.Context, opts cfwarp.Options) (*cfwarp.Profile, error)
	tunnelUp    func(ctx context.Context, cfg tunnel.Config) (tunnelHandle, error)
	probe       func(ctx context.Context) *health.Result
}

func NewSupervisor(cfg *config.Config) *Supervisor {
	ctx, cancel := context.WithCancel(context.Background())
	srv := proxy.NewServer(proxy.Options{
		ListenAddr:     cfg.ProxyListenAddr(),
		MaxConnections: cfg.MaxConnections,
		DialTimeout:    cfg.DialTimeout,
		DNSServers:     cfg.DNSServers,
		AllowPrivate:   cfg.AllowPrivateDestinations,
	})
	chk := health.NewChecker(cfg.LocalProxyAddr(), cfg.HealthcheckTimeout)
	s := &Supervisor{
		cfg:         cfg,
		proxy:       srv,
		checker:     chk,
		ctx:         ctx,
		cancel:      cancel,
		failures:    make(chan error, 4),
		grace:       switchGrace,
		loadProfile: cfwarp.Load,
		tunnelUp: func(ctx context.Context, c tunnel.Config) (tunnelHandle, error) {
			return tunnel.Up(ctx, c)
		},
	}
	s.probe = func(ctx context.Context) *health.Result { return s.checker.Check(ctx) }
	if !cfg.DisableHealthServer && cfg.HealthPort > 0 {
		s.healthSrv = health.NewServer(cfg.HealthListenAddr(), chk, srv.Stats(), s)
	}
	return s
}

// Status 实现 health.TunnelStatusProvider
func (s *Supervisor) Status() (tunnel.Status, error) {
	t := s.currentTunnel()
	if t == nil {
		return tunnel.Status{}, errors.New("tunnel not started")
	}
	return t.Status()
}

func (s *Supervisor) currentTunnel() tunnelHandle {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	return s.tun
}

func (s *Supervisor) fail(err error) {
	if s.ctx.Err() != nil {
		return
	}
	select {
	case s.failures <- err:
	default:
	}
	s.cancel()
}

// Run treats persistent loss of the WARP path as fatal. Docker restarts PID 1;
// health labels alone never restart a standalone container.
func (s *Supervisor) Run() (retErr error) {
	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	watcherDone := make(chan struct{})
	go func() {
		select {
		case <-sigCtx.Done():
			s.cancel()
		case <-watcherDone:
		}
	}()
	defer close(watcherDone)
	defer func() {
		s.shutdown()
		select {
		case err := <-s.failures:
			retErr = err
		default:
			if sigCtx.Err() != nil && retErr != nil && s.ctx.Err() != nil {
				retErr = nil
			}
		}
	}()
	if err := s.cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(s.cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("WARP data dir: %w", err)
	}

	startCtx, cancelStart := context.WithTimeout(s.ctx, s.cfg.ConnectTimeout)
	defer cancelStart()
	profile, err := s.loadProfile(startCtx, cfwarp.Options{
		Path:       s.cfg.RegistrationPath(),
		LicenseKey: s.cfg.LicenseKey,
	})
	if err != nil {
		return fmt.Errorf("WARP registration: %w", err)
	}
	slog.Info("WARP device loaded", "device", profile.DeviceID, "account", profile.AccountType)

	t, err := s.tunnelUp(startCtx, s.tunnelConfig(profile))
	if err != nil {
		return fmt.Errorf("WireGuard tunnel: %w", err)
	}
	s.tunMu.Lock()
	s.tun, s.lastSwitch = t, time.Now()
	s.tunMu.Unlock()

	if err := s.proxy.Listen(); err != nil {
		return err
	}
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		if err := s.proxy.Serve(); err != nil {
			s.fail(err)
		}
	}()
	if s.healthSrv != nil {
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			if err := s.healthSrv.Start(); err != nil {
				s.fail(err)
			}
		}()
	}

	res, err := s.waitReady(startCtx)
	if err != nil {
		return err
	}
	slog.Info("WARP proxy ready", "listen", s.cfg.ProxyListenAddr(), "warp", res.TraceWarp, "ip", res.ExternalIP, "colo", res.Colo)

	if s.cfg.RecoveryFailures > 0 {
		s.workers.Add(1)
		go func() { defer s.workers.Done(); s.monitorHealth() }()
	}
	<-s.ctx.Done()
	return nil
}

// tunnelConfig 把注册信息转换成隧道参数；WG_ENDPOINT 覆盖项优先于 Cloudflare 下发的接入点
func (s *Supervisor) tunnelConfig(p *cfwarp.Profile) tunnel.Config {
	seen := make(map[string]bool)
	var endpoints []string
	for _, ep := range append(append([]string{}, s.cfg.WGEndpoints...), p.Endpoints...) {
		if !seen[ep] {
			seen[ep] = true
			endpoints = append(endpoints, ep)
		}
	}
	addrs := []netip.Prefix{p.AddressV4}
	if p.AddressV6.IsValid() {
		addrs = append(addrs, p.AddressV6)
	}
	return tunnel.Config{
		Interface:     s.cfg.WGInterface,
		Mode:          tunnel.Mode(s.cfg.WGMode),
		PrivateKey:    p.PrivateKey,
		PeerPublicKey: p.PeerPublicKey,
		Endpoints:     endpoints,
		Addresses:     addrs,
		MTU:           s.cfg.WGMTU,
	}
}

// waitReady 等待首个成功的 WARP trace。当前接入点握手成功后才做 trace 探测；
// 在 switchGrace 内没有握手就换下一个接入点，不让每个被封的接入点都耗掉一次探测超时。
func (s *Supervisor) waitReady(ctx context.Context) (*health.Result, error) {
	last := &health.Result{Error: "no WireGuard handshake yet"}
	ticker := time.NewTicker(readyPollInterval)
	defer ticker.Stop()
	for {
		if s.handshakeSinceSwitch() {
			if last = s.probe(ctx); last.Healthy {
				return last, nil
			}
		} else {
			s.rotateIfStale("startup")
		}
		select {
		case <-ctx.Done():
			if s.ctx.Err() != nil {
				return nil, s.ctx.Err()
			}
			return nil, fmt.Errorf("WARP tunnel not usable within %s: %s", s.cfg.ConnectTimeout, last.Error)
		case <-ticker.C:
		}
	}
}

// handshakeSinceSwitch 报告当前接入点在建隧道或最近一次切换之后是否完成过握手
func (s *Supervisor) handshakeSinceSwitch() bool {
	s.tunMu.Lock()
	t, since := s.tun, s.lastSwitch
	s.tunMu.Unlock()
	if t == nil {
		return false
	}
	st, err := t.Status()
	return err == nil && st.LastHandshake.After(since)
}

// rotateIfStale 在没有近期握手时切换到下一个接入点；刚建好或刚切换的接入点先等首次握手
func (s *Supervisor) rotateIfStale(reason string) {
	s.tunMu.Lock()
	t, since := s.tun, time.Since(s.lastSwitch)
	s.tunMu.Unlock()
	if t == nil || since < s.grace {
		return
	}
	st, err := t.Status()
	if err == nil && !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < staleHandshake {
		return
	}
	next, err := t.RotateEndpoint()
	if err != nil {
		slog.Warn("WireGuard endpoint rotation failed", "reason", reason, "error", err)
		return
	}
	s.tunMu.Lock()
	s.lastSwitch = time.Now()
	s.tunMu.Unlock()
	slog.Warn("WireGuard handshake stale, rotated endpoint", "reason", reason, "from", st.Endpoint, "to", next)
}

// Count consecutive failures; rotate stale endpoints first and exit only when the
// tunnel stays unusable so Docker can restart the container.
func (s *Supervisor) monitorHealth() {
	timer := time.NewTimer(s.cfg.RecoveryGrace)
	defer timer.Stop()
	select {
	case <-s.ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(s.cfg.RecoveryInterval)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			res := s.probe(s.ctx)
			if res.Healthy {
				failures = 0
				continue
			}
			if s.ctx.Err() != nil {
				return
			}
			failures++
			slog.Warn("WARP health probe failed", "consecutive", failures, "error", res.Error)
			if failures >= s.cfg.RecoveryFailures {
				s.fail(fmt.Errorf("WARP unavailable for %d consecutive probes", failures))
				return
			}
			s.rotateIfStale("health probe")
		}
	}
}

func (s *Supervisor) shutdown() {
	s.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if s.healthSrv != nil {
		_ = s.healthSrv.Stop(ctx)
	}
	cancel()
	_ = s.proxy.Stop()
	s.workers.Wait()
	s.tunMu.Lock()
	t := s.tun
	s.tun = nil
	s.tunMu.Unlock()
	if t != nil {
		if err := t.Close(); err != nil {
			slog.Warn("WireGuard tunnel teardown failed", "error", err)
		}
	}
}

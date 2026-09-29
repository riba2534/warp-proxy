package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/riba2534/warp-proxy/pkg/config"
	"github.com/riba2534/warp-proxy/pkg/forwarder"
	"github.com/riba2534/warp-proxy/pkg/health"
	"github.com/riba2534/warp-proxy/pkg/warp"
)

type child struct {
	cmd  *exec.Cmd
	done chan struct{}
}

type Supervisor struct {
	cfg       *config.Config
	warpCtrl  *warp.Controller
	forwarder *forwarder.Server
	healthSrv *health.Server
	checker   *health.Checker
	ctx       context.Context
	cancel    context.CancelFunc
	failures  chan error
	children  []*child
	workers   sync.WaitGroup
	ownsDBus  bool
}

func NewSupervisor(cfg *config.Config) *Supervisor {
	ctx, cancel := context.WithCancel(context.Background())
	ctrl := warp.NewController(cfg)
	fwd := forwarder.NewServer(cfg.ProxyListenAddr(), cfg.WarpSvcTargetAddr())
	fwd.SetConnectionLimit(cfg.MaxConnections)
	chk := health.NewChecker(cfg.LocalProxyAddr(), cfg.HealthcheckTimeout)
	s := &Supervisor{cfg: cfg, warpCtrl: ctrl, forwarder: fwd, checker: chk, ctx: ctx, cancel: cancel, failures: make(chan error, 4)}
	if !cfg.DisableHealthServer && cfg.HealthPort > 0 {
		s.healthSrv = health.NewServer(cfg.HealthListenAddr(), chk, fwd.GetStats(), ctrl)
	}
	return s
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

// Run treats child exit and persistent loss of the WARP path as fatal. Docker
// restarts PID 1; health labels alone never restart a standalone container.
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
	if err := s.setupEnvironment(); err != nil {
		return err
	}
	if err := s.startDBus(); err != nil {
		return err
	}
	if err := s.startWarpSvc(); err != nil {
		return err
	}
	if err := s.warpCtrl.WaitForDaemon(s.ctx, 15*time.Second); err != nil {
		return fmt.Errorf("WARP daemon readiness: %w", err)
	}
	if err := s.warpCtrl.SetupAndConnect(s.ctx); err != nil {
		return fmt.Errorf("WARP initialization: %w", err)
	}
	if err := s.forwarder.Listen(); err != nil {
		return err
	}
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		if err := s.forwarder.Serve(); err != nil {
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
	if s.cfg.RecoveryFailures > 0 {
		s.workers.Add(1)
		go func() { defer s.workers.Done(); s.monitorHealth() }()
	}
	slog.Info("WARP proxy ready", "listen", s.cfg.ProxyListenAddr())
	<-s.ctx.Done()
	return nil
}

func (s *Supervisor) startChild(name string, cmd *exec.Cmd) error {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	c := &child{cmd: cmd, done: make(chan struct{})}
	s.children = append(s.children, c)
	go func() {
		err := cmd.Wait()
		close(c.done)
		s.fail(fmt.Errorf("%s exited unexpectedly: %v", name, err))
	}()
	return nil
}

func (s *Supervisor) setupEnvironment() error {
	for _, d := range []string{"/var/run/dbus", "/var/lib/cloudflare-warp", "/var/run/cloudflare-warp"} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "dbus-uuidgen", "--ensure").Run(); err != nil {
		return fmt.Errorf("dbus uuid: %w", err)
	}
	return nil
}

func socketAlive(path string) bool {
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (s *Supervisor) startDBus() error {
	path := "/var/run/dbus/system_bus_socket"
	if socketAlive(path) {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove("/var/run/dbus/pid")
	if err := s.startChild("dbus-daemon", exec.Command("dbus-daemon", "--system", "--nofork", "--nopidfile")); err != nil {
		return err
	}
	s.ownsDBus = true
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("D-Bus readiness: %w", ctx.Err())
		case <-ticker.C:
			if socketAlive(path) {
				return nil
			}
		}
	}
}

func (s *Supervisor) startWarpSvc() error {
	return s.startChild("warp-svc", exec.Command("warp-svc"))
}

// Count consecutive failures, allowing the official daemon to reconnect first.
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
			res := s.checker.Check(s.ctx)
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
	_ = s.forwarder.Stop()
	// Terminating warp-svc closes its tunnel; an extra disconnect CLI could block
	// behind the same unresponsive daemon we are trying to recover.
	for i := len(s.children) - 1; i >= 0; i-- {
		terminateChild(s.children[i], 2*time.Second)
	}
	s.workers.Wait()
	if s.ownsDBus {
		_ = os.Remove(filepath.Join("/var/run/dbus", "system_bus_socket"))
	}
}

func terminateChild(c *child, timeout time.Duration) {
	select {
	case <-c.done:
		return
	default:
	}
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-c.done:
		return
	case <-timer.C:
		_ = c.cmd.Process.Kill()
	}
	<-c.done
}

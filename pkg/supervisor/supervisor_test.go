package supervisor

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/riba2534/warp-proxy/pkg/config"
	"github.com/riba2534/warp-proxy/pkg/health"
)

func TestChildExitCancelsSupervisor(t *testing.T) {
	s := NewSupervisor(config.LoadFromEnv())
	defer s.shutdown()
	if err := s.startChild("test-daemon", exec.Command("sh", "-c", "exit 7")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("child exit not detected")
	}
	select {
	case err := <-s.failures:
		if !strings.Contains(err.Error(), "test-daemon") {
			t.Fatal(err)
		}
	default:
		t.Fatal("missing fatal error")
	}
	select {
	case <-s.children[0].done:
	default:
		t.Fatal("child not reaped")
	}
}

func TestShutdownTerminatesAndReapsChild(t *testing.T) {
	s := NewSupervisor(config.LoadFromEnv())
	if err := s.startChild("test-daemon", exec.Command("sleep", "30")); err != nil {
		t.Fatal(err)
	}
	s.shutdown()
	select {
	case <-s.children[0].done:
	default:
		t.Fatal("child not reaped")
	}
	select {
	case err := <-s.failures:
		t.Fatalf("normal stop counted as failure: %v", err)
	default:
	}
}

func TestRecoveryThreshold(t *testing.T) {
	cfg := config.LoadFromEnv()
	cfg.RecoveryGrace = 0
	cfg.RecoveryInterval = 10 * time.Millisecond
	cfg.RecoveryFailures = 2
	s := NewSupervisor(cfg)
	defer s.shutdown()
	s.checker = health.NewChecker("127.0.0.1:1", 10*time.Millisecond)
	go s.monitorHealth()
	select {
	case err := <-s.failures:
		if !strings.Contains(err.Error(), "2 consecutive") {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("persistent failure did not trigger recovery")
	}
}

func TestMonitorHonorsCancellation(t *testing.T) {
	cfg := config.LoadFromEnv()
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

func TestStartMissingChild(t *testing.T) {
	s := NewSupervisor(config.LoadFromEnv())
	defer s.shutdown()
	if err := s.startChild("missing", exec.CommandContext(context.Background(), "/nonexistent/warp-proxy-test")); err == nil {
		t.Fatal("expected missing binary error")
	}
}

func TestRunReturnsStartupError(t *testing.T) {
	cfg := config.LoadFromEnv()
	cfg.ProxyPort = -1
	s := NewSupervisor(cfg)
	if err := s.Run(); err == nil || !strings.Contains(err.Error(), "WARP_PROXY_PORT") {
		t.Fatalf("startup error swallowed by shutdown: %v", err)
	}
}

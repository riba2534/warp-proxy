package warp

import (
	"context"
	"github.com/riba2534/warp-proxy/pkg/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConnectTimeoutBoundsCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warp-cli")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 10\n"), 0700); err != nil {
		t.Fatal(err)
	}
	c := NewController(&config.Config{})
	c.executor = &CLIExecutor{cliPath: path}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.WaitForConnected(ctx, 1100*time.Millisecond) }()
	select {
	case <-done:
	case <-time.After(1800 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("CONNECT_TIMEOUT=1.1s did not interrupt hung warp-cli after 1.8s")
	}
}
func TestLicenseRedaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warp-cli")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'license rejected' >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	e := &CLIExecutor{cliPath: path}
	_, err := e.RegistrationLicense(context.Background(), "AUDIT-FAKE-LICENSE-NOT-A-REAL-SECRET")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "AUDIT-FAKE-LICENSE-NOT-A-REAL-SECRET") {
		t.Fatal("license value included in error string consumed by log.Printf")
	}
}

func TestRegistrationTransientErrorDoesNotRegisterNewDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warp-cli")
	script := "#!/bin/sh\nif [ \"$2 $3\" = \"registration show\" ]; then echo 'IPC temporarily unavailable' >&2; exit 1; fi\necho 'unexpected mutation' >&2\nexit 9\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.LoadFromEnv()
	c := NewController(cfg)
	c.executor = &CLIExecutor{cliPath: path}
	err := c.SetupAndConnect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cannot verify registration") {
		t.Fatalf("transient error must stop before any registration mutation: %v", err)
	}
}

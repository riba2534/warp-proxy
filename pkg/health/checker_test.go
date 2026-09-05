package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/riba2534/warp-proxy/pkg/forwarder"
)

type mockWarpStatusProvider struct {
	status string
}

func (m *mockWarpStatusProvider) GetStatus(ctx context.Context) (string, error) {
	return m.status, nil
}

func TestHealthHTTPServer(t *testing.T) {
	stats := forwarder.NewStats()
	stats.IncActiveConns()
	stats.AddBytesClientToUp(1024)
	stats.AddBytesUpToClient(2048)

	provider := &mockWarpStatusProvider{status: "Status update: Connected. Reason: None."}

	// 创建一个指向不存在端口的 checker，验证请求不健康时的处理
	checker := NewChecker("127.0.0.1:59999", 500*time.Millisecond)
	srv := NewServer("127.0.0.1:0", checker, stats, provider)

	// 测试 /healthz 处理器
	reqHealthz := httptest.NewRequest("GET", "/healthz", nil)
	wHealthz := httptest.NewRecorder()
	srv.handleHealthz(wHealthz, reqHealthz)

	if wHealthz.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for failed proxy check, got %d", wHealthz.Code)
	}

	// 测试 /status 处理器
	reqStatus := httptest.NewRequest("GET", "/status", nil)
	wStatus := httptest.NewRecorder()
	srv.handleStatus(wStatus, reqStatus)

	var resp StatusResponse
	if err := json.NewDecoder(wStatus.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode json response: %v", err)
	}

	if resp.Status != "unhealthy" {
		t.Errorf("expected status unhealthy, got %s", resp.Status)
	}
	if !strings.Contains(resp.WarpStatus, "Connected") {
		t.Errorf("expected warp status to contain Connected, got %s", resp.WarpStatus)
	}
	if resp.ForwarderStats.ActiveConns != 1 {
		t.Errorf("expected activeConns=1, got %d", resp.ForwarderStats.ActiveConns)
	}
	if resp.ForwarderStats.BytesClientToUp != 1024 {
		t.Errorf("expected BytesClientToUp=1024, got %d", resp.ForwarderStats.BytesClientToUp)
	}
	if resp.ForwarderStats.BytesUpToClient != 2048 {
		t.Errorf("expected BytesUpToClient=2048, got %d", resp.ForwarderStats.BytesUpToClient)
	}
}

func TestCheckRawTCP(t *testing.T) {
	// 启动一个常规 TCP 监听器
	testSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer testSrv.Close()

	addr := testSrv.Listener.Addr().String()
	if err := CheckRawTCP(addr, 1*time.Second); err != nil {
		t.Errorf("expected CheckRawTCP to succeed for %s, got %v", addr, err)
	}

	// 测试未监听的端口
	if err := CheckRawTCP("127.0.0.1:59998", 200*time.Millisecond); err == nil {
		t.Errorf("expected CheckRawTCP to fail on closed port, but it succeeded")
	}
}

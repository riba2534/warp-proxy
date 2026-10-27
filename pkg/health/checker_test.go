package health

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/riba2534/warp-proxy/pkg/proxy"
	"github.com/riba2534/warp-proxy/pkg/tunnel"
)

type mockTunnelStatus struct {
	status tunnel.Status
	err    error
}

func (m *mockTunnelStatus) Status() (tunnel.Status, error) {
	return m.status, m.err
}

func TestHealthHTTPServer(t *testing.T) {
	stats := proxy.NewServer(proxy.Options{ListenAddr: "127.0.0.1:0"}).Stats()
	provider := &mockTunnelStatus{status: tunnel.Status{
		Mode:          tunnel.ModeKernel,
		Interface:     "wg0",
		Endpoint:      "162.159.192.1:2408",
		LastHandshake: time.Now().Add(-12 * time.Second),
		RxBytes:       4096,
	}}

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

	body := wStatus.Body.String()
	var resp StatusResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("failed to decode json response: %v", err)
	}

	if resp.Status != "unhealthy" {
		t.Errorf("expected status unhealthy, got %s", resp.Status)
	}
	if !strings.HasPrefix(resp.WarpStatus, "Connected (kernel WireGuard via 162.159.192.1:2408") {
		t.Errorf("unexpected warp status %q", resp.WarpStatus)
	}
	if resp.Tunnel == nil || resp.Tunnel.Endpoint != "162.159.192.1:2408" || resp.Tunnel.RxBytes != 4096 {
		t.Errorf("tunnel status not reported: %+v", resp.Tunnel)
	}
	// v1 监控面板依赖的字段名保持不变
	for _, key := range []string{`"forwarder_stats"`, `"active_connections"`, `"bytes_received"`, `"warp_status"`} {
		if !strings.Contains(body, key) {
			t.Errorf("status JSON lost %s: %s", key, body)
		}
	}
}

func TestDescribeTunnel(t *testing.T) {
	now := time.Now()
	if got := describeTunnel(tunnel.Status{}, errors.New("link down"), now); got != "Disconnected: link down" {
		t.Errorf("got %q", got)
	}
	st := tunnel.Status{Mode: tunnel.ModeUserspace, Endpoint: "162.159.193.10:500"}
	if got := describeTunnel(st, nil, now); !strings.Contains(got, "no handshake yet") {
		t.Errorf("got %q", got)
	}
	st.LastHandshake = now.Add(-90 * time.Second)
	if got := describeTunnel(st, nil, now); got != "Connected (userspace WireGuard via 162.159.193.10:500, last handshake 1m30s ago)" {
		t.Errorf("got %q", got)
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

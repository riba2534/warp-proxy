package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/riba2534/warp-proxy/pkg/forwarder"
)

// WarpStatusProvider 提供当前 WARP 状态文本的接口
type WarpStatusProvider interface {
	GetStatus(ctx context.Context) (string, error)
}

// Server 提供健康检查与运行状态 HTTP API
type Server struct {
	listenAddr     string
	checker        *Checker
	stats          *forwarder.Stats
	statusProvider WarpStatusProvider
	httpServer     *http.Server
}

// StatusResponse 是 /status 端点返回的 JSON 结构体
type StatusResponse struct {
	Status         string             `json:"status"` // healthy 或 unhealthy
	Timestamp      string             `json:"timestamp"`
	WarpStatus     string             `json:"warp_status"`
	TraceResult    *Result            `json:"trace_result,omitempty"`
	ForwarderStats forwarder.Snapshot `json:"forwarder_stats"`
}

// NewServer 创建 HTTP 健康检查服务
func NewServer(listenAddr string, checker *Checker, stats *forwarder.Stats, statusProvider WarpStatusProvider) *Server {
	return &Server{
		listenAddr:     listenAddr,
		checker:        checker,
		stats:          stats,
		statusProvider: statusProvider,
	}
}

// Start 启动 HTTP 健康检查服务
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/status", s.handleStatus)

	s.httpServer = &http.Server{
		Addr:         s.listenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	log.Printf("[Health] Health check HTTP server listening on %s", s.listenAddr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("health check HTTP server failed: %w", err)
	}
	return nil
}

// handleHealthz 处理 K8s/Docker 探针的 /healthz 请求
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	res := s.checker.Check(ctx)
	if res.Healthy {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, "Unhealthy: %s\n", res.Error)
	}
}

// handleStatus 返回详细运行指标与 trace 信息
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	traceRes := s.checker.Check(ctx)

	warpStatus := "Unknown"
	if s.statusProvider != nil {
		if st, err := s.statusProvider.GetStatus(ctx); err == nil {
			warpStatus = st
		}
	}

	statusText := "unhealthy"
	if traceRes.Healthy {
		statusText = "healthy"
	}

	resp := StatusResponse{
		Status:         statusText,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		WarpStatus:     warpStatus,
		TraceResult:    traceRes,
		ForwarderStats: s.stats.GetSnapshot(),
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if traceRes.Healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// Stop 优雅停止 HTTP 服务
func (s *Server) Stop(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

package supervisor

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/riba2534/warp-proxy/pkg/config"
	"github.com/riba2534/warp-proxy/pkg/forwarder"
	"github.com/riba2534/warp-proxy/pkg/health"
	"github.com/riba2534/warp-proxy/pkg/warp"
)

// Supervisor 作为容器的 PID 1 主管进程，负责管理 D-Bus、warp-svc 守护进程、
// 初始化 WARP 连接、启动网络转发及处理 OS 信号实现优雅停机。
type Supervisor struct {
	cfg        *config.Config
	warpCtrl   *warp.Controller
	forwarder  *forwarder.Server
	healthSrv  *health.Server
	checker    *health.Checker

	dbusCmd    *exec.Cmd
	warpSvcCmd *exec.Cmd

	ctx        context.Context
	cancel     context.CancelFunc
}

// NewSupervisor 创建进程监督器
func NewSupervisor(cfg *config.Config) *Supervisor {
	ctx, cancel := context.WithCancel(context.Background())
	warpCtrl := warp.NewController(cfg)
	fwd := forwarder.NewServer(cfg.ProxyListenAddr(), cfg.WarpSvcTargetAddr())
	chk := health.NewChecker(cfg.LocalProxyAddr(), cfg.HealthcheckTimeout)

	var hSrv *health.Server
	if !cfg.DisableHealthServer && cfg.HealthPort > 0 {
		hSrv = health.NewServer(cfg.HealthListenAddr(), chk, fwd.GetStats(), warpCtrl)
	}

	return &Supervisor{
		cfg:       cfg,
		warpCtrl:  warpCtrl,
		forwarder: fwd,
		healthSrv: hSrv,
		checker:   chk,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Run 启动所有子系统并阻塞等待退出信号
func (s *Supervisor) Run() error {
	// 注册信号监听
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	// 1. 初始化系统依赖环境（D-Bus 等）
	if err := s.setupEnvironment(); err != nil {
		return fmt.Errorf("failed to setup environment: %w", err)
	}

	// 2. 启动 D-Bus 守护进程
	if err := s.startDBus(); err != nil {
		return fmt.Errorf("failed to start D-Bus daemon: %w", err)
	}

	// 3. 启动官方 warp-svc 守护进程
	if err := s.startWarpSvc(); err != nil {
		return fmt.Errorf("failed to start warp-svc: %w", err)
	}

	// 4. 等待 warp-svc 就绪
	if err := s.warpCtrl.WaitForDaemon(s.ctx, 15*time.Second); err != nil {
		return fmt.Errorf("warp-svc failed to become ready: %w", err)
	}

	// 5. 初始化配置并连接 WARP 网络
	if err := s.warpCtrl.SetupAndConnect(s.ctx); err != nil {
		return fmt.Errorf("failed to setup and connect WARP: %w", err)
	}

	// 6. 启动 L4 透明端口转发服务
	if err := s.forwarder.Listen(); err != nil {
		return fmt.Errorf("failed to bind forwarder listening port %s: %w", s.cfg.ProxyListenAddr(), err)
	}

	fwdErrChan := make(chan error, 1)
	go func() {
		fwdErrChan <- s.forwarder.Serve()
	}()

	// 7. 启动 HTTP 健康检查服务（若未禁用）
	if s.healthSrv != nil {
		go func() {
			if err := s.healthSrv.Start(); err != nil {
				log.Printf("[Supervisor] Health check server error: %v", err)
			}
		}()
	}

	log.Printf("[Supervisor] warp-proxy is fully operational! SOCKS5 proxy listening on %s", s.cfg.ProxyListenAddr())

	// 等待退出信号或转发器致命错误
	select {
	case sig := <-sigChan:
		log.Printf("[Supervisor] Received signal %v (%s), initiating graceful shutdown...", sig, sig.String())
	case err := <-fwdErrChan:
		log.Printf("[Supervisor] Forwarder encountered fatal error: %v", err)
	case <-s.ctx.Done():
		log.Println("[Supervisor] Context cancelled, shutting down...")
	}

	s.shutdown()
	return nil
}

// setupEnvironment 准备运行所需的目录与权限
func (s *Supervisor) setupEnvironment() error {
	dirs := []string{
		"/var/run/dbus",
		"/var/lib/cloudflare-warp",
		"/var/run/cloudflare-warp",
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil && !os.IsExist(err) {
			log.Printf("[Supervisor] Warning: failed to create directory %s: %v", d, err)
		}
	}

	// 确保生成 dbus uuid
	if _, err := exec.LookPath("dbus-uuidgen"); err == nil {
		_ = exec.Command("dbus-uuidgen", "--ensure").Run()
	}

	return nil
}

// startDBus 启动系统级 D-Bus 守护进程
func (s *Supervisor) startDBus() error {
	dbusSocket := "/var/run/dbus/system_bus_socket"
	if fi, err := os.Stat(dbusSocket); err == nil && !fi.IsDir() {
		log.Println("[Supervisor] D-Bus system bus socket already exists, skipping start")
		return nil
	}

	// 清理陈旧的 pid 文件
	_ = os.Remove("/var/run/dbus/pid")

	log.Println("[Supervisor] Starting D-Bus system daemon...")
	cmd := exec.Command("dbus-daemon", "--system", "--nofork", "--nopidfile")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start dbus-daemon: %w", err)
	}
	s.dbusCmd = cmd

	// 等待 socket 创建
	time.Sleep(500 * time.Millisecond)
	log.Println("[Supervisor] D-Bus daemon started successfully")
	return nil
}

// startWarpSvc 启动 Cloudflare WARP 后台守护进程
func (s *Supervisor) startWarpSvc() error {
	warpSvcPath, err := exec.LookPath("warp-svc")
	if err != nil {
		warpSvcPath = "/usr/bin/warp-svc"
	}

	log.Printf("[Supervisor] Starting warp-svc daemon from %s...", warpSvcPath)
	cmd := exec.Command(warpSvcPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start warp-svc: %w", err)
	}
	s.warpSvcCmd = cmd

	log.Println("[Supervisor] warp-svc daemon process started")
	return nil
}

// shutdown 执行完整的优雅停机流程
func (s *Supervisor) shutdown() {
	s.cancel()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. 关闭 HTTP 健康检查服务
	if s.healthSrv != nil {
		log.Println("[Supervisor] Stopping health check HTTP server...")
		_ = s.healthSrv.Stop(shutdownCtx)
	}

	// 2. 停止 L4 转发器
	log.Println("[Supervisor] Stopping L4 forwarder...")
	_ = s.forwarder.Stop()

	// 3. 断开 WARP 连接
	log.Println("[Supervisor] Disconnecting WARP...")
	_ = s.warpCtrl.Disconnect(shutdownCtx)

	// 4. 终止 warp-svc 进程
	if s.warpSvcCmd != nil && s.warpSvcCmd.Process != nil {
		log.Println("[Supervisor] Terminating warp-svc...")
		terminateProcess(s.warpSvcCmd.Process, 3*time.Second)
	}

	// 5. 终止 D-Bus 进程
	if s.dbusCmd != nil && s.dbusCmd.Process != nil {
		log.Println("[Supervisor] Terminating dbus-daemon...")
		terminateProcess(s.dbusCmd.Process, 2*time.Second)
	}

	// 清理临时套接字
	_ = os.Remove(filepath.Join("/var/run/dbus", "system_bus_socket"))

	log.Println("[Supervisor] All services stopped gracefully. Goodbye!")
}

// terminateProcess 发送 SIGTERM 并等待进程退出，超时则发送 SIGKILL
func terminateProcess(proc *os.Process, timeout time.Duration) {
	if proc == nil {
		return
	}

	// 先尝试 SIGTERM
	_ = proc.Signal(syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		_, _ = proc.Wait()
		close(done)
	}()

	select {
	case <-done:
		return
	case <-time.After(timeout):
		log.Printf("[Supervisor] Process %d did not terminate in time, sending SIGKILL...", proc.Pid)
		_ = proc.Kill()
		<-done
	}
}

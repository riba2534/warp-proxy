package warp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"time"

	"github.com/riba2534/warp-proxy/pkg/config"
)

// Controller 负责管理 Cloudflare WARP 客户端的生命周期与初始化配置
type Controller struct {
	cfg      *config.Config
	executor *CLIExecutor
}

// NewController 创建 WARP 控制器实例
func NewController(cfg *config.Config) *Controller {
	return &Controller{
		cfg:      cfg,
		executor: NewCLIExecutor(),
	}
}

// IsRegistered 检查本地是否已有有效的 WARP 注册信息
func (c *Controller) IsRegistered(ctx context.Context) bool {
	registered, err := c.registrationState(ctx)
	return err == nil && registered
}

func (c *Controller) registrationState(ctx context.Context) (bool, error) {
	out, err := c.executor.RegistrationShow(ctx)
	lower := strings.ToLower(out)
	if strings.Contains(lower, "registration missing") || strings.Contains(lower, "missing registration") || strings.Contains(lower, "not registered") || strings.Contains(lower, "no registration") {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot verify registration: %w", err)
	}
	if strings.TrimSpace(out) == "" || strings.Contains(lower, "error") {
		return false, fmt.Errorf("unexpected registration response")
	}
	return true, nil
}

// WaitForDaemon 等待 warp-svc 后台守护进程准备就绪并可响应 CLI 请求
func (c *Controller) WaitForDaemon(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	log.Println("[WARP] Waiting for warp-svc daemon to become ready...")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if c.executor.Ping(ctx) {
				log.Println("[WARP] warp-svc daemon is ready and responding")
				return nil
			}
			if time.Now().After(deadline) {
				return errors.New("timeout waiting for warp-svc daemon to respond")
			}
		}
	}
}

// SetupAndConnect 执行完整的 WARP 初始化与连接流程
func (c *Controller) SetupAndConnect(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.ConnectTimeout)
	defer cancel()
	// 1. 确保已注册账号
	registered, registrationErr := c.registrationState(ctx)
	if registrationErr != nil {
		return registrationErr
	}
	if !registered {
		log.Println("[WARP] No existing registration found, registering new WARP account...")
		out, err := c.executor.RegistrationNew(ctx)
		if err != nil {
			return fmt.Errorf("failed to register new WARP account: %w (output: %s)", err, out)
		}
		log.Println("[WARP] Successfully registered new WARP account")
	} else {
		log.Println("[WARP] Existing WARP registration found, reusing credentials")
	}

	// 2. 如果配置了 WARP+ License Key，尝试绑定
	if c.cfg.LicenseKey != "" {
		log.Println("[WARP] Applying WARP+ License Key...")
		out, err := c.executor.RegistrationLicense(ctx, c.cfg.LicenseKey)
		if err != nil {
			slog.Warn("Failed to apply WARP license", "error", err, "output", out)
		} else {
			log.Println("[WARP] License Key applied successfully")
		}
	}

	// 3. 配置运行模式为 proxy（SOCKS5 代理模式）
	log.Println("[WARP] Setting operation mode to 'proxy'...")
	if out, err := c.executor.SetModeProxy(ctx); err != nil {
		return fmt.Errorf("failed to set mode to proxy: %w (output: %s)", err, out)
	}

	// 4. 设置内部 SOCKS5 代理端口
	log.Printf("[WARP] Setting proxy listening port to %d...", c.cfg.WarpSvcPort)
	if out, err := c.executor.SetProxyPort(ctx, c.cfg.WarpSvcPort); err != nil {
		return fmt.Errorf("failed to set proxy port to %d: %w (output: %s)", c.cfg.WarpSvcPort, err, out)
	}

	// 5. 发起连接
	log.Println("[WARP] Connecting to Cloudflare WARP network...")
	if out, err := c.executor.Connect(ctx); err != nil {
		slog.Warn("WARP connect command failed", "error", err, "output", out)
	}

	// 6. 轮询等待连接成功
	if err := c.WaitForConnected(ctx, c.cfg.ConnectTimeout); err != nil {
		return fmt.Errorf("failed to establish WARP connection: %w", err)
	}

	log.Println("[WARP] Cloudflare WARP connected successfully!")
	return nil
}

// WaitForConnected 持续轮询直到状态变为 Connected
func (c *Controller) WaitForConnected(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			status, err := c.GetStatus(ctx)
			if err == nil {
				// 检查是否已进入 Connected 状态
				if strings.Contains(status, "Connected") && !strings.Contains(status, "Connecting") {
					return nil
				}
				log.Printf("[WARP] Connection status: %s", status)
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout (%v) waiting for WARP connection (last status: %s)", timeout, status)
			}
		}
	}
}

// GetStatus 获取当前 WARP 状态
func (c *Controller) GetStatus(ctx context.Context) (string, error) {
	out, err := c.executor.Status(ctx)
	if err != nil {
		return "", err
	}

	// 整理状态输出为单行简洁文本
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Status update:") || strings.Contains(trimmed, "Status:") {
			return trimmed, nil
		}
	}

	if len(lines) > 0 {
		return strings.TrimSpace(lines[0]), nil
	}
	return "Unknown", nil
}

// Disconnect 断开 WARP 连接
func (c *Controller) Disconnect(ctx context.Context) error {
	_, err := c.executor.Disconnect(ctx)
	return err
}

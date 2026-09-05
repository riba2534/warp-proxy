package warp

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// CLIExecutor 封装调用 warp-cli 命令行工具的执行逻辑
type CLIExecutor struct {
	cliPath string
}

// NewCLIExecutor 创建命令行执行器
func NewCLIExecutor() *CLIExecutor {
	path, err := exec.LookPath("warp-cli")
	if err != nil {
		path = "/usr/bin/warp-cli"
	}
	return &CLIExecutor{cliPath: path}
}

// runWithFallback 尝试先执行 primary 命令，若遇到未知子命令/参数错误，自动回退执行 fallback 命令
func (e *CLIExecutor) runWithFallback(ctx context.Context, primaryArgs, fallbackArgs []string) (string, error) {
	out, err := e.run(ctx, primaryArgs...)
	if err == nil {
		return out, nil
	}

	// 检查是否是因为命令行语法不支持（版本差异）
	lowerOut := strings.ToLower(out)
	if isCommandSyntaxError(lowerOut) && len(fallbackArgs) > 0 {
		log.Printf("[WARP-CLI] Primary command 'warp-cli %s' failed (%v), trying fallback 'warp-cli %s'",
			strings.Join(primaryArgs, " "), err, strings.Join(fallbackArgs, " "))
		return e.run(ctx, fallbackArgs...)
	}

	return out, err
}

func isCommandSyntaxError(output string) bool {
	syntaxErrorKeywords := []string{
		"unrecognized subcommand",
		"invalid value",
		"unexpected argument",
		"unknown command",
		"error: unrecognized",
		"found argument",
		"which wasn't expected",
	}
	for _, kw := range syntaxErrorKeywords {
		if strings.Contains(output, kw) {
			return true
		}
	}
	return false
}

// run 执行单个 warp-cli 命令并捕获输出
func (e *CLIExecutor) run(ctx context.Context, args ...string) (string, error) {
	// 默认添加 --accept-tos
	fullArgs := []string{"--accept-tos"}
	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, e.cliPath, fullArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	combinedOutput := strings.TrimSpace(stdout.String() + "\n" + stderr.String())

	if err != nil {
		return combinedOutput, fmt.Errorf("command 'warp-cli %s' failed: %w (output: %s)",
			strings.Join(fullArgs, " "), err, combinedOutput)
	}

	return combinedOutput, nil
}

// Status 获取当前 warp-cli 状态
func (e *CLIExecutor) Status(ctx context.Context) (string, error) {
	return e.run(ctx, "status")
}

// RegistrationNew 注册新账号（兼容新版 registration new 与旧版 register）
func (e *CLIExecutor) RegistrationNew(ctx context.Context) (string, error) {
	return e.runWithFallback(ctx,
		[]string{"registration", "new"},
		[]string{"register"},
	)
}

// RegistrationLicense 设置 WARP+ License Key（兼容新版 registration license 与旧版 set-license）
func (e *CLIExecutor) RegistrationLicense(ctx context.Context, key string) (string, error) {
	return e.runWithFallback(ctx,
		[]string{"registration", "license", key},
		[]string{"set-license", key},
	)
}

// SetModeProxy 设置代理模式（兼容新版 mode proxy 与旧版 set-mode proxy）
func (e *CLIExecutor) SetModeProxy(ctx context.Context) (string, error) {
	return e.runWithFallback(ctx,
		[]string{"mode", "proxy"},
		[]string{"set-mode", "proxy"},
	)
}

// SetProxyPort 设置代理监听端口（兼容新版 proxy port 与旧版 set-proxy-port）
func (e *CLIExecutor) SetProxyPort(ctx context.Context, port int) (string, error) {
	portStr := fmt.Sprintf("%d", port)
	return e.runWithFallback(ctx,
		[]string{"proxy", "port", portStr},
		[]string{"set-proxy-port", portStr},
	)
}

// Connect 发起 WARP 连接
func (e *CLIExecutor) Connect(ctx context.Context) (string, error) {
	return e.run(ctx, "connect")
}

// Disconnect 断开 WARP 连接
func (e *CLIExecutor) Disconnect(ctx context.Context) (string, error) {
	return e.run(ctx, "disconnect")
}

// RegistrationShow 检查注册信息
func (e *CLIExecutor) RegistrationShow(ctx context.Context) (string, error) {
	return e.runWithFallback(ctx,
		[]string{"registration", "show"},
		[]string{"account"},
	)
}

// Ping 测试 warp-svc 是否正常响应
func (e *CLIExecutor) Ping(ctx context.Context) bool {
	ctxTimeout, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	out, err := e.Status(ctxTimeout)
	if err != nil {
		return false
	}
	// 如果输出了正常的状态信息，说明 daemon 正在响应
	return strings.Contains(out, "Status") || strings.Contains(out, "Success")
}

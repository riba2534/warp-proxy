package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/riba2534/warp-proxy/pkg/config"
	"github.com/riba2534/warp-proxy/pkg/health"
	"github.com/riba2534/warp-proxy/pkg/supervisor"
)

var (
	// Version 版本号，可在编译时通过 -ldflags "-X main.Version=..." 注入
	Version   = "1.0.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	var (
		flagHealthcheck bool
		flagVersion     bool
	)

	flag.BoolVar(&flagHealthcheck, "healthcheck", false, "以健康检查探针模式运行，通过 SOCKS5 代理测试连通性 (退出码 0: 正常, 1: 异常)")
	flag.BoolVar(&flagVersion, "v", false, "显示版本号")
	flag.BoolVar(&flagVersion, "version", false, "显示版本号")
	flag.Parse()

	// 兼容子命令形式: warp-proxy healthcheck
	if len(flag.Args()) > 0 && flag.Args()[0] == "healthcheck" {
		flagHealthcheck = true
	}

	if flagVersion {
		fmt.Printf("warp-proxy v%s (commit: %s, build: %s)\n", Version, GitCommit, BuildTime)
		os.Exit(0)
	}

	cfg := config.LoadFromEnv()

	// 健康检查模式
	if flagHealthcheck {
		runHealthcheck(cfg)
		return
	}

	// 主管服务模式 (PID 1)
	log.Printf("==================================================")
	log.Printf("  Starting warp-proxy v%s", Version)
	log.Printf("  Proxy Entry:   %s", cfg.ProxyListenAddr())
	log.Printf("  Internal Warp: %s", cfg.WarpSvcTargetAddr())
	if !cfg.DisableHealthServer && cfg.HealthPort > 0 {
		log.Printf("  Health Server: %s", cfg.HealthListenAddr())
	}
	log.Printf("==================================================")

	sup := supervisor.NewSupervisor(cfg)
	if err := sup.Run(); err != nil {
		log.Fatalf("[FATAL] Supervisor exited with error: %v", err)
	}
}

// runHealthcheck 执行快速健康探针，作为 Docker HEALTHCHECK 使用
func runHealthcheck(cfg *config.Config) {
	timeout := cfg.HealthcheckTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	chk := health.NewChecker(cfg.LocalProxyAddr(), timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	res := chk.Check(ctx)
	if res.Healthy {
		fmt.Printf("[HEALTHCHECK OK] warp=%s, ip=%s, colo=%s (duration: %v)\n",
			res.TraceWarp, res.ExternalIP, res.Colo, res.CheckDuration)
		os.Exit(0)
	} else {
		fmt.Fprintf(os.Stderr, "[HEALTHCHECK FAILED] %s (duration: %v)\n", res.Error, res.CheckDuration)
		os.Exit(1)
	}
}

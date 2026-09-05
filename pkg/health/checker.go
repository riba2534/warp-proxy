package health

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Result 包含健康检查的详细探测结果
type Result struct {
	Healthy       bool              `json:"healthy"`
	TraceWarp     string            `json:"trace_warp"` // on, plus, off, unknown
	ExternalIP    string            `json:"external_ip,omitempty"`
	Colo          string            `json:"colo,omitempty"`
	TraceRaw      map[string]string `json:"trace_details,omitempty"`
	Error         string            `json:"error,omitempty"`
	CheckDuration time.Duration     `json:"check_duration_ms"`
}

// Checker 执行通过 SOCKS5 代理的真实网络连通性探测
type Checker struct {
	proxyAddr string
	timeout   time.Duration

	cacheMu     sync.RWMutex
	cachedRes   *Result
	cachedTime  time.Time
	cacheMaxAge time.Duration
}

// NewChecker 创建健康检查器
func NewChecker(proxyAddr string, timeout time.Duration) *Checker {
	return &Checker{
		proxyAddr:   proxyAddr,
		timeout:     timeout,
		cacheMaxAge: 5 * time.Second, // 避免高频探测打爆上游
	}
}

// Check 执行健康检查，支持短时间结果缓存
func (c *Checker) Check(ctx context.Context) *Result {
	c.cacheMu.RLock()
	if c.cachedRes != nil && time.Since(c.cachedTime) < c.cacheMaxAge {
		res := *c.cachedRes
		c.cacheMu.RUnlock()
		return &res
	}
	c.cacheMu.RUnlock()

	res := c.doCheck(ctx)

	c.cacheMu.Lock()
	c.cachedRes = res
	c.cachedTime = time.Now()
	c.cacheMu.Unlock()

	return res
}

// doCheck 实际建立 SOCKS5 拨号并发起 HTTP 请求
func (c *Checker) doCheck(ctx context.Context) *Result {
	start := time.Now()
	res := &Result{
		TraceWarp: "unknown",
		TraceRaw:  make(map[string]string),
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// 1. 创建指向本地代理端口的 SOCKS5 拨号器
	dialer, err := proxy.SOCKS5("tcp", c.proxyAddr, nil, &net.Dialer{
		Timeout:   c.timeout,
		KeepAlive: 15 * time.Second,
	})
	if err != nil {
		res.Healthy = false
		res.Error = fmt.Sprintf("failed to create SOCKS5 dialer for %s: %v", c.proxyAddr, err)
		res.CheckDuration = time.Since(start)
		return res
	}

	// 探测候选列表：
	// 1. 优先使用 1.1.1.1 裸 IP（ATYP=0x01，直达 Cloudflare 顶级公共诊断节点，彻底避免 VPS 本地 DNS 污染与解析失败假阳性）
	// 2. 备用 1.0.0.1 裸 IP
	// 3. 备用 cloudflare.com 域名
	type probeTarget struct {
		url        string
		serverName string
	}

	targets := []probeTarget{
		{url: "https://1.1.1.1/cdn-cgi/trace", serverName: "cloudflare-dns.com"},
		{url: "https://1.0.0.1/cdn-cgi/trace", serverName: "cloudflare-dns.com"},
		{url: "https://cloudflare.com/cdn-cgi/trace", serverName: "cloudflare.com"},
	}

	var lastErr error
	for _, target := range targets {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
			TLSClientConfig: &tls.Config{
				ServerName: target.serverName,
			},
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   4 * time.Second,
			ResponseHeaderTimeout: 4 * time.Second,
		}

		client := &http.Client{
			Transport: tr,
			Timeout:   c.timeout,
		}

		req, err := http.NewRequestWithContext(ctxTimeout, "GET", target.url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "warp-proxy-healthcheck/1.0")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("HTTP status %d", resp.StatusCode)
			continue
		}

		// 解析 trace 响应
		scanner := bufio.NewScanner(io.LimitReader(resp.Body, 4096))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v := strings.TrimSpace(parts[1])
				res.TraceRaw[k] = v
				switch k {
				case "warp":
					res.TraceWarp = v
				case "ip":
					res.ExternalIP = v
				case "colo":
					res.Colo = v
				}
			}
		}
		_ = resp.Body.Close()

		if res.TraceWarp == "on" || res.TraceWarp == "plus" {
			res.Healthy = true
			res.CheckDuration = time.Since(start)
			return res
		}

		lastErr = fmt.Errorf("trace returned warp=%s", res.TraceWarp)
	}

	res.Healthy = false
	if lastErr != nil {
		res.Error = fmt.Sprintf("all trace probes failed, last error: %v", lastErr)
	} else {
		res.Error = "no trace probe succeeded"
	}
	res.CheckDuration = time.Since(start)
	return res
}

// CheckRawTCP 仅测试端口是否能正常建立 TCP 握手（用于非常快速的基础探针）
func CheckRawTCP(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// FormatURL 格式化带有代理的 URL
func FormatURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	return parsed.String()
}

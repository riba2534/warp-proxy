package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config 存储服务的所有配置项
type Config struct {
	// 外部监听地址与端口（SOCKS5 / SOCKS4 / HTTP CONNECT 共用入口）
	ProxyHost string
	ProxyPort int

	// Cloudflare WARP+ 许可证密钥（可选）
	LicenseKey string

	// WARP 注册信息所在目录（需持久化挂载）
	DataDir string

	// WireGuard 隧道配置
	WGMode      string
	WGInterface string
	WGMTU       int
	// WGEndpoints 覆盖 Cloudflare 下发的接入点（host:port，按顺序优先）
	WGEndpoints []string

	// 代理出站：域名解析服务器与私有地址策略
	DNSServers               []string
	AllowPrivateDestinations bool
	DialTimeout              time.Duration

	// HTTP 健康检查服务配置
	HealthHost          string
	HealthPort          int
	DisableHealthServer bool

	// 启动时等待 WARP 隧道首次探测成功的超时时间
	ConnectTimeout time.Duration

	// 健康检查探测超时时间
	HealthcheckTimeout time.Duration

	// 日志级别 (debug, info, warn, error)
	LogLevel         string
	RecoveryInterval time.Duration
	RecoveryFailures int
	RecoveryGrace    time.Duration
	MaxConnections   int
}

// DefaultDNSServers 经隧道使用 Cloudflare 公共 DNS，与官方 WARP 客户端一致
const DefaultDNSServers = "1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001"

// LoadFromEnv 从环境变量加载配置，提供合理的生产级默认值
func LoadFromEnv() *Config {
	cfg := &Config{
		MaxConnections:           getEnvInt("MAX_CONNECTIONS", 1024),
		ProxyHost:                getEnv("WARP_PROXY_HOST", "0.0.0.0"),
		ProxyPort:                getEnvInt("WARP_PROXY_PORT", 1080),
		LicenseKey:               getEnv("WARP_LICENSE_KEY", ""),
		DataDir:                  getEnv("WARP_DATA_DIR", "/var/lib/cloudflare-warp"),
		WGMode:                   strings.ToLower(getEnv("WG_MODE", "auto")),
		WGInterface:              getEnv("WG_INTERFACE", "wg0"),
		WGMTU:                    getEnvInt("WG_MTU", 1280),
		WGEndpoints:              getEnvList("WG_ENDPOINT", ""),
		DNSServers:               getEnvList("DNS_SERVERS", DefaultDNSServers),
		AllowPrivateDestinations: getEnvBool("ALLOW_PRIVATE_DESTINATIONS", false),
		DialTimeout:              getEnvDuration("DIAL_TIMEOUT", 10*time.Second),
		HealthHost:               getEnv("HEALTH_HOST", "0.0.0.0"),
		HealthPort:               getEnvInt("HEALTH_PORT", 8080),
		DisableHealthServer:      getEnvBool("DISABLE_HEALTH_SERVER", false),
		ConnectTimeout:           getEnvDuration("CONNECT_TIMEOUT", 60*time.Second),
		HealthcheckTimeout:       getEnvDuration("HEALTHCHECK_TIMEOUT", 4*time.Second),
		LogLevel:                 getEnv("LOG_LEVEL", "info"),
		RecoveryInterval:         getEnvDuration("RECOVERY_INTERVAL", 30*time.Second),
		RecoveryFailures:         getEnvInt("RECOVERY_FAILURES", 3),
		RecoveryGrace:            getEnvDuration("RECOVERY_GRACE", 60*time.Second),
	}

	// 兼容 PORT 环境变量（若未明确设置 WARP_PROXY_PORT）
	if _, ok := os.LookupEnv("WARP_PROXY_PORT"); !ok {
		if port := getEnvInt("PORT", 0); port > 0 {
			cfg.ProxyPort = port
		}
	}

	return cfg
}

// ProxyListenAddr 返回外部监听的完整 TCP 地址
func (c *Config) ProxyListenAddr() string {
	return net.JoinHostPort(c.ProxyHost, strconv.Itoa(c.ProxyPort))
}

// HealthListenAddr 返回健康检查 HTTP 服务的监听地址
func (c *Config) HealthListenAddr() string {
	return net.JoinHostPort(c.HealthHost, strconv.Itoa(c.HealthPort))
}

// LocalProxyAddr 返回用于本地健康检查的代理地址
func (c *Config) LocalProxyAddr() string {
	host := c.ProxyHost
	if host == "0.0.0.0" || host == "" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(c.ProxyPort))
}

// RegistrationPath 返回 WireGuard 设备注册文件路径
func (c *Config) RegistrationPath() string {
	return filepath.Join(c.DataDir, "wireguard-account.json")
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return defaultVal
}

// getEnvList 解析逗号分隔的列表，忽略空项
func getEnvList(key, defaultVal string) []string {
	var out []string
	for _, item := range strings.Split(getEnv(key, defaultVal), ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func getEnvInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if boolVal, err := strconv.ParseBool(val); err == nil {
			return boolVal
		}
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}

func (c *Config) Validate() error {
	if c.MaxConnections < 1 {
		return fmt.Errorf("MAX_CONNECTIONS must be positive")
	}
	if c.ProxyPort < 1 || c.ProxyPort > 65535 {
		return fmt.Errorf("WARP_PROXY_PORT must be between 1 and 65535")
	}
	if c.HealthPort < 0 || c.HealthPort > 65535 {
		return fmt.Errorf("HEALTH_PORT must be between 0 and 65535")
	}
	if c.ConnectTimeout <= 0 || c.HealthcheckTimeout <= 0 || c.DialTimeout <= 0 {
		return fmt.Errorf("timeouts must be positive")
	}
	if c.RecoveryInterval <= 0 || c.RecoveryFailures < 0 || c.RecoveryGrace < 0 {
		return fmt.Errorf("invalid recovery configuration")
	}
	switch c.WGMode {
	case "auto", "kernel", "userspace":
	default:
		return fmt.Errorf("WG_MODE must be auto, kernel or userspace")
	}
	if c.WGInterface == "" || len(c.WGInterface) > 15 {
		return fmt.Errorf("WG_INTERFACE must be 1-15 characters")
	}
	if c.WGMTU < 1280 || c.WGMTU > 1500 {
		return fmt.Errorf("WG_MTU must be between 1280 and 1500")
	}
	for _, ep := range c.WGEndpoints {
		if _, port, err := net.SplitHostPort(ep); err != nil || port == "" {
			return fmt.Errorf("WG_ENDPOINT entries must be host:port")
		}
	}
	for _, s := range c.DNSServers {
		if _, err := netip.ParseAddr(s); err != nil {
			if _, err := netip.ParseAddrPort(s); err != nil {
				return fmt.Errorf("DNS_SERVERS entries must be IP or IP:port")
			}
		}
	}
	if c.DataDir == "" {
		return fmt.Errorf("WARP_DATA_DIR must not be empty")
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid LOG_LEVEL")
	}
	return nil
}

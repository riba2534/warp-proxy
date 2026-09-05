package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config 存储服务的所有配置项
type Config struct {
	// 外部监听地址与端口（SOCKS5 转发入口）
	ProxyHost string
	ProxyPort int

	// 内部 warp-svc 监听地址与端口
	WarpSvcHost string
	WarpSvcPort int

	// Cloudflare WARP+ 许可证密钥（可选）
	LicenseKey string

	// HTTP 健康检查服务配置
	HealthHost          string
	HealthPort          int
	DisableHealthServer bool

	// WARP 连接等待超时时间
	ConnectTimeout time.Duration

	// 健康检查探测超时时间
	HealthcheckTimeout time.Duration

	// 日志级别 (debug, info, warn, error)
	LogLevel string
}

// LoadFromEnv 从环境变量加载配置，提供合理的生产级默认值
func LoadFromEnv() *Config {
	cfg := &Config{
		ProxyHost:           getEnv("WARP_PROXY_HOST", "0.0.0.0"),
		ProxyPort:           getEnvInt("WARP_PROXY_PORT", 1080),
		WarpSvcHost:         getEnv("WARP_SVC_HOST", "127.0.0.1"),
		WarpSvcPort:         getEnvInt("WARP_SVC_PORT", 40000),
		LicenseKey:          getEnv("WARP_LICENSE_KEY", ""),
		HealthHost:          getEnv("HEALTH_HOST", "0.0.0.0"),
		HealthPort:          getEnvInt("HEALTH_PORT", 8080),
		DisableHealthServer: getEnvBool("DISABLE_HEALTH_SERVER", false),
		ConnectTimeout:      getEnvDuration("CONNECT_TIMEOUT", 60*time.Second),
		HealthcheckTimeout:  getEnvDuration("HEALTHCHECK_TIMEOUT", 10*time.Second),
		LogLevel:            getEnv("LOG_LEVEL", "info"),
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
	return fmt.Sprintf("%s:%d", c.ProxyHost, c.ProxyPort)
}

// WarpSvcTargetAddr 返回内部 warp-svc 的完整 TCP 地址
func (c *Config) WarpSvcTargetAddr() string {
	return fmt.Sprintf("%s:%d", c.WarpSvcHost, c.WarpSvcPort)
}

// HealthListenAddr 返回健康检查 HTTP 服务的监听地址
func (c *Config) HealthListenAddr() string {
	return fmt.Sprintf("%s:%d", c.HealthHost, c.HealthPort)
}

// LocalProxyAddr 返回用于本地健康检查的代理地址
func (c *Config) LocalProxyAddr() string {
	host := c.ProxyHost
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s:%d", host, c.ProxyPort)
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return defaultVal
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

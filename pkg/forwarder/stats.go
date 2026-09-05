package forwarder

import (
	"sync/atomic"
	"time"
)

// Stats 记录转发器的运行统计指标
type Stats struct {
	startTime        time.Time
	activeConns      int64
	totalConns       int64
	bytesClientToUp  int64 // 客户端 -> 上游 (上传/接收)
	bytesUpToClient  int64 // 上游 -> 客户端 (下载/发送)
}

// NewStats 创建并初始化统计对象
func NewStats() *Stats {
	return &Stats{
		startTime: time.Now(),
	}
}

// IncActiveConns 增加活跃连接数和总连接数
func (s *Stats) IncActiveConns() {
	atomic.AddInt64(&s.activeConns, 1)
	atomic.AddInt64(&s.totalConns, 1)
}

// DecActiveConns 减少活跃连接数
func (s *Stats) DecActiveConns() {
	atomic.AddInt64(&s.activeConns, -1)
}

// AddBytesClientToUp 累加客户端向上游发送的字节数
func (s *Stats) AddBytesClientToUp(n int64) {
	atomic.AddInt64(&s.bytesClientToUp, n)
}

// AddBytesUpToClient 累加由上游向客户端发送的字节数
func (s *Stats) AddBytesUpToClient(n int64) {
	atomic.AddInt64(&s.bytesUpToClient, n)
}

// Snapshot 获取当前统计数据的快照
type Snapshot struct {
	UptimeSeconds    int64 `json:"uptime_seconds"`
	ActiveConns      int64 `json:"active_connections"`
	TotalConns       int64 `json:"total_connections"`
	BytesClientToUp  int64 `json:"bytes_received"` // 外部发往代理的字节数
	BytesUpToClient  int64 `json:"bytes_sent"`     // 代理返回给外部的字节数
}

// GetSnapshot 返回当前统计指标的快照
func (s *Stats) GetSnapshot() Snapshot {
	return Snapshot{
		UptimeSeconds:   int64(time.Since(s.startTime).Seconds()),
		ActiveConns:     atomic.LoadInt64(&s.activeConns),
		TotalConns:      atomic.LoadInt64(&s.totalConns),
		BytesClientToUp: atomic.LoadInt64(&s.bytesClientToUp),
		BytesUpToClient: atomic.LoadInt64(&s.bytesUpToClient),
	}
}

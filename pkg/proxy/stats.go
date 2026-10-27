package proxy

import (
	"sync/atomic"
	"time"
)

// Stats holds the server's counters. Connections count from admission (within
// MaxConnections) until they close, whether or not they reach a relay.
type Stats struct {
	startTime       time.Time
	activeConns     atomic.Int64
	totalConns      atomic.Int64
	bytesClientToUp atomic.Int64
	bytesUpToClient atomic.Int64
	rejected        atomic.Int64
}

// NewStats returns zeroed counters whose uptime starts now.
func NewStats() *Stats {
	return &Stats{startTime: time.Now()}
}

// IncActiveConns records an admitted connection.
func (s *Stats) IncActiveConns() {
	s.activeConns.Add(1)
	s.totalConns.Add(1)
}

// DecActiveConns records that an admitted connection closed.
func (s *Stats) DecActiveConns() { s.activeConns.Add(-1) }

// AddBytesClientToUp adds bytes relayed from a client to its destination.
func (s *Stats) AddBytesClientToUp(n int64) { s.bytesClientToUp.Add(n) }

// AddBytesUpToClient adds bytes relayed from a destination to its client.
func (s *Stats) AddBytesUpToClient(n int64) { s.bytesUpToClient.Add(n) }

// IncRejected records a connection refused by the connection limit or the
// destination policy.
func (s *Stats) IncRejected() { s.rejected.Add(1) }

// Snapshot is a point-in-time copy of Stats.
type Snapshot struct {
	UptimeSeconds   int64 `json:"uptime_seconds"`
	ActiveConns     int64 `json:"active_connections"`
	TotalConns      int64 `json:"total_connections"`
	BytesClientToUp int64 `json:"bytes_received"` // from clients to the proxy
	BytesUpToClient int64 `json:"bytes_sent"`     // from the proxy back to clients
	Rejected        int64 `json:"rejected_connections"`
}

// GetSnapshot returns the current counters.
func (s *Stats) GetSnapshot() Snapshot {
	return Snapshot{
		UptimeSeconds:   int64(time.Since(s.startTime).Seconds()),
		ActiveConns:     s.activeConns.Load(),
		TotalConns:      s.totalConns.Load(),
		BytesClientToUp: s.bytesClientToUp.Load(),
		BytesUpToClient: s.bytesUpToClient.Load(),
		Rejected:        s.rejected.Load(),
	}
}

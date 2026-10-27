// Package tunnel brings up a WireGuard interface inside the current network
// namespace and routes all egress through it the way wg-quick does, except
// WireGuard's own UDP and the directly connected subnets. It works on Linux
// only; elsewhere Up returns an error wrapping errors.ErrUnsupported.
package tunnel

import "time"

type Status struct {
	Mode          Mode      `json:"mode"` // effective: kernel or userspace
	Interface     string    `json:"interface"`
	Endpoint      string    `json:"endpoint"`       // current resolved ip:port
	LastHandshake time.Time `json:"last_handshake"` // zero before the first handshake
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	IPv6          bool      `json:"ipv6"` // IPv6 egress configured
}

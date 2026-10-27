//go:build !linux

package proxy

import (
	"errors"
	"syscall"
)

// setSocketMark fails: SO_MARK exists only on Linux.
func setSocketMark(syscall.RawConn, uint32) error {
	return errors.ErrUnsupported
}

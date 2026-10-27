package proxy

import (
	"os"
	"syscall"
)

// setSocketMark sets SO_MARK, which needs CAP_NET_ADMIN.
func setSocketMark(c syscall.RawConn, mark uint32) error {
	var err error
	if ctrlErr := c.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
	}); ctrlErr != nil {
		return ctrlErr
	}
	return os.NewSyscallError("setsockopt SO_MARK", err)
}

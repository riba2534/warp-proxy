package proxy

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

// With CAP_NET_ADMIN the real setter marks the socket; without it the kernel
// refuses SO_MARK and the dial fails closed.
func TestSetSocketMark(t *testing.T) {
	upstream := startUpstream(t, func(net.Conn) {})
	s := NewServer(Options{Mark: testMark, AllowPrivate: true, Logger: testLogger(t)})
	c, err := s.dial(context.Background(), "tcp", upstream)
	if err != nil {
		if !errors.Is(err, errMark) || !errors.Is(err, syscall.EPERM) {
			t.Fatalf("dial: %v", err)
		}
		t.Log("no CAP_NET_ADMIN: the dial failed closed")
		return
	}
	defer c.Close()
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mark int
	var getErr error
	if err := raw.Control(func(fd uintptr) { mark, getErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK) }); err != nil || getErr != nil {
		t.Fatal(err, getErr)
	}
	if uint32(mark) != testMark {
		t.Errorf("SO_MARK %#x, want %#x", mark, testMark)
	}
}

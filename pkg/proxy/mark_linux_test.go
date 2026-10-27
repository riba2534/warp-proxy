package proxy

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

// With CAP_NET_ADMIN the real setter marks the socket. Without it the kernel
// refuses SO_MARK and a dial to a public destination fails closed in Control,
// before anything is sent.
func TestSetSocketMark(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	raw, err := pc.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := setSocketMark(raw, testMark); err != nil {
		if !errors.Is(err, syscall.EPERM) {
			t.Fatalf("setSocketMark: %v", err)
		}
		t.Log("no CAP_NET_ADMIN: checking that dials fail closed")
		s := NewServer(Options{Mark: testMark, Logger: testLogger(t)})
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		if _, err := s.dial(ctx, "tcp", "203.0.113.1:80"); !errors.Is(err, errMark) || !errors.Is(err, syscall.EPERM) {
			t.Fatalf("dial: %v", err)
		}
		return
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

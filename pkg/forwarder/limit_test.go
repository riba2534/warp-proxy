package forwarder

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestConnectionLimitKeepsAdmittedClientWorking(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := upstream.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	f := NewServer("127.0.0.1:0", upstream.Addr().String())
	f.SetConnectionLimit(1)
	if err = f.Listen(); err != nil {
		t.Fatal(err)
	}
	go f.Serve()
	defer f.Stop()
	first, err := net.Dial("tcp", f.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	var peer net.Conn
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("first not admitted")
	}
	defer peer.Close()
	second, err := net.Dial("tcp", f.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1)
	if _, err = second.Read(b); err != io.EOF {
		t.Fatalf("excess client should close, got %v", err)
	}
	if _, err = first.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = io.ReadFull(peer, b); err != nil || b[0] != 'x' {
		t.Fatalf("admitted client affected: %v", err)
	}
}

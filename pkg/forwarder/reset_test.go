package forwarder

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestClientResetClosesUpstream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := ln.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	f := NewServer("127.0.0.1:0", ln.Addr().String())
	if err = f.Listen(); err != nil {
		t.Fatal(err)
	}
	go f.Serve()
	defer f.Stop()
	c, err := net.Dial("tcp", f.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var up net.Conn
	select {
	case up = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("no upstream")
	}
	defer up.Close()
	c.Write([]byte("x"))
	up.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1)
	if _, err = io.ReadFull(up, b); err != nil {
		t.Fatal(err)
	}
	c.(*net.TCPConn).SetLinger(0)
	c.Close()
	// Upstream deliberately does not close its write half after receiving FIN.
	up.Read(b)
	time.Sleep(250 * time.Millisecond)
	if n := f.GetStats().GetSnapshot().ActiveConns; n != 0 {
		t.Fatalf("client RST left %d active upstream connection(s); io.Copy error swallowed", n)
	}
}

package health

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKSGreetingCancellation(t *testing.T) {
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
	done := make(chan *Result, 1)
	go func() { done <- NewChecker(ln.Addr().String(), 150*time.Millisecond).Check(context.Background()) }()
	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("no SOCKS dial")
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	greeting := make([]byte, 3)
	if _, err = io.ReadFull(conn, greeting); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.Healthy {
			t.Fatal("unexpected healthy")
		}
		t.Log("health request returned after deadline")
	case <-time.After(time.Second):
		t.Fatal("health request stuck")
	}
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	b := make([]byte, 1)
	_, err = conn.Read(b)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("SOCKS socket still open 300ms after request timeout; Dial ignores cancellation")
	}
	if err != io.EOF {
		t.Fatalf("expected EOF after cancellation, got %v", err)
	}
}

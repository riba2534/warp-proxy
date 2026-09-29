package health

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentChecksShareProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	acceptDone := make(chan struct{})
	var handlers sync.WaitGroup
	go func() {
		defer close(acceptDone)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.SetDeadline(time.Now().Add(2 * time.Second))
			accepted.Add(1)
			handlers.Add(1)
			go func() { defer handlers.Done(); defer c.Close(); io.Copy(io.Discard, c) }()
		}
	}()
	defer func() { ln.Close(); <-acceptDone; handlers.Wait() }()
	checker := NewChecker(ln.Addr().String(), 150*time.Millisecond)
	var callers sync.WaitGroup
	for i := 0; i < 20; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if checker.Check(ctx).Healthy {
				t.Error("unresponsive SOCKS reported healthy")
			}
		}()
	}
	callers.Wait()
	if n := accepted.Load(); n == 0 || n > 3 {
		t.Fatalf("20 callers should share at most 3 fallback dials, got %d", n)
	}
}

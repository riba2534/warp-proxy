package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"runtime"
	"runtime/pprof"
	"slices"
	"testing"
	"time"
)

func TestNewServerDefaults(t *testing.T) {
	s := NewServer(Options{})
	if s.opts.MaxConnections != 1024 || s.opts.DialTimeout != 10*time.Second ||
		s.opts.HandshakeTimeout != 10*time.Second || s.opts.AllowPrivate || s.log == nil {
		t.Errorf("defaults %+v", s.opts)
	}
	if s.Addr() != nil {
		t.Error("Addr before Listen")
	}
	if err := s.Serve(); err == nil {
		t.Error("Serve before Listen returned nil")
	}
	if err := s.Stop(); err != nil {
		t.Errorf("Stop before Listen: %v", err)
	}
}

func TestListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := NewServer(Options{ListenAddr: ln.Addr().String()}).Listen(); err == nil {
		t.Fatal("Listen on a busy port succeeded")
	}
}

// The handshake deadline is absolute: a client that never finishes its request,
// however it trickles bytes, is closed once HandshakeTimeout passes.
func TestHandshakeTimeout(t *testing.T) {
	const timeout = 200 * time.Millisecond
	s := startServer(t, Options{HandshakeTimeout: timeout, Dial: redirectTo(startUpstream(t, pong), nil)}, nil)
	cases := []struct {
		name  string
		start func(c net.Conn)
	}{
		{"silent", func(net.Conn) {}},
		{"partial socks5 greeting", func(c net.Conn) { _, _ = c.Write([]byte{socks5Version}) }},
		{"socks5 without request", func(c net.Conn) {
			_, _ = c.Write(socks5Greeting(socks5NoAuth))
			_, _ = io.ReadFull(c, make([]byte, 2))
		}},
		{"socks4 without user id terminator", func(c net.Conn) {
			_, _ = c.Write([]byte{socks4Version, socks4Connect, 0, 80, 203, 0, 113, 1, 'u'})
		}},
		{"slowloris http head", func(c net.Conn) {
			_, _ = c.Write([]byte("CONNECT example.test:443 HTTP/1.1\r\n"))
			go func() {
				for c.SetWriteDeadline(time.Now().Add(testTimeout)) == nil {
					if _, err := c.Write([]byte("X")); err != nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
			}()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			c := dialProxy(t, s)
			tc.start(c)
			expectClosed(t, c)
			if elapsed := time.Since(start); elapsed < timeout*3/4 || elapsed > 10*timeout {
				t.Errorf("closed after %v, want about %v", elapsed, timeout)
			}
		})
	}
}

// Neither a dial slower than HandshakeTimeout nor an idle relay is cut by the
// handshake deadline.
func TestHandshakeDeadlineEndsWithHandshake(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	connect := redirectTo(startUpstream(t, acceptInto(accepted)), nil)
	slowDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		time.Sleep(300 * time.Millisecond)
		return connect(ctx, network, address)
	}
	s := startServer(t, Options{HandshakeTimeout: 100 * time.Millisecond, Dial: slowDial}, nil)
	c, up := openRelay(t, s, accepted)
	time.Sleep(300 * time.Millisecond)
	echo(t, c, up, "still open")
	echo(t, up, c, "both ways")
}

func TestMaxConnections(t *testing.T) {
	accepted := make(chan net.Conn, 2)
	s := startServer(t, Options{MaxConnections: 1, Dial: redirectTo(startUpstream(t, acceptInto(accepted)), nil)}, nil)
	first, up := openRelay(t, s, accepted)

	second := dialProxy(t, s)
	if got, err := io.ReadAll(second); err != nil || len(got) != 0 {
		t.Fatalf("excess client got %q, %v; want an immediate EOF", got, err)
	}
	echo(t, first, up, "admitted client unaffected")
	echo(t, up, first, "both ways")
	if st := s.Stats().GetSnapshot(); st.Rejected != 1 || st.ActiveConns != 1 || st.TotalConns != 1 {
		t.Errorf("stats %+v, want 1 rejected, 1 active, 1 total", st)
	}

	// The slot frees once the admitted client's relay ends.
	first.Close()
	up.Close()
	waitFor(t, "the first client to be released", func() bool { return s.Stats().GetSnapshot().ActiveConns == 0 })
	openRelay(t, s, accepted)
}

// Stop closes active relays, handshakes and in-flight dials and waits for the
// handlers; startServer's cleanup then checks that Serve returned nil and that
// a second Stop is harmless.
func TestStopClosesEverything(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	connect := redirectTo(startUpstream(t, acceptInto(accepted)), nil)
	dialing := make(chan struct{})
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "203.0.113.2:80" {
			close(dialing)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return connect(ctx, network, address)
	}
	s := startServer(t, Options{Dial: dial, DialTimeout: time.Minute}, nil)

	relayed, up := openRelay(t, s, accepted)
	pending := dialProxy(t, s)
	if _, err := pending.Write(slices.Concat(socks5Greeting(socks5NoAuth), socks5IP("203.0.113.2", 80))); err != nil {
		t.Fatal(err)
	}
	<-dialing
	idle := dialProxy(t, s)
	waitFor(t, "three admitted clients", func() bool { return s.Stats().GetSnapshot().ActiveConns == 3 })

	stopped := make(chan error, 1)
	go func() { stopped <- s.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Stop did not return")
	}
	for _, c := range []net.Conn{relayed, pending, idle, up} {
		expectClosed(t, c)
	}
	if st := s.Stats().GetSnapshot(); st.ActiveConns != 0 {
		t.Errorf("%d connections still active", st.ActiveConns)
	}
	if c, err := net.DialTimeout("tcp", s.Addr().String(), time.Second); err == nil {
		c.Close()
		t.Error("listener still accepting after Stop")
	}
}

func TestStatsCounters(t *testing.T) {
	s := startServer(t, Options{Dial: redirectTo(startUpstream(t, pong), nil)}, nil)
	c := dialProxy(t, s)
	mustSOCKS5(t, c, socks5IP("203.0.113.1", 80))
	exchange(t, c, "ping")
	c = dialProxy(t, s)
	if code, _ := socks5Connect(t, c, socks5IP("127.0.0.1", 80)); code != 0x02 {
		t.Fatalf("reply %#x", code)
	}
	waitFor(t, "connections to finish", func() bool { return s.Stats().GetSnapshot().ActiveConns == 0 })

	st := s.Stats().GetSnapshot()
	want := Snapshot{UptimeSeconds: st.UptimeSeconds, TotalConns: 2, BytesClientToUp: 4, BytesUpToClient: 9, Rejected: 1}
	if st != want || st.UptimeSeconds < 0 {
		t.Errorf("snapshot %+v, want %+v", st, want)
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]int64
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"uptime_seconds", "active_connections", "total_connections", "bytes_received", "bytes_sent", "rejected_connections"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("snapshot JSON %s lacks %q", raw, key)
		}
	}
	if len(fields) != 6 {
		t.Errorf("snapshot JSON %s has extra fields", raw)
	}
}

// A reset on either side tears the relay down even when the other side keeps
// its write half open.
func TestResetClosesBothSides(t *testing.T) {
	for _, side := range []string{"client", "upstream"} {
		t.Run(side, func(t *testing.T) {
			accepted := make(chan net.Conn, 1)
			s := startServer(t, Options{Dial: redirectTo(startUpstream(t, acceptInto(accepted)), nil)}, nil)
			c, up := openRelay(t, s, accepted)
			echo(t, c, up, "x")
			resetting, other := net.Conn(c), up
			if side == "upstream" {
				resetting, other = up.(*notifyConn).Conn, c
			}
			_ = resetting.(*net.TCPConn).SetLinger(0)
			resetting.Close()
			expectClosed(t, other)
			waitFor(t, "the relay to end", func() bool { return s.Stats().GetSnapshot().ActiveConns == 0 })
		})
	}
}

// After Stop no goroutine of the server, its handlers or relays remains.
func TestNoGoroutineLeakAfterStop(t *testing.T) {
	before := runtime.NumGoroutine()
	t.Run("traffic", func(t *testing.T) {
		s := startServer(t, Options{Dial: redirectTo(startUpstream(t, pong), nil)}, &fakeResolver{hosts: exampleHosts})
		for range 10 {
			c := dialProxy(t, s)
			mustSOCKS5(t, c, socks5Domain("example.test", 80))
			exchange(t, c, "leak check")
		}
		open := dialProxy(t, s) // relay still open at Stop
		mustSOCKS5(t, open, socks5Domain("example.test", 80))
		refused := dialProxy(t, s)
		if code, _ := socks5Connect(t, refused, socks5IP("10.0.0.1", 80)); code != 0x02 {
			t.Fatalf("reply %#x", code)
		}
		idle := dialProxy(t, s) // handshake in progress at Stop
		_, _ = idle.Write([]byte{socks5Version})
		waitFor(t, "two clients left", func() bool { return s.Stats().GetSnapshot().ActiveConns == 2 })
	}) // cleanups: clients closed, server stopped, upstream closed

	deadline := time.Now().Add(testTimeout)
	for runtime.NumGoroutine() > before+2 {
		if time.Now().After(deadline) {
			var buf bytes.Buffer
			_ = pprof.Lookup("goroutine").WriteTo(&buf, 1)
			t.Fatalf("%d goroutines before, %d after Stop:\n%s", before, runtime.NumGoroutine(), buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

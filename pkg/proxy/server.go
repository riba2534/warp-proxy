// Package proxy is the SOCKS5, SOCKS4/4a and HTTP CONNECT proxy server clients
// reach on one port. Destinations are dialed from the server's own network
// namespace, whose default route is the WireGuard tunnel but which can still
// reach loopback and its directly connected (Docker) subnets, so internal
// destinations are refused unless Options.AllowPrivate is set.
package proxy

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	defaultMaxConnections = 1024
	defaultTimeout        = 10 * time.Second
	keepAlivePeriod       = 30 * time.Second
)

// Options configures a Server; zero values select the defaults.
type Options struct {
	ListenAddr       string
	MaxConnections   int           // default 1024; excess connections are closed immediately
	DialTimeout      time.Duration // default 10s, whole connect including fallbacks
	HandshakeTimeout time.Duration // default 10s, deadline for the client's request
	DNSServers       []string      // "ip" or "ip:port"; empty = system resolver
	AllowPrivate     bool          // default false
	// Dial is a test hook; it receives IP literals only, after policy.
	Dial   func(ctx context.Context, network, address string) (net.Conn, error)
	Logger *slog.Logger
}

// Server accepts proxy clients, applies the destination policy and relays bytes.
type Server struct {
	opts   Options
	log    *slog.Logger
	stats  *Stats
	dial   dialFunc
	lookup lookupFunc
	err    error // invalid Options, reported by Listen

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{} // clients and their upstreams, closed by Stop
	clients  int
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// closeWriter is implemented by connections that can half-close (send FIN).
type closeWriter interface {
	CloseWrite() error
}

// NewServer returns a server for opts. Invalid options are reported by Listen.
func NewServer(opts Options) *Server {
	if opts.MaxConnections <= 0 {
		opts.MaxConnections = defaultMaxConnections
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = defaultTimeout
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = defaultTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		opts:   opts,
		log:    cmp.Or(opts.Logger, slog.Default()),
		stats:  NewStats(),
		dial:   opts.Dial,
		conns:  make(map[net.Conn]struct{}),
		ctx:    ctx,
		cancel: cancel,
	}
	if s.dial == nil {
		s.dial = defaultDial(opts.AllowPrivate)
	}
	s.lookup, s.err = newLookup(opts.DNSServers)
	return s
}

// Stats returns the server's live counters.
func (s *Server) Stats() *Stats { return s.stats }

// Listen opens the listener without accepting, so Addr is known before Serve.
func (s *Server) Listen() error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return nil
	}
	// Accepted connections inherit the keep-alive; Go disables Nagle by default.
	lc := net.ListenConfig{KeepAlive: keepAlivePeriod}
	ln, err := lc.Listen(s.ctx, "tcp", s.opts.ListenAddr)
	if err != nil {
		return fmt.Errorf("proxy: listen on %s: %w", s.opts.ListenAddr, err)
	}
	s.listener = ln
	return nil
}

// Addr returns the listener's address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Serve accepts connections until Stop, then returns nil. It returns an error
// if Listen was not called or the listener fails permanently.
func (s *Server) Serve() error {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	if ln == nil {
		return errors.New("proxy: Serve called before Listen")
	}
	s.log.Info("proxy server listening", "addr", ln.Addr().String())

	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			if !transientAcceptError(err) {
				return fmt.Errorf("proxy: accept: %w", err)
			}
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			s.log.Warn("proxy accept failed; retrying", "error", err, "backoff", backoff)
			select {
			case <-time.After(backoff):
			case <-s.ctx.Done():
				return nil
			}
			continue
		}
		backoff = 0
		if s.admit(c) {
			go s.handle(c)
		}
	}
}

// transientAcceptError reports resource exhaustion that clears on its own.
func transientAcceptError(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) ||
		errors.Is(err, syscall.ECONNABORTED)
}

// Stop closes the listener and every connection, then waits for the handlers.
func (s *Server) Stop() error {
	s.cancel()
	var err error
	s.mu.Lock()
	if s.listener != nil {
		if err = s.listener.Close(); errors.Is(err, net.ErrClosed) {
			err = nil // already stopped
		}
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

// admit registers an accepted client within MaxConnections or closes it.
func (s *Server) admit(c net.Conn) bool {
	s.mu.Lock()
	ok := s.ctx.Err() == nil && s.clients < s.opts.MaxConnections
	if ok {
		s.clients++
		s.conns[c] = struct{}{}
		s.wg.Add(1)
	}
	s.mu.Unlock()
	if ok {
		s.stats.IncActiveConns()
		return true
	}
	if s.ctx.Err() == nil {
		s.stats.IncRejected()
		s.log.Debug("proxy connection", "client", c.RemoteAddr().String(), "result", "connection limit reached")
	}
	_ = c.Close()
	return false
}

// release closes an admitted client and frees its slot.
func (s *Server) release(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.clients--
	s.mu.Unlock()
	_ = c.Close()
	s.stats.DecActiveConns()
	s.wg.Done()
}

// track registers an upstream so Stop closes it; once stopping it closes c instead.
func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		_ = c.Close()
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	_ = c.Close()
}

const (
	protoSOCKS5  = "socks5"
	protoSOCKS4  = "socks4"
	protoSOCKS4a = "socks4a"
	protoHTTP    = "http"
)

// request is a client's CONNECT request.
type request struct {
	proto string // for logs
	host  string // hostname or IP literal, as the client sent it
	port  uint16
	// reply builds the protocol's answer: success with the upstream's local
	// address as the bound address, or the failure err denotes.
	reply func(bound net.Addr, err error) []byte
}

func (r request) target() string {
	if r.host == "" {
		return ""
	}
	return net.JoinHostPort(r.host, strconv.Itoa(int(r.port)))
}

// readRequest picks the protocol by the first byte and reads the request.
func readRequest(br *bufio.Reader, w io.Writer) (request, error) {
	first, err := br.Peek(1)
	if err != nil {
		return request{}, err
	}
	switch first[0] {
	case socks5Version:
		return readSOCKS5(br, w)
	case socks4Version:
		return readSOCKS4(br, w)
	}
	return readHTTPConnect(br, w)
}

func (s *Server) handle(client net.Conn) {
	defer s.release(client)
	start := time.Now()
	req, toUp, toClient, err := s.serveConn(client)
	if s.log.Enabled(s.ctx, slog.LevelDebug) {
		result := "ok"
		if err != nil {
			result = err.Error()
		}
		s.log.Debug("proxy connection", "client", client.RemoteAddr().String(), "protocol", req.proto,
			"target", req.target(), "result", result, "bytes_up", toUp, "bytes_down", toClient,
			"duration", time.Since(start))
	}
}

// serveConn serves one client: handshake, policy-checked connect, reply, relay.
func (s *Server) serveConn(client net.Conn) (req request, toUp, toClient int64, err error) {
	_ = client.SetDeadline(time.Now().Add(s.opts.HandshakeTimeout))
	br := bufio.NewReaderSize(client, maxHTTPHead)
	if req, err = readRequest(br, client); err != nil {
		return req, 0, 0, fmt.Errorf("handshake: %w", err)
	}
	_ = client.SetDeadline(time.Time{})

	upstream, err := s.connect(s.ctx, req.host, req.port)
	if err == nil && !s.track(upstream) {
		err = errors.New("server stopped")
	}
	if err != nil {
		if classify(err) == failPolicy {
			s.stats.IncRejected()
		}
		_, _ = client.Write(req.reply(nil, err))
		return req, 0, 0, fmt.Errorf("connect: %w", err)
	}
	defer s.untrack(upstream)

	if _, err = client.Write(req.reply(upstream.LocalAddr(), nil)); err != nil {
		return req, 0, 0, fmt.Errorf("reply: %w", err)
	}
	// Bytes the client sent right behind its request were read into br.
	if n := br.Buffered(); n > 0 {
		pending, _ := br.Peek(n)
		if _, err = upstream.Write(pending); err != nil {
			return req, 0, 0, fmt.Errorf("relay: %w", err)
		}
		toUp = int64(n)
		s.stats.AddBytesClientToUp(toUp)
	}
	up, down := s.relay(client, upstream)
	return req, toUp + up, down, nil
}

// relay copies both directions between the raw TCP connections (splice on
// Linux) until both are done, and returns the byte counts.
func (s *Server) relay(client, upstream net.Conn) (toUp, toClient int64) {
	done := make(chan int64, 1)
	go func() {
		n := pipe(upstream, client)
		s.stats.AddBytesClientToUp(n)
		done <- n
	}()
	toClient = pipe(client, upstream)
	s.stats.AddBytesUpToClient(toClient)
	return <-done, toClient
}

// pipe copies src to dst. A clean EOF is passed on as a half-close; an error
// closes both connections so the other direction ends too.
func pipe(dst, src net.Conn) int64 {
	n, err := io.Copy(dst, src)
	if err != nil {
		_ = dst.Close()
		_ = src.Close()
	} else if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	return n
}

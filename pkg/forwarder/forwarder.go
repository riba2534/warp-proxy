package forwarder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Server 是一个高性能 L4 传输层 TCP 端口透明转发器。
// 它将来自客户端的所有原始数据包原汁原味地直通上游 warp-svc，
// 从而从根本上避免 gost 等应用层代理对 SOCKS5 协议地址类型的篡改。
type Server struct {
	listenAddr  string
	targetAddr  string
	listener    net.Listener
	stats       *Stats
	dialTimeout time.Duration

	mu          sync.Mutex
	conns       map[net.Conn]struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// closeWriter 定义支持 TCP 半关闭（发送 FIN）的接口
type closeWriter interface {
	CloseWrite() error
}

// NewServer 创建一个新的 L4 端口转发服务实例
func NewServer(listenAddr, targetAddr string) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		listenAddr:  listenAddr,
		targetAddr:  targetAddr,
		stats:       NewStats(),
		dialTimeout: 5 * time.Second,
		conns:       make(map[net.Conn]struct{}),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// GetStats 返回当前运行统计信息
func (s *Server) GetStats() *Stats {
	return s.stats
}

// Listen 初始化 TCP 监听器，但不开始阻塞 accept。
// 该方法可用于在后台调用 Serve() 前同步获取分配的监听地址。
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return nil
	}

	lc := net.ListenConfig{
		KeepAlive: 30 * time.Second,
	}

	ln, err := lc.Listen(s.ctx, "tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.listenAddr, err)
	}
	s.listener = ln
	return nil
}

// Addr 返回监听器的实际网络地址（需在 Listen 或 Start 之后调用）
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Serve 开始接受客户端连接并进行数据转发，此方法会阻塞
func (s *Server) Serve() error {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()

	if ln == nil {
		return errors.New("listener not initialized, call Listen() first")
	}

	log.Printf("[Forwarder] L4 transparent forwarder serving on %s -> %s", ln.Addr(), s.targetAddr)

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				var ne net.Error
				if errors.As(err, &ne) && ne.Temporary() {
					log.Printf("[Forwarder] Temporary accept error: %v", err)
					time.Sleep(10 * time.Millisecond)
					continue
				}
				return fmt.Errorf("accept error: %w", err)
			}
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c)
		}(clientConn)
	}
}

// Start 开始监听并转发流量，该方法会阻塞直到服务停止或发生不可恢复的错误
func (s *Server) Start() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

// handleConn 处理单个客户端连接并与上游建立直通管道
func (s *Server) handleConn(clientConn net.Conn) {
	// 配置客户端连接的 TCP 特性
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	s.trackConn(clientConn, true)
	defer func() {
		s.trackConn(clientConn, false)
		_ = clientConn.Close()
	}()

	// 拨号连接本地 warp-svc 上游
	d := net.Dialer{
		Timeout:   s.dialTimeout,
		KeepAlive: 30 * time.Second,
	}

	upstreamConn, err := d.DialContext(s.ctx, "tcp", s.targetAddr)
	if err != nil {
		log.Printf("[Forwarder] Failed to connect to upstream %s for client %s: %v",
			s.targetAddr, clientConn.RemoteAddr(), err)
		return
	}

	if tcpUp, ok := upstreamConn.(*net.TCPConn); ok {
		_ = tcpUp.SetNoDelay(true)
		_ = tcpUp.SetKeepAlive(true)
		_ = tcpUp.SetKeepAlivePeriod(30 * time.Second)
	}

	s.trackConn(upstreamConn, true)
	defer func() {
		s.trackConn(upstreamConn, false)
		_ = upstreamConn.Close()
	}()

	s.stats.IncActiveConns()
	defer s.stats.DecActiveConns()

	// 启动双向并发直通转发管道
	// 在 Linux 上，当双方都为 TCPConn 时，Go 的 io.Copy 底层会自动调用 splice(2) 实现零拷贝
	var pipeWg sync.WaitGroup
	pipeWg.Add(2)

	// 客户端 -> 上游 (包含客户端的原始 SOCKS5 握手包，包括 ATYP=0x01 的裸 IP 请求)
	go func() {
		defer pipeWg.Done()
		n, _ := io.Copy(upstreamConn, clientConn)
		s.stats.AddBytesClientToUp(n)
		if cw, ok := upstreamConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()

	// 上游 -> 客户端
	go func() {
		defer pipeWg.Done()
		n, _ := io.Copy(clientConn, upstreamConn)
		s.stats.AddBytesUpToClient(n)
		if cw, ok := clientConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()

	pipeWg.Wait()
}

func (s *Server) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

// Stop 优雅关闭转发器，停止接收新连接并断开已有连接
func (s *Server) Stop() error {
	s.cancel()

	var err error
	s.mu.Lock()
	if s.listener != nil {
		err = s.listener.Close()
	}
	// 优雅关闭已有连接
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()
	log.Printf("[Forwarder] L4 transparent forwarder stopped")
	return err
}

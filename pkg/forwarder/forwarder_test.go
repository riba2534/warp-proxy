package forwarder

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestLosslessIPv4Forwarding 单元测试：
// 验证纯 IPv4 裸地址 (ATYP=0x01) SOCKS5 请求通过 L4 转发器透传至上游时保持完整无损。
func TestLosslessIPv4Forwarding(t *testing.T) {
	rawIP := net.ParseIP("1.1.1.1").To4()
	rawPort := uint16(443)

	// 1. 启动模拟的 warp-svc SOCKS5 服务端
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock upstream: %v", err)
	}
	defer upstreamLn.Close()
	upstreamAddr := upstreamLn.Addr().String()

	var receivedAtyp byte
	var receivedIP []byte
	var receivedPort uint16
	var serverErr error
	upstreamDone := make(chan struct{})

	go func() {
		defer close(upstreamDone)
		conn, err := upstreamLn.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer conn.Close()

		// 阶段 1: 协商握手 (05 01 00)
		handshakeBuf := make([]byte, 3)
		if _, err := io.ReadFull(conn, handshakeBuf); err != nil {
			serverErr = fmt.Errorf("read handshake failed: %w", err)
			return
		}
		if handshakeBuf[0] != 0x05 {
			serverErr = fmt.Errorf("invalid socks version: %x", handshakeBuf[0])
			return
		}
		// 回复协商: 05 00 (无鉴权)
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			serverErr = fmt.Errorf("write handshake reply failed: %w", err)
			return
		}

		// 阶段 2: CONNECT 请求
		// 协议结构: VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR(变长) | DST.PORT(2)
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			serverErr = fmt.Errorf("read request header failed: %w", err)
			return
		}

		receivedAtyp = header[3]
		// 断言: ATYP 必须是 0x01 (IPv4 地址)
		if receivedAtyp != 0x01 {
			serverErr = fmt.Errorf("expected ATYP=0x01 (IPv4), but got ATYP=0x%02x", receivedAtyp)
			return
		}

		// 读取 4 字节 IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			serverErr = fmt.Errorf("read ipv4 failed: %w", err)
			return
		}
		receivedIP = ipBuf

		// 读取 2 字节端口
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBuf); err != nil {
			serverErr = fmt.Errorf("read port failed: %w", err)
			return
		}
		receivedPort = binary.BigEndian.Uint16(portBuf)

		// 回复连接成功: 05 00 00 01 <bnd.addr 0.0.0.0> <bnd.port 0>
		resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		if _, err := conn.Write(resp); err != nil {
			serverErr = fmt.Errorf("write connect reply failed: %w", err)
			return
		}

		// 阶段 3: 双向回显测试数据
		data := make([]byte, 8)
		if _, err := io.ReadFull(conn, data); err != nil {
			serverErr = fmt.Errorf("read payload failed: %w", err)
			return
		}
		if string(data) != "EchoPing" {
			serverErr = fmt.Errorf("unexpected payload: %s", string(data))
			return
		}
		_, _ = conn.Write([]byte("EchoPong"))
	}()

	// 2. 启动 L4 透明转发器
	fwd := NewServer("127.0.0.1:0", upstreamAddr)
	if err := fwd.Listen(); err != nil {
		t.Fatalf("fwd listen failed: %v", err)
	}
	fwdAddr := fwd.Addr().String()
	go func() {
		_ = fwd.Serve()
	}()
	defer func() { _ = fwd.Stop() }()

	// 3. 客户端连接 L4 转发器，发起 SOCKS5 握手并连接裸 IP
	clientConn, err := net.DialTimeout("tcp", fwdAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer clientConn.Close()

	// 发送握手请求
	_, err = clientConn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		t.Fatalf("client send handshake failed: %v", err)
	}

	handshakeResp := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, handshakeResp); err != nil {
		t.Fatalf("client read handshake response failed: %v", err)
	}
	if handshakeResp[0] != 0x05 || handshakeResp[1] != 0x00 {
		t.Fatalf("unexpected handshake response: %x", handshakeResp)
	}

	// 发送针对裸 IP 的 CONNECT 请求 (ATYP=0x01, 4字节IP, 2字节端口)
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, rawIP...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, rawPort)
	req = append(req, portBytes...)

	if _, err := clientConn.Write(req); err != nil {
		t.Fatalf("client write connect request failed: %v", err)
	}

	// 读取 CONNECT 响应
	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, connectResp); err != nil {
		t.Fatalf("client read connect response failed: %v", err)
	}
	if connectResp[1] != 0x00 {
		t.Fatalf("connect failed with code: %x", connectResp[1])
	}

	// 发送测试消息
	if _, err := clientConn.Write([]byte("EchoPing")); err != nil {
		t.Fatalf("client write payload failed: %v", err)
	}

	pong := make([]byte, 8)
	if _, err := io.ReadFull(clientConn, pong); err != nil {
		t.Fatalf("client read pong failed: %v", err)
	}
	if string(pong) != "EchoPong" {
		t.Fatalf("unexpected reply: %s", string(pong))
	}

	<-upstreamDone
	if serverErr != nil {
		t.Fatalf("server assertion failed: %v", serverErr)
	}

	// 核心断言确认
	if receivedAtyp != 0x01 {
		t.Errorf("ATYP should be 0x01, got 0x%02x", receivedAtyp)
	}
	if !bytes.Equal(receivedIP, rawIP) {
		t.Errorf("IP mismatch: expected %v, got %v", rawIP, receivedIP)
	}
	if receivedPort != rawPort {
		t.Errorf("Port mismatch: expected %d, got %d", rawPort, receivedPort)
	}
}

// TestLosslessIPv6Forwarding 验证 IPv6 裸地址 (ATYP=0x04) 也能 100% 原样保留
func TestLosslessIPv6Forwarding(t *testing.T) {
	rawIPv6 := net.ParseIP("2606:4700:4700::1111").To16()
	targetPort := uint16(853)

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock upstream: %v", err)
	}
	defer upstreamLn.Close()

	var receivedAtyp byte
	var receivedIP []byte
	var serverErr error
	upstreamDone := make(chan struct{})

	go func() {
		defer close(upstreamDone)
		conn, err := upstreamLn.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer conn.Close()

		// 握手
		hb := make([]byte, 3)
		_, _ = io.ReadFull(conn, hb)
		_, _ = conn.Write([]byte{0x05, 0x00})

		// 请求头
		header := make([]byte, 4)
		_, _ = io.ReadFull(conn, header)
		receivedAtyp = header[3]

		if receivedAtyp != 0x04 {
			serverErr = fmt.Errorf("expected ATYP=0x04, got 0x%02x", receivedAtyp)
			return
		}

		ipBuf := make([]byte, 16)
		_, _ = io.ReadFull(conn, ipBuf)
		receivedIP = ipBuf

		portBuf := make([]byte, 2)
		_, _ = io.ReadFull(conn, portBuf)

		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()

	fwd := NewServer("127.0.0.1:0", upstreamLn.Addr().String())
	if err := fwd.Listen(); err != nil {
		t.Fatalf("fwd listen failed: %v", err)
	}
	fwdAddr := fwd.Addr().String()
	go func() {
		_ = fwd.Serve()
	}()
	defer func() { _ = fwd.Stop() }()

	clientConn, err := net.DialTimeout("tcp", fwdAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer clientConn.Close()

	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
	hb := make([]byte, 2)
	_, _ = io.ReadFull(clientConn, hb)

	req := []byte{0x05, 0x01, 0x00, 0x04}
	req = append(req, rawIPv6...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, targetPort)
	req = append(req, portBytes...)

	_, _ = clientConn.Write(req)
	resp := make([]byte, 10)
	_, _ = io.ReadFull(clientConn, resp)

	<-upstreamDone
	if serverErr != nil {
		t.Fatalf("server error: %v", serverErr)
	}

	if receivedAtyp != 0x04 {
		t.Errorf("expected ATYP=0x04, got 0x%02x", receivedAtyp)
	}
	if !bytes.Equal(receivedIP, rawIPv6) {
		t.Errorf("IPv6 mismatch: expected %v, got %v", rawIPv6, receivedIP)
	}
}

// TestDomainForwarding 测试域名类型的 SOCKS5 请求也同样保持无损 (ATYP=0x03)
func TestDomainForwarding(t *testing.T) {
	targetDomain := "cloudflare.com"
	targetPort := uint16(443)

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock upstream: %v", err)
	}
	defer upstreamLn.Close()

	var receivedAtyp byte
	var receivedDomain string
	var serverErr error
	upstreamDone := make(chan struct{})

	go func() {
		defer close(upstreamDone)
		conn, err := upstreamLn.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer conn.Close()

		// 握手
		hb := make([]byte, 3)
		_, _ = io.ReadFull(conn, hb)
		_, _ = conn.Write([]byte{0x05, 0x00})

		// 请求头
		header := make([]byte, 4)
		_, _ = io.ReadFull(conn, header)
		receivedAtyp = header[3]

		if receivedAtyp != 0x03 {
			serverErr = fmt.Errorf("expected ATYP=0x03, got 0x%02x", receivedAtyp)
			return
		}

		// 域名长度 + 域名
		lenBuf := make([]byte, 1)
		_, _ = io.ReadFull(conn, lenBuf)
		domainBuf := make([]byte, lenBuf[0])
		_, _ = io.ReadFull(conn, domainBuf)
		receivedDomain = string(domainBuf)

		// 端口
		portBuf := make([]byte, 2)
		_, _ = io.ReadFull(conn, portBuf)

		// 成功回复
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()

	fwd := NewServer("127.0.0.1:0", upstreamLn.Addr().String())
	if err := fwd.Listen(); err != nil {
		t.Fatalf("fwd listen failed: %v", err)
	}
	fwdAddr := fwd.Addr().String()
	go func() {
		_ = fwd.Serve()
	}()
	defer func() { _ = fwd.Stop() }()

	clientConn, err := net.DialTimeout("tcp", fwdAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer clientConn.Close()

	// 握手
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
	hb := make([]byte, 2)
	_, _ = io.ReadFull(clientConn, hb)

	// 域名连接请求
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetDomain))}
	req = append(req, []byte(targetDomain)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, targetPort)
	req = append(req, portBytes...)

	_, _ = clientConn.Write(req)
	resp := make([]byte, 10)
	_, _ = io.ReadFull(clientConn, resp)

	<-upstreamDone
	if serverErr != nil {
		t.Fatalf("server error: %v", serverErr)
	}

	if receivedAtyp != 0x03 {
		t.Errorf("expected ATYP=0x03, got 0x%02x", receivedAtyp)
	}
	if receivedDomain != targetDomain {
		t.Errorf("expected domain %s, got %s", targetDomain, receivedDomain)
	}
}

// TestHighThroughputDataStreaming 测试大容量数据传输吞吐与完整性（无丢包、校验一致）
func TestHighThroughputDataStreaming(t *testing.T) {
	const dataSize = 1024 * 1024 // 1 MB

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream error: %v", err)
	}
	defer upstreamLn.Close()

	sentData := make([]byte, dataSize)
	_, _ = rand.Read(sentData)
	receivedData := make([]byte, dataSize)

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = io.ReadFull(conn, receivedData)
		// 回发相同数据
		_, _ = conn.Write(receivedData)
	}()

	fwd := NewServer("127.0.0.1:0", upstreamLn.Addr().String())
	if err := fwd.Listen(); err != nil {
		t.Fatalf("fwd listen failed: %v", err)
	}
	fwdAddr := fwd.Addr().String()
	go func() {
		_ = fwd.Serve()
	}()
	defer func() { _ = fwd.Stop() }()

	clientConn, err := net.Dial("tcp", fwdAddr)
	if err != nil {
		t.Fatalf("dial forwarder error: %v", err)
	}
	defer clientConn.Close()

	echoedData := make([]byte, dataSize)
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		_, _ = io.ReadFull(clientConn, echoedData)
	}()

	_, err = clientConn.Write(sentData)
	if err != nil {
		t.Fatalf("write data error: %v", err)
	}
	// 客户端数据发送完毕，通知半关闭 (FIN)
	if tc, ok := clientConn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	<-serverDone
	<-clientDone

	// 等待一小段时间让 pipe goroutine 累加 stats
	time.Sleep(20 * time.Millisecond)

	if !bytes.Equal(sentData, echoedData) {
		t.Fatalf("data integrity check failed: sent and received payload differ!")
	}

	snapshot := fwd.GetStats().GetSnapshot()
	if snapshot.BytesClientToUp < int64(dataSize) || snapshot.BytesUpToClient < int64(dataSize) {
		t.Errorf("traffic stats inaccurate: up=%d, down=%d",
			snapshot.BytesClientToUp, snapshot.BytesUpToClient)
	}
	t.Logf("PASS: 1MB high throughput streaming verified, bytes client->up: %d, up->client: %d",
		snapshot.BytesClientToUp, snapshot.BytesUpToClient)
}

// TestConcurrentConnections 测试多并发连接的稳定性与统计指标准确性
func TestConcurrentConnections(t *testing.T) {
	const connCount = 20

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen failed: %v", err)
	}
	defer upstreamLn.Close()

	go func() {
		for {
			c, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 8)
				_, _ = io.ReadFull(conn, buf)
				_, _ = conn.Write([]byte("PONG_OK!"))
			}(c)
		}
	}()

	fwd := NewServer("127.0.0.1:0", upstreamLn.Addr().String())
	if err := fwd.Listen(); err != nil {
		t.Fatalf("fwd listen failed: %v", err)
	}
	fwdAddr := fwd.Addr().String()
	go func() {
		_ = fwd.Serve()
	}()
	defer func() { _ = fwd.Stop() }()

	var wg sync.WaitGroup
	wg.Add(connCount)

	for i := 0; i < connCount; i++ {
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", fwdAddr, 2*time.Second)
			if err != nil {
				t.Errorf("concurrent dial error: %v", err)
				return
			}
			defer c.Close()

			_, _ = c.Write([]byte("PING_OK!"))
			reply := make([]byte, 8)
			_, _ = io.ReadFull(c, reply)
			if string(reply) != "PONG_OK!" {
				t.Errorf("unexpected reply: %s", string(reply))
			}
		}()
	}

	wg.Wait()
	time.Sleep(50 * time.Millisecond)

	snapshot := fwd.GetStats().GetSnapshot()
	if snapshot.TotalConns != int64(connCount) {
		t.Errorf("expected totalConns=%d, got %d", connCount, snapshot.TotalConns)
	}
	if snapshot.ActiveConns != 0 {
		t.Errorf("expected activeConns=0 after completion, got %d", snapshot.ActiveConns)
	}
	t.Logf("PASS: Concurrent connections (%d conns) verified successfully!", connCount)
}

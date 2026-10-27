package cfwarp

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Golden ClientHello record of Android WARP 6.38.9 (build 5641) with the
// random zeroed, from wgcf v2.3.1 (MIT, cloudflare/api_test.go).
const androidClientHelloGolden = "16030100a10100009d03030000000000000000000000000000000000000000000000000000000000000000000004c02cc030010000700000001d001b0000186170692e636c6f7564666c617265636c69656e742e636f6d00170000ff01000100000a00080006001d00170018000b00020100002300000010000b000908687474702f312e31000500050100000000000d00140012040308040401050308050501080606010201"

func TestClientHelloMatchesAndroidApp(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		_, err := handshake(context.Background(), client, "api.cloudflareclient.com", nil, utls.NewLRUClientSessionCache(1))
		done <- err
	}()

	server.SetReadDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatal(err)
	}
	record := make([]byte, binary.BigEndian.Uint16(header[3:]))
	if _, err := io.ReadFull(server, record); err != nil {
		t.Fatal(err)
	}
	got := append(header, record...)
	clear(got[11 : 11+32]) // record header 5 + handshake header 4 + version 2
	want, _ := hex.DecodeString(androidClientHelloGolden)
	if !bytes.Equal(got, want) {
		t.Errorf("ClientHello differs from the Android app:\n got %x\nwant %x", got, want)
	}
	server.Close()
	<-done
}

// TestClientHelloResumption checks that a resumed handshake carries the
// ticket and a 32-byte session ID, as Conscrypt does, while the first one
// carries neither.
func TestClientHelloResumption(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	cache := utls.NewLRUClientSessionCache(4)

	dial := func() *utls.PubClientHelloMsg {
		raw, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		rec := &recordingConn{Conn: raw}
		conn, err := handshake(context.Background(), rec, "127.0.0.1", pool, cache)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		data := rec.writes.Bytes()
		hello := utls.UnmarshalClientHello(data[5 : 5+int(binary.BigEndian.Uint16(data[3:5]))])
		if hello == nil {
			t.Fatalf("not a ClientHello: %x", data)
		}
		return hello
	}

	if first := dial(); len(first.SessionId) != 0 || len(first.SessionTicket) != 0 {
		t.Errorf("first hello carries session state: id %x, ticket %x", first.SessionId, first.SessionTicket)
	}
	if resumed := dial(); len(resumed.SessionId) != 32 || len(resumed.SessionTicket) == 0 {
		t.Errorf("resumed hello: session ID %d bytes, ticket %d bytes; want 32 and non-empty", len(resumed.SessionId), len(resumed.SessionTicket))
	}
}

type recordingConn struct {
	net.Conn
	writes bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.writes.Write(p)
	return c.Conn.Write(p)
}

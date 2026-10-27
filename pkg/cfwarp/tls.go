package cfwarp

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

const tlsHandshakeTimeout = 10 * time.Second

// newTransport returns an HTTP/1.1 transport whose TLS handshakes present the
// ClientHello of the Android WARP app; Cloudflare rejects other fingerprints.
// rootCAs nil means the system roots. There is deliberately no proxy support:
// net/http would bypass DialTLSContext for a CONNECT tunnel.
func newTransport(rootCAs *x509.CertPool) *http.Transport {
	cache := utls.NewLRUClientSessionCache(64)
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			raw, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(ctx, tlsHandshakeTimeout)
			defer cancel()
			conn, err := handshake(ctx, raw, host, rootCAs, cache)
			if err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// handshake runs a TLS 1.2 client handshake with the WARP Android ClientHello.
// Reproduced from wgcf v2.3.1 (MIT, github.com/ViRb3/wgcf, cloudflare/api.go).
func handshake(ctx context.Context, raw net.Conn, serverName string, rootCAs *x509.CertPool, cache utls.ClientSessionCache) (*utls.UConn, error) {
	conn := utls.UClient(raw, &utls.Config{
		ServerName:         serverName,
		RootCAs:            rootCAs,
		ClientSessionCache: cache,
		MinVersion:         utls.VersionTLS12,
		MaxVersion:         utls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}, utls.HelloCustom)
	if err := conn.ApplyPreset(clientHelloSpec()); err != nil {
		return nil, fmt.Errorf("apply WARP TLS fingerprint: %w", err)
	}
	// Conscrypt sends an empty session ID on a fresh TLS 1.2 handshake, while
	// uTLS generates one for every custom hello. Clear it before the session
	// lookup and set one only when a cached ticket is offered.
	conn.HandshakeState.Hello.SessionId = nil
	if err := conn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("build WARP TLS ClientHello: %w", err)
	}
	if len(conn.HandshakeState.Hello.SessionTicket) != 0 {
		conn.HandshakeState.Hello.SessionId = make([]byte, 32)
		rand.Read(conn.HandshakeState.Hello.SessionId)
		if err := conn.MarshalClientHello(); err != nil {
			return nil, fmt.Errorf("marshal resumed WARP TLS ClientHello: %w", err)
		}
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("WARP TLS handshake: %w", err)
	}
	return conn, nil
}

// clientHelloSpec is the ClientHello of Cloudflare WARP for Android 6.38.9
// (build 5641), as captured by wgcf v2.3.1 (MIT).
func clientHelloSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS12,
		CipherSuites: []uint16{
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateNever},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.PKCS1WithSHA1,
			}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

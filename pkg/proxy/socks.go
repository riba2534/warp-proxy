package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
)

// SOCKS5 (RFC 1928) constants.
const (
	socks5Version      = 0x05
	socks5NoAuth       = 0x00
	socks5NoAcceptable = 0xff
	socks5CmdConnect   = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	socks5Succeeded       = 0x00
	socks5GeneralFailure  = 0x01
	socks5CmdUnsupported  = 0x07
	socks5AtypUnsupported = 0x08
)

// socks5Codes maps a connect failure to its SOCKS5 reply code.
var socks5Codes = [...]byte{
	failGeneral:     socks5GeneralFailure,
	failPolicy:      0x02, // connection not allowed by ruleset
	failUnreachable: 0x04, // host unreachable
	failRefused:     0x05, // connection refused
	failTimeout:     0x06, // TTL expired
}

// SOCKS4 constants (SOCKS4 and the SOCKS4a hostname extension).
const (
	socks4Version     = 0x04
	socks4Connect     = 0x01
	socks4Granted     = 0x5a
	socks4Rejected    = 0x5b
	socks4MaxHostname = 255
)

// readSOCKS5 negotiates the no-authentication method and reads a CONNECT
// request. Requests it cannot serve are answered here before returning an error.
func readSOCKS5(br *bufio.Reader, w io.Writer) (request, error) {
	req := request{proto: protoSOCKS5, reply: socks5ConnectReply}
	var greeting [2]byte // VER NMETHODS
	if _, err := io.ReadFull(br, greeting[:]); err != nil {
		return req, err
	}
	methods := make([]byte, greeting[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return req, err
	}
	if !slices.Contains(methods, socks5NoAuth) {
		_, _ = w.Write([]byte{socks5Version, socks5NoAcceptable})
		return req, errors.New("socks5: client offers no acceptable authentication method")
	}
	if _, err := w.Write([]byte{socks5Version, socks5NoAuth}); err != nil {
		return req, err
	}

	var head [4]byte // VER CMD RSV ATYP
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return req, err
	}
	if head[0] != socks5Version {
		_, _ = w.Write(socks5Reply(socks5GeneralFailure, nil))
		return req, fmt.Errorf("socks5: request version %#x", head[0])
	}
	host, err := readSOCKS5Host(br, head[3])
	if err != nil {
		code := byte(socks5GeneralFailure)
		if errors.Is(err, errUnsupportedAtyp) {
			code = socks5AtypUnsupported
		}
		_, _ = w.Write(socks5Reply(code, nil))
		return req, err
	}
	var port [2]byte
	if _, err := io.ReadFull(br, port[:]); err != nil {
		return req, err
	}
	req.host, req.port = host, binary.BigEndian.Uint16(port[:])
	if head[1] != socks5CmdConnect {
		_, _ = w.Write(socks5Reply(socks5CmdUnsupported, nil))
		return req, fmt.Errorf("socks5: unsupported command %#x", head[1])
	}
	return req, nil
}

var errUnsupportedAtyp = errors.New("socks5: unsupported address type")

func readSOCKS5Host(br *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return "", err
		}
		return netip.AddrFrom4(b).String(), nil
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return "", err
		}
		return netip.AddrFrom16(b).String(), nil
	case atypDomain:
		n, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		name := make([]byte, n)
		if _, err := io.ReadFull(br, name); err != nil {
			return "", err
		}
		if n == 0 || slices.Contains(name, 0) {
			return "", errors.New("socks5: empty domain name or NUL byte in it")
		}
		return string(name), nil
	}
	return "", fmt.Errorf("%w %#x", errUnsupportedAtyp, atyp)
}

func socks5ConnectReply(bound net.Addr, err error) []byte {
	if err != nil {
		return socks5Reply(socks5Codes[classify(err)], nil)
	}
	return socks5Reply(socks5Succeeded, bound)
}

// socks5Reply builds a reply whose BND.ADDR/BND.PORT is bound, or 0.0.0.0:0.
func socks5Reply(code byte, bound net.Addr) []byte {
	ap := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	if tcp, ok := bound.(*net.TCPAddr); ok {
		ap = tcp.AddrPort()
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	reply := []byte{socks5Version, code, 0x00, atypIPv4}
	if ap.Addr().Is6() {
		reply[3] = atypIPv6
	}
	reply = append(reply, ap.Addr().AsSlice()...)
	return binary.BigEndian.AppendUint16(reply, ap.Port())
}

// readSOCKS4 reads a SOCKS4 or SOCKS4a CONNECT request; the user ID is ignored.
func readSOCKS4(br *bufio.Reader, w io.Writer) (request, error) {
	req := request{proto: protoSOCKS4, reply: socks4ConnectReply}
	var head [8]byte // VN CD DSTPORT DSTIP
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return req, err
	}
	reject := func(err error) (request, error) {
		_, _ = w.Write(socks4Reply(socks4Rejected))
		return req, err
	}
	if _, err := readCString(br); err != nil {
		return reject(fmt.Errorf("socks4: user id: %w", err))
	}
	ip := netip.AddrFrom4([4]byte(head[4:8]))
	req.host, req.port = ip.String(), binary.BigEndian.Uint16(head[2:4])
	// SOCKS4a: DSTIP 0.0.0.x with x != 0 means a hostname follows the user ID.
	if b := ip.As4(); b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] != 0 {
		req.proto = protoSOCKS4a
		name, err := readCString(br)
		if err == nil && (name == "" || len(name) > socks4MaxHostname) {
			err = fmt.Errorf("length %d", len(name))
		}
		if err != nil {
			return reject(fmt.Errorf("socks4a: hostname: %w", err))
		}
		req.host = name
	}
	if head[1] != socks4Connect {
		return reject(fmt.Errorf("socks4: unsupported command %#x", head[1]))
	}
	return req, nil
}

// readCString reads a NUL-terminated string; it fails with bufio.ErrBufferFull
// rather than grow past the reader's buffer.
func readCString(br *bufio.Reader) (string, error) {
	b, err := br.ReadSlice(0)
	if err != nil {
		return "", err
	}
	return string(b[:len(b)-1]), nil
}

func socks4ConnectReply(_ net.Addr, err error) []byte {
	if err != nil {
		return socks4Reply(socks4Rejected)
	}
	return socks4Reply(socks4Granted)
}

func socks4Reply(code byte) []byte {
	return []byte{0x00, code, 0, 0, 0, 0, 0, 0}
}

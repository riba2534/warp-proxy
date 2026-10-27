package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// maxHTTPHead bounds an HTTP request head (request line and headers). The
// handshake reader's buffer has this size, so no single line can outgrow it.
const maxHTTPHead = 8 << 10

var httpEstablished = []byte("HTTP/1.1 200 Connection established\r\n\r\n")

// httpCodes maps a connect failure to its HTTP status.
var httpCodes = [...]int{
	failGeneral:     http.StatusBadGateway,
	failPolicy:      http.StatusForbidden,
	failUnreachable: http.StatusBadGateway,
	failRefused:     http.StatusBadGateway,
	failTimeout:     http.StatusGatewayTimeout,
}

func httpConnectReply(_ net.Addr, err error) []byte {
	if err != nil {
		return httpError(httpCodes[classify(err)], "")
	}
	return httpEstablished
}

func httpError(status int, header string) []byte {
	return fmt.Appendf(nil, "HTTP/1.1 %d %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n",
		status, http.StatusText(status), header)
}

// readHTTPConnect reads a request head and returns its CONNECT target; headers
// are ignored. Requests it cannot serve are answered here before returning an
// error. Bytes the client sent after the head stay buffered in br.
func readHTTPConnect(br *bufio.Reader, w io.Writer) (request, error) {
	req := request{proto: protoHTTP, reply: httpConnectReply}
	reject := func(status int, header string, err error) (request, error) {
		_, _ = w.Write(httpError(status, header))
		return req, err
	}
	var requestLine string
	for size, first := 0, true; ; first = false {
		line, err := br.ReadSlice('\n')
		size += len(line)
		if errors.Is(err, bufio.ErrBufferFull) || size > maxHTTPHead {
			return reject(http.StatusRequestHeaderFieldsTooLarge, "", errors.New("http: request head too large"))
		}
		if err != nil {
			return req, err
		}
		line = bytes.TrimRight(line, "\r\n")
		if first {
			requestLine = string(line)
		} else if len(line) == 0 {
			break
		}
	}

	method, rest, ok := strings.Cut(requestLine, " ")
	target, version, ok2 := strings.Cut(rest, " ")
	if major, _, okVersion := http.ParseHTTPVersion(version); !ok || !ok2 || !okVersion || major != 1 {
		return reject(http.StatusBadRequest, "", fmt.Errorf("http: malformed request line %q", requestLine))
	}
	if method != http.MethodConnect {
		return reject(http.StatusMethodNotAllowed, "Allow: CONNECT\r\n", fmt.Errorf("http: method %s not allowed", method))
	}
	host, portText, err := net.SplitHostPort(target)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	if err != nil || portErr != nil || host == "" || port == 0 {
		return reject(http.StatusBadRequest, "", fmt.Errorf("http: bad CONNECT target %q", target))
	}
	req.host, req.port = host, uint16(port)
	return req, nil
}

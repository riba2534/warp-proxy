package cfwarp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// API identity of Cloudflare WARP for Android 6.38.9 (build 5641), taken from
// wgcf v2.3.1 (MIT, github.com/ViRb3/wgcf). The API answers only clients that
// match the app, including the TLS fingerprint in tls.go.
const (
	defaultBaseURL = "https://api.cloudflareclient.com"
	apiVersion     = "v0a5641"
	userAgent      = "1.1.1.1/6.38.9-5641 (Android 16.0.0)"
	clientVersion  = "a-6.38.9-5641"

	maxResponseBytes = 1 << 20
)

// defaultPorts are the WireGuard ports Cloudflare documents for WARP endpoints.
var defaultPorts = []int{2408, 500, 1701, 4500}

type client struct {
	http     *http.Client
	baseURL  string
	timeout  time.Duration
	licenses []string // scrubbed from API error messages
}

// apiError is a non-2xx answer from the API.
type apiError struct {
	method, path string
	status       int
	detail       string // Cloudflare's error messages, secrets scrubbed
}

func hasStatus(err error, status int) bool {
	var e *apiError
	return errors.As(err, &e) && e.status == status
}

func (e *apiError) Error() string {
	msg := fmt.Sprintf("%s %s: HTTP %d %s", e.method, e.path, e.status, http.StatusText(e.status))
	if e.detail != "" {
		msg += ": " + e.detail
	}
	return msg
}

// call sends one API request below /{apiVersion} and decodes a JSON answer
// into out when out is non-nil. token authenticates device calls.
func (c *client) call(ctx context.Context, method, path, token string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	path = "/" + apiVersion + path
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	// Headers of the Android app's OkHttp client (no Accept header).
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("CF-Client-Version", clientVersion)
	req.Header.Set("Connection", "Keep-Alive")
	if in != nil {
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("%s %s: read response: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &apiError{method: method, path: path, status: resp.StatusCode, detail: c.errorDetail(data, token)}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s %s: decode response: %w", method, path, err)
		}
	}
	return nil
}

// errorDetail extracts the messages of a Cloudflare error envelope
// ({"errors":[{"code":…,"message":…}]}) with the token and licenses removed.
// The private key never leaves the host, so it cannot be echoed.
func (c *client) errorDetail(body []byte, token string) string {
	var envelope struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	var msgs []string
	for _, e := range envelope.Errors {
		if e.Message != "" {
			msgs = append(msgs, e.Message)
		}
	}
	detail := strings.Join(msgs, "; ")
	for _, s := range append([]string{token}, c.licenses...) {
		if s != "" {
			detail = strings.ReplaceAll(detail, s, "[REDACTED]")
		}
	}
	if len(detail) > 256 {
		detail = detail[:256]
	}
	return detail
}

// registrationRequest is the body of POST /reg as sent by the Android app.
func registrationRequest(publicKey, model string, now time.Time) map[string]string {
	return map[string]string{
		"fcm_token":     "", // populated by Firebase in the app
		"install_id":    "", // populated by Firebase in the app
		"key":           publicKey,
		"locale":        "en_US",
		"model":         model,
		"tos":           now.Format(time.RFC3339Nano),
		"serial_number": "",
		"os_version":    "16.0.0",
		"key_type":      "curve25519",
		"tunnel_type":   "wireguard",
	}
}

// device is the subset of the registration and GET /reg/{id} answers we use.
type device struct {
	ID      string `json:"id"`
	Token   string `json:"token"` // registration answer only
	Account struct {
		AccountType string `json:"account_type"`
		License     string `json:"license"`
	} `json:"account"`
	Config *struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string   `json:"public_key"`
			Endpoint  endpoint `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

// deviceConfig returns the WireGuard part of the answer, nil when absent.
func (d *device) deviceConfig() *deviceConfig {
	if d.Config == nil || len(d.Config.Peers) == 0 {
		return nil
	}
	peer := d.Config.Peers[0]
	return &deviceConfig{
		PeerPublicKey: peer.PublicKey,
		Endpoint:      peer.Endpoint,
		AddressV4:     d.Config.Interface.Addresses.V4,
		AddressV6:     d.Config.Interface.Addresses.V6,
	}
}

// endpoint is peers[0].endpoint. v4 and v6 usually carry a placeholder port
// ("162.159.192.1:0"); host carries a real one.
type endpoint struct {
	Host  string `json:"host,omitempty"`
	V4    string `json:"v4,omitempty"`
	V6    string `json:"v6,omitempty"`
	Ports []int  `json:"ports,omitempty"`
}

// candidates lists "host:port" endpoints in preference order: the endpoint
// wgcf writes into its profile, then v4 with every port, then v6 with every
// port (API ports first, then the defaults), without duplicates.
func (e endpoint) candidates() []string {
	var ports []int
	for _, p := range slices.Concat(e.Ports, defaultPorts) {
		if p > 0 && p <= 65535 && !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}
	v4, v6 := stripPort(e.V4), stripPort(e.V6)

	var out []string
	add := func(hostport string) {
		if !slices.Contains(out, hostport) {
			out = append(out, hostport)
		}
	}
	if e.Host != "" {
		host, port, err := net.SplitHostPort(e.Host)
		if err != nil {
			host, port = e.Host, ""
		}
		if port == "" || port == "0" {
			port = strconv.Itoa(ports[0])
		}
		add(net.JoinHostPort(host, port))
	}
	// Without a host, wgcf's endpoint (v4, else v6, with the first port) is
	// the first candidate of this loop anyway.
	for _, host := range []string{v4, v6} {
		if host == "" {
			continue
		}
		for _, p := range ports {
			add(net.JoinHostPort(host, strconv.Itoa(p)))
		}
	}
	return out
}

// stripPort drops the port of "ip:port" or "[ip]:port"; anything else is
// returned unchanged.
func stripPort(s string) string {
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

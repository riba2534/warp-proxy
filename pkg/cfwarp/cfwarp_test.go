package cfwarp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	testDeviceID = "5b2a7b1c-0d6e-4f4a-9a43-3c1f2e8d9b70"
	testToken    = "tok-6c0f9a2e-SECRET"
	testLicense  = "Ab12Cd34-Ef56Gh78-Ij90Kl12"
	newLicense   = "Zz98Yy76-Xx54Ww32-Vv10Uu98"
	// Cloudflare's published WARP peer key; any valid key would do.
	testPeerKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
)

var (
	regPath     = "/" + apiVersion + "/reg"
	devicePath  = regPath + "/" + testDeviceID
	accountPath = devicePath + "/account"
	namePath    = accountPath + "/reg/" + testDeviceID
)

type request struct {
	method, path string
	body         map[string]any
}

// fakeAPI is a TLS server standing in for api.cloudflareclient.com. Every
// request is checked for the WARP app's headers, path version and TLS shape.
type fakeAPI struct {
	t      *testing.T
	srv    *httptest.Server
	routes map[string]http.HandlerFunc // "METHOD /path"
	logs   bytes.Buffer

	mu   sync.Mutex
	reqs []request
}

func newFakeAPI(t *testing.T, routes map[string]http.HandlerFunc) *fakeAPI {
	f := &fakeAPI{t: t, routes: routes}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	t := f.t
	data, _ := io.ReadAll(r.Body)
	req := request{method: r.Method, path: r.URL.Path}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &req.body); err != nil {
			t.Errorf("%s %s: body is not JSON: %v", r.Method, r.URL.Path, err)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json; charset=UTF-8" {
			t.Errorf("%s %s: Content-Type = %q", r.Method, r.URL.Path, got)
		}
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()

	// Only the uTLS Android hello yields TLS 1.2 with this suite; Go's own
	// client would negotiate TLS 1.3.
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS12 || r.TLS.CipherSuite != tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 || r.TLS.NegotiatedProtocol != "http/1.1" {
		t.Errorf("%s %s: TLS state %+v is not the WARP app's", r.Method, r.URL.Path, r.TLS)
	}
	if !strings.HasPrefix(r.URL.Path, "/v0a5641/") {
		t.Errorf("path %q lacks the API version", r.URL.Path)
	}
	for name, want := range map[string]string{
		"User-Agent":        "1.1.1.1/6.38.9-5641 (Android 16.0.0)",
		"Cf-Client-Version": "a-6.38.9-5641",
		"Connection":        "Keep-Alive",
	} {
		if got := r.Header.Values(name); len(got) != 1 || got[0] != want {
			t.Errorf("%s %s: %s = %q, want %q", r.Method, r.URL.Path, name, got, want)
		}
	}
	if _, ok := r.Header["Accept"]; ok {
		t.Errorf("%s %s: unexpected Accept header", r.Method, r.URL.Path)
	}
	wantAuth := "Bearer " + testToken
	if r.Method == http.MethodPost && r.URL.Path == regPath {
		wantAuth = ""
	}
	if got := r.Header.Get("Authorization"); got != wantAuth {
		t.Errorf("%s %s: Authorization = %q, want %q", r.Method, r.URL.Path, got, wantAuth)
	}

	route := f.routes[r.Method+" "+r.URL.Path]
	if route == nil {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusTeapot)
		return
	}
	route(w, r)
}

func (f *fakeAPI) options(path string) Options {
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	transport := newTransport(pool)
	f.t.Cleanup(transport.CloseIdleConnections)
	return Options{
		Path:       path,
		BaseURL:    f.srv.URL,
		HTTPClient: &http.Client{Transport: transport},
		Timeout:    5 * time.Second,
		Logger:     slog.New(slog.NewTextHandler(&f.logs, nil)),
	}
}

// take returns the requests so far and forgets them.
func (f *fakeAPI) take() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	reqs := f.reqs
	f.reqs = nil
	return reqs
}

func reply(status int, body any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		if body != nil {
			json.NewEncoder(w).Encode(body)
		}
	}
}

// devicePayload mimics a registration (token set) or GET /reg/{id} answer,
// including members this package does not know.
func devicePayload(token, accountType, v4, v6, host string) map[string]any {
	m := map[string]any{
		"id":          testDeviceID,
		"type":        "a",
		"model":       "PC",
		"key_type":    "curve25519",
		"tunnel_type": "wireguard",
		"policy":      map[string]any{"tunnel_protocol": "wireguard"},
		"account": map[string]any{
			"id": "acc-1", "account_type": accountType, "license": testLicense,
			"warp_plus": accountType == "unlimited", "premium_data": 0,
		},
		"config": map[string]any{
			"client_id": "AbCd",
			"interface": map[string]any{"addresses": map[string]any{"v4": v4, "v6": v6}},
			"peers": []any{map[string]any{
				"public_key": testPeerKey,
				"endpoint": map[string]any{
					"host": host, "v4": "162.159.192.1:0", "v6": "[2606:4700:d0::a29f:c001]:0",
					"ports": []int{2408, 500, 1701, 4500},
				},
			}},
			"services": map[string]any{"http_proxy": "172.16.0.1:2480"},
		},
	}
	if token != "" {
		m["token"] = token
	}
	return m
}

func cfError(status int, msg string) http.HandlerFunc {
	return reply(status, map[string]any{
		"result": nil, "success": false, "messages": []any{},
		"errors": []any{map[string]any{"code": 1000 + status, "message": msg}},
	})
}

// seed writes a registration file as a previous run would have left it.
func seed(t *testing.T, path string) *state {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	st := &state{
		Version:     stateVersion,
		DeviceID:    testDeviceID,
		AccessToken: testToken,
		PrivateKey:  key.String(),
		License:     testLicense,
		AccountType: "free",
		Config: &deviceConfig{
			PeerPublicKey: testPeerKey,
			Endpoint:      endpoint{Host: "engage.cloudflareclient.com:2408", V4: "162.159.192.1:0", V6: "[2606:4700:d0::a29f:c001]:0", Ports: []int{2408, 500, 1701, 4500}},
			AddressV4:     "172.16.0.2",
			AddressV6:     "2606:4700:110:8a36::1",
		},
	}
	if err := writeState(path, st); err != nil {
		t.Fatal(err)
	}
	return st
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertNoSecrets(t *testing.T, what, text string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if s != "" && strings.Contains(text, s) {
			t.Errorf("%s leaks a secret %q: %s", what, s, text)
		}
	}
}

func equalCalls(t *testing.T, reqs []request, want ...string) {
	t.Helper()
	var got []string
	for _, r := range reqs {
		got = append(got, r.method+" "+r.path)
	}
	if !slices.Equal(got, want) {
		t.Errorf("API calls = %q, want %q", got, want)
	}
}

func TestLoadRegistersNewDevice(t *testing.T) {
	f := newFakeAPI(t, map[string]http.HandlerFunc{
		"POST " + regPath:   reply(200, devicePayload(testToken, "free", "172.16.0.2", "2606:4700:110:8a36::1", "engage.cloudflareclient.com:2408")),
		"PATCH " + namePath: reply(200, []any{map[string]any{"id": testDeviceID, "name": "ABCDEF", "active": true}}),
	})
	dir := filepath.Join(t.TempDir(), "cloudflare-warp")
	path := filepath.Join(dir, "wireguard-account.json")

	start := time.Now()
	p, err := Load(context.Background(), f.options(path))
	if err != nil {
		t.Fatal(err)
	}
	reqs := f.take()
	equalCalls(t, reqs, "POST "+regPath, "PATCH "+namePath)

	key, err := wgtypes.ParseKey(p.PrivateKey)
	if err != nil {
		t.Fatalf("profile private key: %v", err)
	}
	reg := reqs[0].body
	tos, err := time.Parse(time.RFC3339Nano, reg["tos"].(string))
	if err != nil || tos.Before(start.Add(-time.Second)) || tos.After(time.Now()) {
		t.Errorf("tos = %v (%v), want the registration time", reg["tos"], err)
	}
	delete(reg, "tos")
	wantReg := map[string]any{
		"key":           key.PublicKey().String(),
		"install_id":    "",
		"fcm_token":     "",
		"model":         "PC",
		"serial_number": "",
		"os_version":    "16.0.0",
		"key_type":      "curve25519",
		"tunnel_type":   "wireguard",
		"locale":        "en_US",
	}
	if !reflect.DeepEqual(reg, wantReg) {
		t.Errorf("registration body = %v, want %v", reg, wantReg)
	}
	if name, _ := reqs[1].body["name"].(string); !regexp.MustCompile(`^[0-9A-F]{6}$`).MatchString(name) {
		t.Errorf("device name = %q, want 6 hex digits", name)
	}

	want := &Profile{
		PrivateKey:    p.PrivateKey,
		PeerPublicKey: testPeerKey,
		AddressV4:     netip.MustParsePrefix("172.16.0.2/32"),
		AddressV6:     netip.MustParsePrefix("2606:4700:110:8a36::1/128"),
		AccountType:   "free",
		DeviceID:      testDeviceID,
		Endpoints:     p.Endpoints,
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("profile = %+v, want %+v", p, want)
	}
	if len(p.Endpoints) == 0 || p.Endpoints[0] != "engage.cloudflareclient.com:2408" {
		t.Errorf("endpoints = %q", p.Endpoints)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v (%v), want 0700", info.Mode().Perm(), err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("dir holds %d entries, want only the registration file", len(entries))
	}
	var saved map[string]any
	if err := json.Unmarshal(readFile(t, path), &saved); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]any{
		"version": float64(1), "device_id": testDeviceID, "access_token": testToken,
		"private_key": p.PrivateKey, "license": testLicense, "account_type": "free",
	} {
		if saved[k] != v {
			t.Errorf("saved %s = %v, want %v", k, saved[k], v)
		}
	}

	// The next start reuses the device instead of registering again.
	f.routes["GET "+devicePath] = reply(200, devicePayload("", "free", "172.16.0.2", "2606:4700:110:8a36::1", "engage.cloudflareclient.com:2408"))
	again, err := Load(context.Background(), f.options(path))
	if err != nil {
		t.Fatal(err)
	}
	equalCalls(t, f.take(), "GET "+devicePath)
	if !reflect.DeepEqual(again, p) {
		t.Errorf("reloaded profile = %+v, want %+v", again, p)
	}
}

func TestLoadDeviceModelAndNaming(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		wantWarn bool
	}{
		{"name rejected with 500 is ignored", 500, false},
		{"other naming failures warn", 403, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, map[string]http.HandlerFunc{
				"POST " + regPath:   reply(200, devicePayload(testToken, "free", "172.16.0.2", "", "")),
				"PATCH " + namePath: cfError(tc.status, "cannot rename device of "+testToken),
			})
			opts := f.options(filepath.Join(t.TempDir(), "reg.json"))
			opts.DeviceModel = "Linux"
			p, err := Load(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if got := f.take()[0].body["model"]; got != "Linux" {
				t.Errorf("model = %v, want Linux", got)
			}
			if p.AddressV6.IsValid() {
				t.Errorf("AddressV6 = %v, want none", p.AddressV6)
			}
			if got := strings.Contains(f.logs.String(), "level=WARN"); got != tc.wantWarn {
				t.Errorf("warning logged = %v, want %v:\n%s", got, tc.wantWarn, f.logs.String())
			}
			assertNoSecrets(t, "log", f.logs.String(), testToken)
		})
	}
}

func TestLoadUsesCacheWhenRefreshFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route http.HandlerFunc // nil: API unreachable
	}{
		{"unreachable", nil},
		{"server error", cfError(503, "maintenance for "+testToken+" with license "+testLicense)},
		{"device gone", cfError(404, "not found")},
		{"invalid config", reply(200, devicePayload("", "free", "not-an-ip", "", ""))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, map[string]http.HandlerFunc{"GET " + devicePath: tc.route})
			opts := f.options(filepath.Join(t.TempDir(), "reg.json"))
			if tc.route == nil {
				f.srv.Close()
			}
			st := seed(t, opts.Path)
			want, err := st.profile()
			if err != nil {
				t.Fatal(err)
			}
			infoBefore, _ := os.Stat(opts.Path)

			p, err := Load(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p, want) {
				t.Errorf("profile = %+v, want cached %+v", p, want)
			}
			if !strings.Contains(f.logs.String(), "level=WARN") {
				t.Errorf("no warning logged:\n%s", f.logs.String())
			}
			assertNoSecrets(t, "log", f.logs.String(), testToken, st.PrivateKey, testLicense)
			infoAfter, _ := os.Stat(opts.Path)
			if !os.SameFile(infoBefore, infoAfter) {
				t.Error("registration file was rewritten although nothing changed")
			}
		})
	}
}

func TestLoadRefreshUpdatesConfig(t *testing.T) {
	f := newFakeAPI(t, map[string]http.HandlerFunc{
		"GET " + devicePath: reply(200, devicePayload("", "unlimited", "172.16.0.9", "2606:4700:110:8888::9", "")),
	})
	opts := f.options(filepath.Join(t.TempDir(), "reg.json"))
	st := seed(t, opts.Path)
	infoBefore, _ := os.Stat(opts.Path)

	p, err := Load(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	equalCalls(t, f.take(), "GET "+devicePath)
	if p.AddressV4 != netip.MustParsePrefix("172.16.0.9/32") || p.AddressV6 != netip.MustParsePrefix("2606:4700:110:8888::9/128") {
		t.Errorf("addresses = %v %v, want the refreshed ones", p.AddressV4, p.AddressV6)
	}
	if p.Endpoints[0] != "162.159.192.1:2408" {
		t.Errorf("endpoints = %q, want the refreshed v4 endpoint first", p.Endpoints)
	}
	if p.AccountType != "unlimited" || p.PrivateKey != st.PrivateKey {
		t.Errorf("profile = %+v", p)
	}
	saved, err := readState(opts.Path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Config.AddressV4 != "172.16.0.9" || saved.AccountType != "unlimited" || saved.AccessToken != testToken {
		t.Errorf("saved state = %+v", saved)
	}
	infoAfter, _ := os.Stat(opts.Path)
	if os.SameFile(infoBefore, infoAfter) {
		t.Error("registration file was not replaced")
	}

	// Unchanged answer: no rewrite.
	if _, err := Load(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	infoAgain, _ := os.Stat(opts.Path)
	if !os.SameFile(infoAfter, infoAgain) {
		t.Error("registration file was rewritten although nothing changed")
	}
}

func TestLoadRejectsCorruptFile(t *testing.T) {
	valid := func(edit func(m map[string]any)) string {
		key, _ := wgtypes.GeneratePrivateKey()
		m := map[string]any{
			"version": 1, "device_id": testDeviceID, "access_token": testToken, "private_key": key.String(),
			"config": map[string]any{
				"peer_public_key": testPeerKey, "address_v4": "172.16.0.2",
				"endpoint": map[string]any{"v4": "162.159.192.1:0"},
			},
		}
		edit(m)
		data, _ := json.Marshal(m)
		return string(data)
	}
	for name, content := range map[string]string{
		"empty":            "",
		"not json":         `{"version":1,"private_key":"` + testToken,
		"no version":       valid(func(m map[string]any) { delete(m, "version") }),
		"future version":   valid(func(m map[string]any) { m["version"] = 2 }),
		"no device id":     valid(func(m map[string]any) { delete(m, "device_id") }),
		"no token":         valid(func(m map[string]any) { delete(m, "access_token") }),
		"bad private key":  valid(func(m map[string]any) { m["private_key"] = testToken }),
		"bad peer key":     valid(func(m map[string]any) { m["config"].(map[string]any)["peer_public_key"] = "x" }),
		"bad address":      valid(func(m map[string]any) { m["config"].(map[string]any)["address_v4"] = "2001:db8::1" }),
		"no endpoint":      valid(func(m map[string]any) { m["config"].(map[string]any)["endpoint"] = map[string]any{} }),
		"wrong field type": valid(func(m map[string]any) { m["access_token"] = 42 }),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeAPI(t, nil)
			opts := f.options(filepath.Join(t.TempDir(), "reg.json"))
			opts.LicenseKey = newLicense
			if err := os.WriteFile(opts.Path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(context.Background(), opts)
			if err == nil {
				t.Fatal("Load accepted a corrupt registration file")
			}
			assertNoSecrets(t, "error", err.Error(), testToken, newLicense)
			equalCalls(t, f.take())
			if got := readFile(t, opts.Path); string(got) != content {
				t.Errorf("file changed to %q", got)
			}
		})
	}
}

func TestLoadAppliesLicense(t *testing.T) {
	putOK := reply(200, map[string]any{"id": "acc-2", "role": "child", "warp_plus": true, "premium_data": 0, "quota": 0})
	getPlus := reply(200, devicePayload("", "unlimited", "172.16.0.2", "", ""))

	t.Run("existing device", func(t *testing.T) {
		f := newFakeAPI(t, map[string]http.HandlerFunc{"PUT " + accountPath: putOK, "GET " + devicePath: getPlus})
		opts := f.options(filepath.Join(t.TempDir(), "reg.json"))
		seed(t, opts.Path)
		opts.LicenseKey = newLicense

		p, err := Load(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		reqs := f.take()
		equalCalls(t, reqs, "PUT "+accountPath, "GET "+devicePath)
		if got := reqs[0].body; !reflect.DeepEqual(got, map[string]any{"license": newLicense}) {
			t.Errorf("license body = %v", got)
		}
		if p.AccountType != "unlimited" {
			t.Errorf("account type = %q, want unlimited", p.AccountType)
		}
		if saved, _ := readState(opts.Path); saved == nil || saved.License != newLicense {
			t.Errorf("saved license = %+v", saved)
		}
		assertNoSecrets(t, "log", f.logs.String(), newLicense, testToken)

		// Same license on the next start: no PUT.
		if _, err := Load(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
		equalCalls(t, f.take(), "GET "+devicePath)
	})

	t.Run("fresh registration", func(t *testing.T) {
		f := newFakeAPI(t, map[string]http.HandlerFunc{
			"POST " + regPath:    reply(200, devicePayload(testToken, "free", "172.16.0.2", "", "")),
			"PATCH " + namePath:  reply(200, []any{}),
			"PUT " + accountPath: putOK,
			"GET " + devicePath:  getPlus,
		})
		opts := f.options(filepath.Join(t.TempDir(), "reg.json"))
		opts.LicenseKey = newLicense
		p, err := Load(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		equalCalls(t, f.take(), "POST "+regPath, "PATCH "+namePath, "PUT "+accountPath, "GET "+devicePath)
		if p.AccountType != "unlimited" {
			t.Errorf("account type = %q, want unlimited", p.AccountType)
		}
	})

	t.Run("rejected license", func(t *testing.T) {
		f := newFakeAPI(t, map[string]http.HandlerFunc{
			"PUT " + accountPath: cfError(403, "license "+newLicense+" rejected for token "+testToken),
		})
		opts := f.options(filepath.Join(t.TempDir(), "reg.json"))
		st := seed(t, opts.Path)
		before := readFile(t, opts.Path)
		opts.LicenseKey = newLicense

		_, err := Load(context.Background(), opts)
		if err == nil {
			t.Fatal("Load ignored a rejected license")
		}
		if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "rejected") {
			t.Errorf("error = %v, want the status and Cloudflare's message", err)
		}
		assertNoSecrets(t, "error", err.Error(), newLicense, testToken, st.PrivateKey)
		if !bytes.Equal(readFile(t, opts.Path), before) {
			t.Error("registration file changed after a rejected license")
		}
	})

	t.Run("license kept after registration failure", func(t *testing.T) {
		// The device is persisted before the license is applied, so a failed
		// license never leads to a second registration.
		f := newFakeAPI(t, map[string]http.HandlerFunc{
			"POST " + regPath:    reply(200, devicePayload(testToken, "free", "172.16.0.2", "", "")),
			"PATCH " + namePath:  reply(200, []any{}),
			"PUT " + accountPath: cfError(400, "invalid license"),
		})
		opts := f.options(filepath.Join(t.TempDir(), "reg.json"))
		opts.LicenseKey = newLicense
		if _, err := Load(context.Background(), opts); err == nil {
			t.Fatal("Load ignored a rejected license")
		}
		saved, err := readState(opts.Path)
		if err != nil || saved.DeviceID != testDeviceID || saved.License != testLicense {
			t.Errorf("saved state = %+v, %v; want the registered device", saved, err)
		}
	})
}

func TestUnregister(t *testing.T) {
	for _, tc := range []struct {
		name       string
		route      http.HandlerFunc
		wantErr    bool
		wantRemove bool
	}{
		{"deleted", reply(204, nil), false, true},
		{"already gone", cfError(404, "no such device"), false, true},
		{"api failure", cfError(500, "boom "+testToken), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, map[string]http.HandlerFunc{"DELETE " + devicePath: tc.route})
			opts := f.options(filepath.Join(t.TempDir(), "reg.json"))
			st := seed(t, opts.Path)

			err := Unregister(context.Background(), opts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Unregister error = %v, want error %v", err, tc.wantErr)
			}
			if err != nil {
				assertNoSecrets(t, "error", err.Error(), testToken, st.PrivateKey, testLicense)
			}
			equalCalls(t, f.take(), "DELETE "+devicePath)
			_, statErr := os.Stat(opts.Path)
			if removed := errors.Is(statErr, fs.ErrNotExist); removed != tc.wantRemove {
				t.Errorf("file removed = %v, want %v", removed, tc.wantRemove)
			}
		})
	}

	t.Run("no registration", func(t *testing.T) {
		f := newFakeAPI(t, nil)
		err := Unregister(context.Background(), f.options(filepath.Join(t.TempDir(), "reg.json")))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Unregister error = %v, want fs.ErrNotExist", err)
		}
		equalCalls(t, f.take())
	})
}

func TestLoadRequiresPath(t *testing.T) {
	if _, err := Load(context.Background(), Options{}); err == nil {
		t.Error("Load without a path succeeded")
	}
}

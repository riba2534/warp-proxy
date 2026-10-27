// Package cfwarp registers a device with Cloudflare WARP's consumer API, the
// way the Android app (and wgcf) does, and keeps the registration in a file so
// that restarts reuse the same device and WireGuard key.
package cfwarp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Profile holds the WireGuard parameters of the registered device.
type Profile struct {
	PrivateKey    string       // base64 WireGuard private key
	PeerPublicKey string       // base64
	Endpoints     []string     // "host:port" candidates in preference order
	AddressV4     netip.Prefix // e.g. 172.16.0.2/32
	AddressV6     netip.Prefix // zero value when Cloudflare returned none
	AccountType   string       // "free", "limited", "unlimited", "team", or "" if unknown
	DeviceID      string
}

// Options configures Load and Unregister.
type Options struct {
	Path        string        // registration file, e.g. /var/lib/cloudflare-warp/wireguard-account.json
	LicenseKey  string        // optional WARP+ license; applied when it differs from the stored one
	DeviceModel string        // default "PC"
	BaseURL     string        // default "https://api.cloudflareclient.com"
	HTTPClient  *http.Client  // nil = default client with the WARP uTLS transport
	Timeout     time.Duration // per API call, default 20s
	Logger      *slog.Logger  // nil = slog.Default()
}

func (o Options) withDefaults() (Options, error) {
	if o.Path == "" {
		return o, errors.New("cfwarp: Options.Path is required")
	}
	if o.DeviceModel == "" {
		o.DeviceModel = "PC"
	}
	if o.BaseURL == "" {
		o.BaseURL = defaultBaseURL
	}
	o.BaseURL = strings.TrimRight(o.BaseURL, "/")
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o, nil
}

// newClient returns the API client and a func releasing its idle connections.
// licenses are scrubbed from API error messages.
func (o Options) newClient(licenses ...string) (*client, func()) {
	c := &client{http: o.HTTPClient, baseURL: o.BaseURL, timeout: o.Timeout, licenses: licenses}
	if c.http != nil {
		return c, func() {}
	}
	c.http = &http.Client{Transport: newTransport(nil)}
	return c, c.http.CloseIdleConnections
}

// Load returns the device profile. No file: generate a key, register, persist, return.
// File present: refresh the device config (peer, endpoint, addresses, account type)
// from the API and persist changes; if the API is unreachable or errors, log a warning
// and return the cached profile so startup never depends on the API. A file that exists
// but cannot be parsed or lacks required fields is an error — never re-register over it.
func Load(ctx context.Context, opts Options) (*Profile, error) {
	o, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	c, done := o.newClient(o.LicenseKey)
	defer done()

	st, err := readState(o.Path)
	refresh := true
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if st, err = register(ctx, c, o); err != nil {
			return nil, err
		}
		// A fresh registration answer already carries the device config.
		refresh = st.Config == nil
	case err != nil:
		return nil, err
	}
	c.licenses = append(c.licenses, st.License)
	before, _ := json.Marshal(st)

	if o.LicenseKey != "" && o.LicenseKey != st.License {
		path := "/reg/" + st.DeviceID + "/account"
		if err := c.call(ctx, http.MethodPut, path, st.AccessToken, map[string]string{"license": o.LicenseKey}, nil); err != nil {
			// An invalid, expired or exhausted license must not stop the proxy:
			// keep the current account and retry on the next start.
			o.Logger.Error("applying WARP+ license failed, continuing with the current account", "device_id", st.DeviceID, "error", err)
		} else {
			o.Logger.Info("applied WARP+ license", "device_id", st.DeviceID)
			// The account type changes with the license; unknown until refreshed.
			st.License, st.AccountType, refresh = o.LicenseKey, "", true
		}
	}
	if refresh {
		if err := c.refresh(ctx, st); err != nil {
			o.Logger.Warn("refreshing WARP device failed, using the cached configuration", "device_id", st.DeviceID, "error", err)
		}
	}
	if after, _ := json.Marshal(st); !bytes.Equal(before, after) {
		if err := writeState(o.Path, st); err != nil {
			return nil, err
		}
	}
	p, err := st.profile()
	if err != nil {
		return nil, fmt.Errorf("cfwarp: %s: %w", o.Path, err)
	}
	return p, nil
}

// register creates a new device with a fresh key and persists it right away,
// so a later failure never causes a second registration.
func register(ctx context.Context, c *client, o Options) (*state, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("cfwarp: generate key: %w", err)
	}
	var dev device
	body := registrationRequest(key.PublicKey().String(), o.DeviceModel, time.Now())
	if err := c.call(ctx, http.MethodPost, "/reg", "", body, &dev); err != nil {
		return nil, fmt.Errorf("cfwarp: register device: %w", err)
	}
	if dev.ID == "" || dev.Token == "" {
		return nil, errors.New("cfwarp: register device: answer lacks id or token")
	}
	st := &state{
		Version:     stateVersion,
		DeviceID:    dev.ID,
		AccessToken: dev.Token,
		PrivateKey:  key.String(),
		License:     dev.Account.License,
	}
	st.update(&dev) // an invalid config stays nil and is fetched again by Load
	if err := writeState(o.Path, st); err != nil {
		return nil, err
	}
	o.Logger.Info("registered WARP device", "device_id", st.DeviceID, "account_type", st.AccountType)

	// Like wgcf, give the device a random short name; purely cosmetic.
	name := make([]byte, 3)
	rand.Read(name)
	path := "/reg/" + st.DeviceID + "/account/reg/" + st.DeviceID
	err = c.call(ctx, http.MethodPatch, path, st.AccessToken, map[string]string{"name": fmt.Sprintf("%X", name)}, nil)
	// Cloudflare may answer 500 yet apply the name; wgcf ignores that too.
	if err != nil && !hasStatus(err, http.StatusInternalServerError) {
		o.Logger.Warn("naming WARP device failed", "device_id", st.DeviceID, "error", err)
	}
	return st, nil
}

// refresh updates the cached device config and account type from the API.
func (c *client) refresh(ctx context.Context, st *state) error {
	var dev device
	if err := c.call(ctx, http.MethodGet, "/reg/"+st.DeviceID, st.AccessToken, nil, &dev); err != nil {
		return err
	}
	return st.update(&dev)
}

// Unregister deletes this device at Cloudflare, then removes the file.
func Unregister(ctx context.Context, opts Options) error {
	o, err := opts.withDefaults()
	if err != nil {
		return err
	}
	st, err := readState(o.Path)
	if err != nil {
		return err
	}
	c, done := o.newClient(st.License)
	defer done()

	err = c.call(ctx, http.MethodDelete, "/reg/"+st.DeviceID, st.AccessToken, nil, nil)
	switch {
	case hasStatus(err, http.StatusNotFound):
		o.Logger.Info("WARP device was already deleted at Cloudflare", "device_id", st.DeviceID)
	case err != nil:
		return fmt.Errorf("cfwarp: unregister device: %w", err)
	}
	if err := os.Remove(o.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cfwarp: %w", err)
	}
	o.Logger.Info("unregistered WARP device", "device_id", st.DeviceID)
	return nil
}

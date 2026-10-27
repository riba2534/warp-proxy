package cfwarp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const stateVersion = 1

// state is the registration file. It holds secrets: written with mode 0600.
type state struct {
	Version     int           `json:"version"`
	DeviceID    string        `json:"device_id"`
	AccessToken string        `json:"access_token"`
	PrivateKey  string        `json:"private_key"`
	License     string        `json:"license,omitempty"`
	AccountType string        `json:"account_type,omitempty"`
	Config      *deviceConfig `json:"config,omitempty"` // last device config seen from the API
}

// deviceConfig is the WireGuard part of the device config, kept as the API
// returned it so the endpoint candidates are derived anew on every load.
type deviceConfig struct {
	PeerPublicKey string   `json:"peer_public_key"`
	Endpoint      endpoint `json:"endpoint"`
	AddressV4     string   `json:"address_v4"`
	AddressV6     string   `json:"address_v6,omitempty"`
}

// apply validates c and copies its WireGuard parameters into p.
func (c *deviceConfig) apply(p *Profile) error {
	if _, err := wgtypes.ParseKey(c.PeerPublicKey); err != nil {
		return errors.New("invalid peer public key")
	}
	v4, err := hostPrefix(c.AddressV4, true)
	if err != nil {
		return fmt.Errorf("invalid IPv4 address %q", c.AddressV4)
	}
	var v6 netip.Prefix
	if c.AddressV6 != "" {
		if v6, err = hostPrefix(c.AddressV6, false); err != nil {
			return fmt.Errorf("invalid IPv6 address %q", c.AddressV6)
		}
	}
	endpoints := c.Endpoint.candidates()
	if len(endpoints) == 0 {
		return errors.New("no WireGuard endpoint")
	}
	p.PeerPublicKey, p.Endpoints, p.AddressV4, p.AddressV6 = c.PeerPublicKey, endpoints, v4, v6
	return nil
}

// hostPrefix parses an interface address ("172.16.0.2", tolerating a prefix
// length) of the wanted family into a single-host prefix.
func hostPrefix(s string, v4 bool) (netip.Prefix, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		prefix, perr := netip.ParsePrefix(s)
		if perr != nil {
			return netip.Prefix{}, err
		}
		addr = prefix.Addr()
	}
	if addr.Is4() != v4 || addr.Is4In6() || addr.Zone() != "" {
		return netip.Prefix{}, errors.New("wrong address family")
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// update adopts the device config and account type of an API answer. An
// invalid config is an error and leaves s unchanged.
func (s *state) update(dev *device) error {
	if cfg := dev.deviceConfig(); cfg != nil {
		if err := cfg.apply(new(Profile)); err != nil {
			return fmt.Errorf("device config: %w", err)
		}
		s.Config = cfg
	}
	if dev.Account.AccountType != "" {
		s.AccountType = dev.Account.AccountType
	}
	return nil
}

func (s *state) profile() (*Profile, error) {
	if s.Config == nil {
		return nil, errors.New("no cached device configuration")
	}
	p := &Profile{PrivateKey: s.PrivateKey, AccountType: s.AccountType, DeviceID: s.DeviceID}
	if err := s.Config.apply(p); err != nil {
		return nil, err
	}
	return p, nil
}

// readState loads and validates the registration file. Errors wrap the
// os error, so a missing file satisfies errors.Is(err, fs.ErrNotExist).
// Messages never contain the secrets.
func readState(path string) (*state, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cfwarp: read registration: %w", err)
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("cfwarp: %s: %w", path, err)
	}
	switch {
	case st.Version != stateVersion:
		return nil, fmt.Errorf("cfwarp: %s: unsupported version %d", path, st.Version)
	case st.DeviceID == "" || st.AccessToken == "":
		return nil, fmt.Errorf("cfwarp: %s: missing device_id or access_token", path)
	}
	if _, err := wgtypes.ParseKey(st.PrivateKey); err != nil {
		return nil, fmt.Errorf("cfwarp: %s: invalid private_key", path)
	}
	if st.Config != nil {
		if _, err := st.profile(); err != nil {
			return nil, fmt.Errorf("cfwarp: %s: config: %w", path, err)
		}
	}
	return &st, nil
}

func writeState(path string, st *state) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, append(data, '\n')); err != nil {
		return fmt.Errorf("cfwarp: save registration: %w", err)
	}
	return nil
}

// writeFileAtomic replaces path with data via a 0600 temp file in the same
// directory (fsync, rename, fsync of the directory). Readers see either the
// old or the new content, never a partial file.
func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*") // created 0600
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	// Make the rename durable; some filesystems cannot sync a directory.
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

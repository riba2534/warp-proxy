//go:build !linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
)

var errUnsupported = fmt.Errorf("WireGuard tunnel requires Linux: %w", errors.ErrUnsupported)

// Tunnel cannot be brought up on this platform.
type Tunnel struct{}

func Up(context.Context, Config) (*Tunnel, error) { return nil, errUnsupported }

func (t *Tunnel) Status() (Status, error) { return Status{}, errUnsupported }

func (t *Tunnel) RotateEndpoint() (string, error) { return "", errUnsupported }

func (t *Tunnel) Close() error { return nil }

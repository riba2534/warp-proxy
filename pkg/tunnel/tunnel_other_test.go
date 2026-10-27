//go:build !linux

package tunnel

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedPlatform(t *testing.T) {
	tn, err := Up(context.Background(), validConfig(t))
	if tn != nil || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Up: %v %v", tn, err)
	}
	var zero Tunnel
	if _, err := zero.Status(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Status: %v", err)
	}
	if _, err := zero.RotateEndpoint(context.Background()); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("RotateEndpoint: %v", err)
	}
	if err := zero.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

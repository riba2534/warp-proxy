//go:build !linux

package proxy

import (
	"context"
	"errors"
	"testing"
)

// A public destination's socket fails in Control, before anything is sent.
func TestSetSocketMarkUnsupported(t *testing.T) {
	s := NewServer(Options{Mark: 1, Logger: testLogger(t)})
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, err := s.dial(ctx, "tcp", "203.0.113.1:80"); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("dial with a mark: %v, want errors.ErrUnsupported", err)
	}
}

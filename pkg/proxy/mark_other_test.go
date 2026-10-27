//go:build !linux

package proxy

import (
	"context"
	"errors"
	"testing"
)

func TestSetSocketMarkUnsupported(t *testing.T) {
	s := NewServer(Options{Mark: 1, AllowPrivate: true, Logger: testLogger(t)})
	if _, err := s.dial(context.Background(), "tcp", startUpstream(t, pong)); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("dial with a mark: %v, want errors.ErrUnsupported", err)
	}
}

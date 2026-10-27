//go:build linux

package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPickEndpointOrderAndWrap(t *testing.T) {
	candidates := []string{"a:1", "b:2", "c:3"}
	var tried []string
	resolve := func(_ context.Context, c string) (netip.AddrPort, error) {
		tried = append(tried, c)
		if c == "b:2" {
			return netip.AddrPort{}, errors.New("no such host")
		}
		return netip.MustParseAddrPort("192.0.2.1:" + c[2:]), nil
	}

	cases := []struct {
		start    int
		wantIdx  int
		wantAddr string
		wantTry  []string
	}{
		{0, 0, "192.0.2.1:1", []string{"a:1"}},
		{1, 2, "192.0.2.1:3", []string{"b:2", "c:3"}}, // unresolvable candidate skipped
		{3, 0, "192.0.2.1:1", []string{"a:1"}},        // past the end wraps
		{2, 2, "192.0.2.1:3", []string{"c:3"}},
	}
	for _, tc := range cases {
		tried = nil
		idx, ap, err := pickEndpoint(context.Background(), candidates, tc.start, resolve)
		if err != nil || idx != tc.wantIdx || ap.String() != tc.wantAddr || !slices.Equal(tried, tc.wantTry) {
			t.Fatalf("start %d: got %d %v %v tried %v", tc.start, idx, ap, err, tried)
		}
	}
}

func TestPickEndpointNoneResolve(t *testing.T) {
	calls := 0
	resolve := func(_ context.Context, c string) (netip.AddrPort, error) {
		calls++
		return netip.AddrPort{}, errors.New("fail " + c)
	}
	_, _, err := pickEndpoint(context.Background(), []string{"a:1", "b:2"}, 1, resolve)
	if err == nil || !strings.Contains(err.Error(), "fail a:1") || !strings.Contains(err.Error(), "fail b:2") {
		t.Fatalf("got %v", err)
	}
	if calls != 2 {
		t.Fatalf("each candidate should be tried once, got %d calls", calls)
	}
}

func TestEndpointResolutionIsBounded(t *testing.T) {
	oldTimeout, oldBudget := resolveTimeout, resolveBudget
	resolveTimeout, resolveBudget = 50*time.Millisecond, 120*time.Millisecond
	t.Cleanup(func() { resolveTimeout, resolveBudget = oldTimeout, oldBudget })

	lookups := 0
	r := resolver{
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			lookups++
			if _, ok := ctx.Deadline(); !ok {
				t.Errorf("lookup of %s has no deadline", host)
			}
			<-ctx.Done() // a resolver that never answers
			return nil, ctx.Err()
		},
		ipv6: func(netip.Addr) bool { return false },
	}
	candidates := []string{"a.example:1", "b.example:1", "c.example:1", "d.example:1", "162.159.192.1:2408"}
	start := time.Now()
	idx, ap, err := pickEndpoint(context.Background(), candidates, 0, r.resolve)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("resolution took %v", elapsed)
	}
	// The budget runs out during the third lookup; the IP literal is still used.
	if err != nil || idx != 4 || ap.String() != "162.159.192.1:2408" || lookups != 4 {
		t.Fatalf("got %d %v %v after %d lookups", idx, ap, err, lookups)
	}
}

func TestResolverAddressChoice(t *testing.T) {
	dual := []netip.Addr{netip.MustParseAddr("2606:4700:d0::a29f:c001"), netip.MustParseAddr("162.159.192.1")}
	cases := []struct {
		name      string
		candidate string
		addrs     []netip.Addr
		ipv6      bool
		want      string
		wantErr   string
	}{
		{name: "IPv4 literal", candidate: "162.159.192.1:2408", want: "162.159.192.1:2408"},
		{name: "IPv6 literal with route", candidate: "[2606:4700:d0::a29f:c001]:500", ipv6: true,
			want: "[2606:4700:d0::a29f:c001]:500"},
		{name: "IPv6 literal without route", candidate: "[2606:4700:d0::a29f:c001]:500", wantErr: "no IPv6 route"},
		{name: "hostname prefers IPv4 without IPv6", candidate: "engage.cloudflareclient.com:2408", addrs: dual,
			want: "162.159.192.1:2408"},
		{name: "hostname keeps resolver order with IPv6", candidate: "engage.cloudflareclient.com:2408", addrs: dual,
			ipv6: true, want: "[2606:4700:d0::a29f:c001]:2408"},
		{name: "mapped IPv4 is unmapped", candidate: "engage.cloudflareclient.com:2408",
			addrs: []netip.Addr{netip.MustParseAddr("::ffff:162.159.192.1")}, want: "162.159.192.1:2408"},
		{name: "IPv6-only name without IPv6", candidate: "v6.example:2408", addrs: dual[:1], wantErr: "no IPv6 route"},
		{name: "lookup failure", candidate: "missing.example:2408", wantErr: "resolve missing.example:2408"},
		{name: "bad candidate", candidate: "162.159.192.1", wantErr: "invalid endpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := resolver{
				lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
					if tc.addrs == nil {
						return nil, errors.New("no such host")
					}
					return tc.addrs, nil
				},
				ipv6: func(netip.Addr) bool { return tc.ipv6 },
			}
			got, err := r.resolve(context.Background(), tc.candidate)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got %v %v, want error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got.String() != tc.want {
				t.Fatalf("got %v %v, want %s", got, err, tc.want)
			}
		})
	}
}

package cfwarp

import (
	"slices"
	"testing"
)

func TestEndpointCandidates(t *testing.T) {
	for _, tc := range []struct {
		name string
		ep   endpoint
		want []string
	}{
		{
			name: "host first, then v4 and v6 with every port",
			ep:   endpoint{Host: "engage.cloudflareclient.com:2408", V4: "162.159.192.1:0", V6: "[2606:4700:d0::a29f:c001]:0", Ports: []int{2408, 500, 1701, 4500}},
			want: []string{
				"engage.cloudflareclient.com:2408",
				"162.159.192.1:2408", "162.159.192.1:500", "162.159.192.1:1701", "162.159.192.1:4500",
				"[2606:4700:d0::a29f:c001]:2408", "[2606:4700:d0::a29f:c001]:500", "[2606:4700:d0::a29f:c001]:1701", "[2606:4700:d0::a29f:c001]:4500",
			},
		},
		{
			name: "no host: v4 with the first API port, API ports before defaults, duplicates dropped",
			ep:   endpoint{V4: "162.159.192.1", V6: "2606:4700:d0::a29f:c001", Ports: []int{4500, 0, 4500, 70000, 2408}},
			want: []string{
				"162.159.192.1:4500", "162.159.192.1:2408", "162.159.192.1:500", "162.159.192.1:1701",
				"[2606:4700:d0::a29f:c001]:4500", "[2606:4700:d0::a29f:c001]:2408", "[2606:4700:d0::a29f:c001]:500", "[2606:4700:d0::a29f:c001]:1701",
			},
		},
		{
			name: "v6 only, default ports",
			ep:   endpoint{V6: "[2606:4700:d0::a29f:c001]:0"},
			want: []string{
				"[2606:4700:d0::a29f:c001]:2408", "[2606:4700:d0::a29f:c001]:500", "[2606:4700:d0::a29f:c001]:1701", "[2606:4700:d0::a29f:c001]:4500",
			},
		},
		{
			name: "host without port or with the placeholder port",
			ep:   endpoint{Host: "engage.cloudflareclient.com", V4: "162.159.192.1:0", Ports: []int{500}},
			want: []string{
				"engage.cloudflareclient.com:500",
				"162.159.192.1:500", "162.159.192.1:2408", "162.159.192.1:1701", "162.159.192.1:4500",
			},
		},
		{
			name: "host equal to a later candidate is listed once",
			ep:   endpoint{Host: "162.159.192.1:0", V4: "162.159.192.1:0", Ports: []int{2408}},
			want: []string{"162.159.192.1:2408", "162.159.192.1:500", "162.159.192.1:1701", "162.159.192.1:4500"},
		},
		{name: "nothing", ep: endpoint{Ports: []int{2408}}, want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ep.candidates(); !slices.Equal(got, tc.want) {
				t.Errorf("candidates =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

func TestErrorDetailRedactsSecrets(t *testing.T) {
	c := &client{licenses: []string{"", testLicense}}
	body := []byte(`{"success":false,"errors":[{"code":1,"message":"bad token ` + testToken + `"},{"code":2,"message":"license ` + testLicense + ` exhausted"}]}`)
	want := "bad token [REDACTED]; license [REDACTED] exhausted"
	if got := c.errorDetail(body, testToken); got != want {
		t.Errorf("detail = %q, want %q", got, want)
	}
	if got := c.errorDetail([]byte("<html>"+testToken+"</html>"), testToken); got != "" {
		t.Errorf("detail of a non-JSON body = %q, want empty", got)
	}
}

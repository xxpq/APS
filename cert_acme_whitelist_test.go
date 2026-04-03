package main

import "testing"

func TestIsHostInACMEWhitelist(t *testing.T) {
	acmeDomainsMutex.Lock()
	originalSet := acmeDomainSet
	acmeDomainSet = map[string]struct{}{
		"a.l-l.cn":        {},
		"*.trusted.local": {},
	}
	acmeDomainsMutex.Unlock()

	t.Cleanup(func() {
		acmeDomainsMutex.Lock()
		acmeDomainSet = originalSet
		acmeDomainsMutex.Unlock()
	})

	cases := []struct {
		name string
		host string
		want bool
	}{
		{name: "exact-domain", host: "a.l-l.cn", want: true},
		{name: "exact-domain-with-port", host: "a.l-l.cn:443", want: true},
		{name: "exact-domain-mixed-case", host: "A.L-L.CN", want: true},
		{name: "exact-domain-trailing-dot", host: "a.l-l.cn.", want: true},
		{name: "wildcard-subdomain", host: "edge.trusted.local", want: true},
		{name: "wildcard-deep-subdomain", host: "x.y.trusted.local", want: true},
		{name: "not-allowed-domain", host: "untrusted.local", want: false},
		{name: "empty", host: "", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isHostInACMEWhitelist(tc.host)
			if got != tc.want {
				t.Fatalf("isHostInACMEWhitelist(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

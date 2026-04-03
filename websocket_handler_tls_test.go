package main

import "testing"

func TestShouldUseLegacyBackendTLS(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		insecureMode bool
		want         bool
	}{
		{name: "insecure forces legacy", host: "example.com", insecureMode: true, want: true},
		{name: "private ipv4", host: "10.1.105.33", insecureMode: false, want: true},
		{name: "loopback", host: "127.0.0.1", insecureMode: false, want: true},
		{name: "public ipv4", host: "8.8.8.8", insecureMode: false, want: false},
		{name: "hostname without insecure", host: "vps.sucdri.p-q.co", insecureMode: false, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldUseLegacyBackendTLS(tc.host, tc.insecureMode)
			if got != tc.want {
				t.Fatalf("shouldUseLegacyBackendTLS(%q, %v) = %v, want %v", tc.host, tc.insecureMode, got, tc.want)
			}
		})
	}
}

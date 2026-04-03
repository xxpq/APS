package main

import (
	"net/http"
	"testing"
)

func TestShouldAllowInsecureBackendTLS(t *testing.T) {
	originalManager := connectionManager
	t.Cleanup(func() {
		connectionManager = originalManager
	})

	cm := NewConnectionManager("cid")
	cm.AddSeedServer(cm.ParseServerAddress("10.10.10.10:443", true))
	connectionManager = cm

	tests := []struct {
		name    string
		rawURL  string
		header  string
		allowed bool
	}{
		{
			name:    "internal self-signed backend allowed",
			rawURL:  "https://10.10.10.20:8443/api",
			allowed: true,
		},
		{
			name:    "aps host always blocked even if internal",
			rawURL:  "https://10.10.10.10:443/.api",
			allowed: false,
		},
		{
			name:    "mapping exemption allows public host",
			rawURL:  "https://example.com/path",
			header:  "true",
			allowed: true,
		},
		{
			name:    "mapping exemption still blocked for aps host",
			rawURL:  "https://10.10.10.10:443/.api",
			header:  "true",
			allowed: false,
		},
		{
			name:    "non-https never uses insecure skip verify",
			rawURL:  "http://10.10.10.20:8080/api",
			header:  "true",
			allowed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.rawURL, nil)
			if err != nil {
				t.Fatalf("new request failed: %v", err)
			}
			if tc.header != "" {
				req.Header.Set(apsInsecureHeader, tc.header)
			}

			got := shouldAllowInsecureBackendTLS(req)
			if got != tc.allowed {
				t.Fatalf("shouldAllowInsecureBackendTLS(%s) = %v, want %v", tc.rawURL, got, tc.allowed)
			}
		})
	}
}

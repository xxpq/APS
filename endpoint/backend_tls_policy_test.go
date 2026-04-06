package main

import (
	"crypto/tls"
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

func TestCloneInsecureBackendTransportTLSCompatibility(t *testing.T) {
	base := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	insecureTransport := cloneInsecureBackendTransport(base)
	if insecureTransport.TLSClientConfig == nil {
		t.Fatalf("TLSClientConfig should not be nil")
	}
	if !insecureTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify should be true")
	}
	if insecureTransport.TLSClientConfig.MinVersion != tls.VersionTLS10 {
		t.Fatalf("MinVersion = %v, want %v", insecureTransport.TLSClientConfig.MinVersion, tls.VersionTLS10)
	}
	if base.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("base transport should remain unchanged, got MinVersion=%v", base.TLSClientConfig.MinVersion)
	}
}

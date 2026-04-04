package main

import "testing"

func TestExtractGridRequestTargetHTTPS(t *testing.T) {
	host, port, useTLS, err := extractGridRequestTarget("https://example.com/path?q=1")
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if host != "example.com" || port != 443 || !useTLS {
		t.Fatalf("unexpected result host=%s port=%d tls=%v", host, port, useTLS)
	}
}

func TestExtractGridRequestTargetHTTPWithCustomPort(t *testing.T) {
	host, port, useTLS, err := extractGridRequestTarget("http://127.0.0.1:18080/api")
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if host != "127.0.0.1" || port != 18080 || useTLS {
		t.Fatalf("unexpected result host=%s port=%d tls=%v", host, port, useTLS)
	}
}

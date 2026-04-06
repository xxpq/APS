package main

import (
	"strings"
	"testing"
)

func TestCollectServiceProxyEnvVarsUppercase(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://10.1.105.105:7890")
	t.Setenv("HTTPS_PROXY", "http://10.1.105.105:7890")
	t.Setenv("ALL_PROXY", "socks5://10.1.105.105:7890")
	t.Setenv("NO_PROXY", "localhost,127.0.0.1,.corp.local")
	t.Setenv(endpointTLSPinTokenEnv, "apspt1.testtoken")
	env := collectServiceProxyEnvVars()
	if env == nil {
		t.Fatal("expected non-nil env vars")
	}
	if env["HTTP_PROXY"] != "http://10.1.105.105:7890" || env["http_proxy"] != "http://10.1.105.105:7890" {
		t.Fatalf("HTTP_PROXY not persisted correctly: %#v", env)
	}
	if env["HTTPS_PROXY"] != "http://10.1.105.105:7890" || env["https_proxy"] != "http://10.1.105.105:7890" {
		t.Fatalf("HTTPS_PROXY not persisted correctly: %#v", env)
	}
	if env["ALL_PROXY"] != "socks5://10.1.105.105:7890" || env["all_proxy"] != "socks5://10.1.105.105:7890" {
		t.Fatalf("ALL_PROXY not persisted correctly: %#v", env)
	}
	if env["NO_PROXY"] != "localhost,127.0.0.1,.corp.local" || env["no_proxy"] != "localhost,127.0.0.1,.corp.local" {
		t.Fatalf("NO_PROXY not persisted correctly: %#v", env)
	}
	if env[endpointTLSPinTokenEnv] != "apspt1.testtoken" || env[strings.ToLower(endpointTLSPinTokenEnv)] != "apspt1.testtoken" {
		t.Fatalf("APS token env not persisted correctly: %#v", env)
	}
}

func TestCollectServiceProxyEnvVarsLowercaseFallback(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("http_proxy", "http://proxy.local:8080")
	t.Setenv("https_proxy", "http://proxy.local:8443")
	t.Setenv("all_proxy", "socks5://proxy.local:1080")
	t.Setenv("no_proxy", "10.0.0.0/8,.local")

	env := collectServiceProxyEnvVars()
	if env == nil {
		t.Fatal("expected non-nil env vars")
	}
	if env["HTTP_PROXY"] != "http://proxy.local:8080" {
		t.Fatalf("expected uppercase HTTP_PROXY fallback from lowercase, got %#v", env)
	}
	if env["HTTPS_PROXY"] != "http://proxy.local:8443" {
		t.Fatalf("expected uppercase HTTPS_PROXY fallback from lowercase, got %#v", env)
	}
	if env["ALL_PROXY"] != "socks5://proxy.local:1080" {
		t.Fatalf("expected uppercase ALL_PROXY fallback from lowercase, got %#v", env)
	}
	if env["NO_PROXY"] != "10.0.0.0/8,.local" {
		t.Fatalf("expected uppercase NO_PROXY fallback from lowercase, got %#v", env)
	}
}

func TestCollectServiceProxyEnvVarsEmpty(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")
	t.Setenv("all_proxy", "")
	t.Setenv("no_proxy", "")

	env := collectServiceProxyEnvVars()
	if env != nil {
		t.Fatalf("expected nil env vars when nothing configured, got %#v", env)
	}
}

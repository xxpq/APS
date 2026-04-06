package main

import (
	"net/url"
	"testing"
)

func TestEndpointProxyURLForTargetUsesAllProxyFallback(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("ALL_PROXY", "http://proxy.local:8080")

	target := &url.URL{Scheme: "https", Host: "a.l-l.cn:443"}
	proxyURL, err := endpointProxyURLForTarget(target)
	if err != nil {
		t.Fatalf("resolve proxy failed: %v", err)
	}
	if proxyURL == nil {
		t.Fatal("expected non-nil proxy URL")
	}
	if proxyURL.Host != "proxy.local:8080" {
		t.Fatalf("unexpected proxy host: %s", proxyURL.Host)
	}
}

func TestEndpointProxyURLForTargetPrefersHTTPSProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "http://secure-proxy.local:8443")
	t.Setenv("NO_PROXY", "")
	t.Setenv("ALL_PROXY", "http://fallback.local:8080")

	target := &url.URL{Scheme: "https", Host: "a.l-l.cn:443"}
	proxyURL, err := endpointProxyURLForTarget(target)
	if err != nil {
		t.Fatalf("resolve proxy failed: %v", err)
	}
	if proxyURL == nil {
		t.Fatal("expected non-nil proxy URL")
	}
	if proxyURL.Host != "secure-proxy.local:8443" {
		t.Fatalf("unexpected proxy host: %s", proxyURL.Host)
	}
}

func TestEndpointProxyURLForTargetRespectsNoProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "a.l-l.cn")
	t.Setenv("ALL_PROXY", "http://proxy.local:8080")

	target := &url.URL{Scheme: "https", Host: "a.l-l.cn:443"}
	proxyURL, err := endpointProxyURLForTarget(target)
	if err != nil {
		t.Fatalf("resolve proxy failed: %v", err)
	}
	if proxyURL != nil {
		t.Fatalf("expected no proxy due to NO_PROXY, got %s", proxyURL.String())
	}
}

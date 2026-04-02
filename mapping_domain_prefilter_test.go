package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMapRequest_DomainPrefilterAllowsKnownHost(t *testing.T) {
	globalRouteCache.clear()

	const serverName = "test_server"
	cfg := &Config{
		Mappings: []Mapping{
			makeTestMapping(serverName, "https://known.example.com/*", "https://backend.internal/*"),
		},
	}

	refreshDomainIndexes(cfg)
	t.Cleanup(func() {
		refreshDomainIndexes(nil)
	})

	proxy := &MapRemoteProxy{
		config:     cfg,
		serverName: serverName,
	}

	req := httptest.NewRequest(http.MethodGet, "https://known.example.com/api/v1", nil)
	targetURL, matched, _, _ := proxy.mapRequest(req)

	if !matched {
		t.Fatalf("expected known host to match mapping, got target=%s", targetURL)
	}
	if targetURL != "https://backend.internal/api/v1" {
		t.Fatalf("unexpected target URL: %s", targetURL)
	}
}

func TestMapRequest_DomainPrefilterRejectsUnknownHost(t *testing.T) {
	globalRouteCache.clear()

	const serverName = "test_server"
	cfg := &Config{
		Mappings: []Mapping{
			makeTestMapping(serverName, "https://known.example.com/*", "https://backend.internal/*"),
		},
	}

	refreshDomainIndexes(cfg)
	t.Cleanup(func() {
		refreshDomainIndexes(nil)
	})

	proxy := &MapRemoteProxy{
		config:     cfg,
		serverName: serverName,
	}

	req := httptest.NewRequest(http.MethodGet, "https://unknown.example.com/api/v1", nil)
	targetURL, matched, _, _ := proxy.mapRequest(req)

	if matched {
		t.Fatalf("expected unknown host to be fast-rejected, got target=%s", targetURL)
	}
	if targetURL != "https://unknown.example.com/api/v1" {
		t.Fatalf("expected original URL on rejection, got %s", targetURL)
	}
}

func TestMapRequest_DomainPrefilterSkipsWhenIndexFromDifferentConfig(t *testing.T) {
	globalRouteCache.clear()

	const serverName = "test_server"

	cfgA := &Config{
		Mappings: []Mapping{
			makeTestMapping(serverName, "https://alpha.example.com/*", "https://backend-a.internal/*"),
		},
	}
	refreshDomainIndexes(cfgA)
	t.Cleanup(func() {
		refreshDomainIndexes(nil)
	})

	cfgB := &Config{
		Mappings: []Mapping{
			makeTestMapping(serverName, "https://beta.example.com/*", "https://backend-b.internal/*"),
		},
	}

	proxy := &MapRemoteProxy{
		config:     cfgB,
		serverName: serverName,
	}

	req := httptest.NewRequest(http.MethodGet, "https://beta.example.com/ok", nil)
	targetURL, matched, _, _ := proxy.mapRequest(req)

	if !matched {
		t.Fatalf("expected match to proceed when index is from another config, got target=%s", targetURL)
	}
	if targetURL != "https://backend-b.internal/ok" {
		t.Fatalf("unexpected target URL: %s", targetURL)
	}
}

func TestMapRequest_DomainPrefilterDisabledForDynamicHostRules(t *testing.T) {
	globalRouteCache.clear()

	const serverName = "test_server"
	regexFrom := `https://(.*)\.example\.com/.*`

	cfg := &Config{
		Mappings: []Mapping{
			{
				serverNames: []string{serverName},
				fromConfig: &EndpointConfig{
					URLs: []string{regexFrom},
				},
				toConfig: &EndpointConfig{
					URLs: []string{regexFrom},
				},
			},
		},
	}

	refreshDomainIndexes(cfg)
	t.Cleanup(func() {
		refreshDomainIndexes(nil)
	})

	proxy := &MapRemoteProxy{
		config:     cfg,
		serverName: serverName,
	}

	req := httptest.NewRequest(http.MethodGet, "https://foo.example.com/path", nil)
	targetURL, matched, _, _ := proxy.mapRequest(req)

	if !matched {
		t.Fatalf("expected regex host rule to bypass fast-reject and match, got target=%s", targetURL)
	}
}

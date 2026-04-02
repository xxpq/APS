package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func makeTestMapping(serverName, fromURL, toURL string) Mapping {
	parsedFrom, _ := url.Parse(fromURL)
	parsedTo, _ := url.Parse(toURL)

	return Mapping{
		serverNames: []string{serverName},
		fromConfig: &EndpointConfig{
			URLs:       []string{fromURL},
			ParsedURLs: []*url.URL{parsedFrom},
		},
		toConfig: &EndpointConfig{
			URLs:       []string{toURL},
			ParsedURLs: []*url.URL{parsedTo},
		},
	}
}

func TestMapRequest_WSSMappingRequiresUpgrade(t *testing.T) {
	globalRouteCache.clear()

	const serverName = "test_server"
	cfg := &Config{
		Mappings: []Mapping{
			makeTestMapping(serverName, "wss://vps.sucdri.p-q.co/*", "wss://10.1.105.33/*"),
		},
	}
	proxy := &MapRemoteProxy{
		config:     cfg,
		serverName: serverName,
	}

	req := httptest.NewRequest(http.MethodGet, "https://vps.sucdri.p-q.co/ui/", nil)

	targetURL, matched, _, _ := proxy.mapRequest(req)
	if matched {
		t.Fatalf("expected no match for plain HTTPS request, got match to %s", targetURL)
	}
	if targetURL != "https://vps.sucdri.p-q.co/ui/" {
		t.Fatalf("expected original URL, got %s", targetURL)
	}
}

func TestMapRequest_WSSMappingMatchesWebSocketUpgrade(t *testing.T) {
	globalRouteCache.clear()

	const serverName = "test_server"
	cfg := &Config{
		Mappings: []Mapping{
			makeTestMapping(serverName, "wss://vps.sucdri.p-q.co/*", "wss://10.1.105.33/*"),
		},
	}
	proxy := &MapRemoteProxy{
		config:     cfg,
		serverName: serverName,
	}

	req := httptest.NewRequest(http.MethodGet, "https://vps.sucdri.p-q.co/ui/", nil)
	req.Header.Set("Connection", "keep-alive, Upgrade")
	req.Header.Set("Upgrade", "websocket")

	targetURL, matched, _, _ := proxy.mapRequest(req)
	if !matched {
		t.Fatal("expected wss mapping to match websocket upgrade request")
	}
	if targetURL != "wss://10.1.105.33/ui/" {
		t.Fatalf("expected wss target URL, got %s", targetURL)
	}
}

func TestMapRequest_CacheSeparatesWebSocketAndPlainHTTP(t *testing.T) {
	globalRouteCache.clear()

	const serverName = "test_server"
	cfg := &Config{
		Mappings: []Mapping{
			makeTestMapping(serverName, "wss://vps.sucdri.p-q.co/*", "wss://10.1.105.33/*"),
		},
	}
	proxy := &MapRemoteProxy{
		config:     cfg,
		serverName: serverName,
	}

	wsReq := httptest.NewRequest(http.MethodGet, "https://vps.sucdri.p-q.co/ui/", nil)
	wsReq.Header.Set("Connection", "Upgrade")
	wsReq.Header.Set("Upgrade", "websocket")

	wsTarget, wsMatched, _, _ := proxy.mapRequest(wsReq)
	if !wsMatched || wsTarget != "wss://10.1.105.33/ui/" {
		t.Fatalf("expected websocket request to hit wss mapping, got matched=%v target=%s", wsMatched, wsTarget)
	}

	plainReq := httptest.NewRequest(http.MethodGet, "https://vps.sucdri.p-q.co/ui/", nil)
	plainTarget, plainMatched, _, _ := proxy.mapRequest(plainReq)
	if plainMatched {
		t.Fatalf("expected plain request not to reuse websocket cache entry, got %s", plainTarget)
	}
	if plainTarget != "https://vps.sucdri.p-q.co/ui/" {
		t.Fatalf("expected original URL for plain request, got %s", plainTarget)
	}
}

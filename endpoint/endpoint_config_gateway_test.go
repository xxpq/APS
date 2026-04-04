package main

import (
	"encoding/json"
	"testing"
)

func TestEndpointRuntimeConfigGatewayDefaults(t *testing.T) {
	raw := []byte(`{"id":"cid-1","tunnelName":"t1","endpointName":"e1","sessionCredential":"x","kdfVersion":"v1","kdfSalt":"s"}`)
	var cfg EndpointRuntimeConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !cfg.GatewayDiscovery {
		t.Fatal("expected gatewayDiscovery default to true")
	}
	if cfg.GatewayDiscoverPort != defaultGatewayDiscoverPort {
		t.Fatalf("expected default gatewayDiscoverPort=%d got %d", defaultGatewayDiscoverPort, cfg.GatewayDiscoverPort)
	}
}

func TestEndpointRuntimeConfigGatewayExplicitOverride(t *testing.T) {
	raw := []byte(`{"id":"cid-1","tunnelName":"t1","endpointName":"e1","sessionCredential":"x","kdfVersion":"v1","kdfSalt":"s","gatewayDiscovery":false,"gatewayDiscoverPort":41001}`)
	var cfg EndpointRuntimeConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if cfg.GatewayDiscovery {
		t.Fatal("expected explicit gatewayDiscovery=false to be preserved")
	}
	if cfg.GatewayDiscoverPort != 41001 {
		t.Fatalf("expected gatewayDiscoverPort=41001 got %d", cfg.GatewayDiscoverPort)
	}
}

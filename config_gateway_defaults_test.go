package main

import (
	"encoding/json"
	"testing"
)

func TestEndpointConfigAPSGatewayDefaults(t *testing.T) {
	raw := []byte(`{"tunnelName":"t1","endpointName":"e1"}`)
	var cfg EndpointConfig_APS
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !cfg.GatewayDiscovery {
		t.Fatal("expected gatewayDiscovery default to true")
	}
	if cfg.GatewayDiscoverPort != DefaultGatewayDiscoverPort {
		t.Fatalf("expected default gatewayDiscoverPort=%d got %d", DefaultGatewayDiscoverPort, cfg.GatewayDiscoverPort)
	}
}

func TestEndpointConfigAPSGatewayExplicitOverride(t *testing.T) {
	raw := []byte(`{"tunnelName":"t1","endpointName":"e1","gatewayDiscovery":false,"gatewayDiscoverPort":40001}`)
	var cfg EndpointConfig_APS
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if cfg.GatewayDiscovery {
		t.Fatal("expected explicit gatewayDiscovery=false to be preserved")
	}
	if cfg.GatewayDiscoverPort != 40001 {
		t.Fatalf("expected explicit gatewayDiscoverPort=40001 got %d", cfg.GatewayDiscoverPort)
	}
}

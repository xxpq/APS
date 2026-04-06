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

func TestEndpointRuntimeConfigGatewayAddressCommaSeparated(t *testing.T) {
	raw := []byte(`{"id":"cid-1","tunnelName":"t1","endpointName":"e1","sessionCredential":"x","kdfVersion":"v1","kdfSalt":"s","gatewayAddress":"10.2.2.2:37990,10.2.2.3:37990"}`)
	var cfg EndpointRuntimeConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	gateways := normalizeEndpointGatewayAddresses(cfg.GatewayAddress)
	if len(gateways) != 2 {
		t.Fatalf("expected canonical gatewayAddress with 2 entries, got %v", gateways)
	}
	if cfg.GatewayAddress != "10.2.2.2:37990,10.2.2.3:37990" {
		t.Fatalf("expected canonical gatewayAddress list, got %s", cfg.GatewayAddress)
	}
}

func TestNormalizeEndpointGatewayAddressesFromSingleField(t *testing.T) {
	got := normalizeEndpointGatewayAddresses("10.2.2.2:37990;10.2.2.3:37990 10.2.2.2:37990")
	if len(got) != 2 {
		t.Fatalf("expected 2 deduplicated addresses, got %v", got)
	}
	if got[0] != "10.2.2.2:37990" || got[1] != "10.2.2.3:37990" {
		t.Fatalf("unexpected gateway list order/content: %v", got)
	}
}

func TestEndpointRuntimeConfigGatewayAddressArray(t *testing.T) {
	raw := []byte(`{"id":"cid-1","tunnelName":"t1","endpointName":"e1","sessionCredential":"x","kdfVersion":"v1","kdfSalt":"s","gatewayAddress":["10.2.2.2:37990","10.2.2.3:37990"]}`)
	var cfg EndpointRuntimeConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if cfg.GatewayAddress != "10.2.2.2:37990,10.2.2.3:37990" {
		t.Fatalf("expected canonical gatewayAddress list, got %s", cfg.GatewayAddress)
	}
}

func TestConfigUpdatePayloadGatewayAddressArray(t *testing.T) {
	raw := []byte(`{"gatewayAddress":["10.3.3.3:37990","10.3.3.4:37990"]}`)
	var payload ConfigUpdatePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if payload.GatewayAddress != "10.3.3.3:37990,10.3.3.4:37990" {
		t.Fatalf("expected canonical gatewayAddress list, got %s", payload.GatewayAddress)
	}
}

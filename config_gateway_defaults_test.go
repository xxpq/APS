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

func TestEndpointConfigAPSGatewayAddressCommaSeparated(t *testing.T) {
	raw := []byte(`{"tunnelName":"t1","endpointName":"e1","gatewayAddress":"10.2.2.2:37990,10.2.2.3:37990"}`)
	var cfg EndpointConfig_APS
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	gateways := normalizeAPSConfiguredGatewayAddresses(cfg.GatewayAddress)
	if len(gateways) != 2 {
		t.Fatalf("expected canonical gatewayAddress with 2 entries, got %v", gateways)
	}
	if cfg.GatewayAddress != "10.2.2.2:37990,10.2.2.3:37990" {
		t.Fatalf("expected canonical gatewayAddress list, got %s", cfg.GatewayAddress)
	}
}

func TestNormalizeAPSGatewayAddressesFromSingleField(t *testing.T) {
	got := normalizeAPSConfiguredGatewayAddresses("10.2.2.2:37990;10.2.2.3:37990 10.2.2.2:37990")
	if len(got) != 2 {
		t.Fatalf("expected 2 deduplicated addresses, got %v", got)
	}
	if got[0] != "10.2.2.2:37990" || got[1] != "10.2.2.3:37990" {
		t.Fatalf("unexpected gateway list order/content: %v", got)
	}
}

func TestEndpointConfigAPSGatewayAddressArray(t *testing.T) {
	raw := []byte(`{"tunnelName":"t1","endpointName":"e1","gatewayAddress":["10.2.2.2:37990","10.2.2.3:37990"]}`)
	var cfg EndpointConfig_APS
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if cfg.GatewayAddress != "10.2.2.2:37990,10.2.2.3:37990" {
		t.Fatalf("expected canonical gatewayAddress list, got %s", cfg.GatewayAddress)
	}
}

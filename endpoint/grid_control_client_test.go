package main

import (
	"os"
	"testing"
)

func TestEndpointGridListenPort(t *testing.T) {
	if got := endpointGridListenPort(ImmutableConnectionContext{}); got != 0 {
		t.Fatalf("expected default listen port 0, got %d", got)
	}
	if got := endpointGridListenPort(ImmutableConnectionContext{GatewayListen: "0.0.0.0:19090"}); got != 19090 {
		t.Fatalf("expected parsed listen port 19090, got %d", got)
	}
}

func TestCollectEndpointGridICECandidatesEnvOnly(t *testing.T) {
	prevCandidates := os.Getenv("APS_GRID_ICE_CANDIDATES")
	prevPorts := os.Getenv("APS_GRID_ICE_LISTEN_PORTS")
	t.Cleanup(func() {
		_ = os.Setenv("APS_GRID_ICE_CANDIDATES", prevCandidates)
		_ = os.Setenv("APS_GRID_ICE_LISTEN_PORTS", prevPorts)
	})
	if err := os.Setenv("APS_GRID_ICE_CANDIDATES", "203.0.113.10:443, 203.0.113.10:443 ,turn:turn.example.com:3478?transport=udp"); err != nil {
		t.Fatalf("set env failed: %v", err)
	}
	if err := os.Setenv("APS_GRID_ICE_LISTEN_PORTS", ""); err != nil {
		t.Fatalf("set env failed: %v", err)
	}

	candidates := collectEndpointGridICECandidates(ImmutableConnectionContext{})
	if len(candidates) != 2 {
		t.Fatalf("expected deduped 2 candidates from env, got %v", candidates)
	}
}

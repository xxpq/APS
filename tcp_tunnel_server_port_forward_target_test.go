package main

import "testing"

func TestFindPortForwardTargetEndpointLockedMatchesConfigID(t *testing.T) {
	server := &TCPTunnelServer{
		endpoints: map[string]*TCPEndpoint{
			"src": {
				ID:           "src",
				TunnelName:   "tunnel-a",
				EndpointName: "my_pc",
				ConfigID:     "my_pc",
			},
			"dst": {
				ID:           "dst",
				TunnelName:   "tunnel-a",
				EndpointName: "kcy_gpu",
				ConfigID:     "alipay",
			},
		},
	}

	got := server.findPortForwardTargetEndpointLocked("tunnel-a", "alipay")
	if got == nil {
		t.Fatalf("expected target endpoint to be resolved by cid")
	}
	if got.ID != "dst" {
		t.Fatalf("expected target endpoint id=dst, got %s", got.ID)
	}
}

func TestEndpointMatchesPortForwardTargetEndpointNameOrCID(t *testing.T) {
	endpoint := &TCPEndpoint{
		EndpointName: "node-A",
		ConfigID:     "cid-123",
	}
	if !endpointMatchesPortForwardTarget(endpoint, "node-A") {
		t.Fatalf("expected endpointName to match")
	}
	if !endpointMatchesPortForwardTarget(endpoint, "cid-123") {
		t.Fatalf("expected cid to match")
	}
	if endpointMatchesPortForwardTarget(endpoint, "cid-999") {
		t.Fatalf("unexpected match on unrelated target")
	}
}


package main

import "testing"

func TestIsLocalGatewayNodeIDMatchesCIDAndEndpointName(t *testing.T) {
	oldCID := *configID
	oldName := *name
	oldRuntime := runtimeConfig
	endpointGatewayRuntime.mu.Lock()
	oldGatewayNodeID := endpointGatewayRuntime.nodeID
	endpointGatewayRuntime.nodeID = ""
	endpointGatewayRuntime.mu.Unlock()
	defer func() {
		*configID = oldCID
		*name = oldName
		runtimeConfig = oldRuntime
		endpointGatewayRuntime.mu.Lock()
		endpointGatewayRuntime.nodeID = oldGatewayNodeID
		endpointGatewayRuntime.mu.Unlock()
	}()

	*configID = "alipay"
	*name = "kcy_gpu"
	runtimeConfig = nil

	if !isLocalGatewayNodeID("alipay") {
		t.Fatalf("expected local cid alias to match")
	}
	if !isLocalGatewayNodeID("kcy_gpu") {
		t.Fatalf("expected local endpointName alias to match")
	}
	if isLocalGatewayNodeID("other-node") {
		t.Fatalf("unexpected match for unrelated node id")
	}
}

func TestLocalPrimaryGatewayNodeIDPrefersRuntimeGatewayNode(t *testing.T) {
	oldCID := *configID
	oldName := *name
	oldRuntime := runtimeConfig
	endpointGatewayRuntime.mu.Lock()
	oldGatewayNodeID := endpointGatewayRuntime.nodeID
	endpointGatewayRuntime.nodeID = "runtime-node"
	endpointGatewayRuntime.mu.Unlock()
	defer func() {
		*configID = oldCID
		*name = oldName
		runtimeConfig = oldRuntime
		endpointGatewayRuntime.mu.Lock()
		endpointGatewayRuntime.nodeID = oldGatewayNodeID
		endpointGatewayRuntime.mu.Unlock()
	}()

	*configID = "cid-node"
	*name = "name-node"
	runtimeConfig = nil

	if got := localPrimaryGatewayNodeID(); got != "runtime-node" {
		t.Fatalf("expected runtime gateway node id, got %q", got)
	}
}


package main

import (
	"testing"
	"time"
)

func resetGatewayRuntimeStateForTest() {
	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.started = false
	endpointGatewayRuntime.listenAddr = ""
	endpointGatewayRuntime.nodeID = ""
	endpointGatewayRuntime.token = ""
	endpointGatewayRuntime.discoverPort = 0
	endpointGatewayRuntime.listener = nil
	endpointGatewayRuntime.discoveryConn = nil
	endpointGatewayRuntime.peers = make(map[string]gatewayPeerInfo)
	endpointGatewayRuntime.peerMetrics = make(map[string]gatewayPeerMetric)
	endpointGatewayRuntime.targetRoutes = make(map[string]gatewayTargetRoute)
	endpointGatewayRuntime.directTargets = make(map[string]struct{})
	endpointGatewayRuntime.mu.Unlock()
}

func TestParseGatewayConnectLineExtended(t *testing.T) {
	line := "APS-GW/1 CONNECT 203.0.113.10:443 token=abc origin=node-a path=node-a,node-b hop=6\n"
	target, meta, err := parseGatewayConnectLine(line)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if target != "203.0.113.10:443" {
		t.Fatalf("unexpected target: %s", target)
	}
	if meta.Token != "abc" {
		t.Fatalf("unexpected token: %s", meta.Token)
	}
	if meta.OriginNodeID != "node-a" {
		t.Fatalf("unexpected origin: %s", meta.OriginNodeID)
	}
	if len(meta.Path) != 2 || meta.Path[0] != "node-a" || meta.Path[1] != "node-b" {
		t.Fatalf("unexpected path: %#v", meta.Path)
	}
	if meta.HopLimit != 6 {
		t.Fatalf("unexpected hop limit: %d", meta.HopLimit)
	}
}

func TestParseGatewayConnectLineLegacyToken(t *testing.T) {
	line := "APS-GW/1 CONNECT 198.51.100.20:8443 legacyToken\n"
	target, meta, err := parseGatewayConnectLine(line)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if target != "198.51.100.20:8443" {
		t.Fatalf("unexpected target: %s", target)
	}
	if meta.Token != "legacyToken" {
		t.Fatalf("unexpected token: %s", meta.Token)
	}
	if meta.HopLimit != defaultGatewayHopLimit {
		t.Fatalf("unexpected default hop limit: %d", meta.HopLimit)
	}
}

func TestParseGatewayGridLine(t *testing.T) {
	line := "APS-GW/1 GRID token=abc origin=node-a path=node-a,node-b hop=5\n"
	meta, err := parseGatewayGridLine(line)
	if err != nil {
		t.Fatalf("parse grid line failed: %v", err)
	}
	if meta.Token != "abc" {
		t.Fatalf("unexpected token: %s", meta.Token)
	}
	if meta.OriginNodeID != "node-a" {
		t.Fatalf("unexpected origin: %s", meta.OriginNodeID)
	}
	if len(meta.Path) != 2 || meta.Path[0] != "node-a" || meta.Path[1] != "node-b" {
		t.Fatalf("unexpected path: %#v", meta.Path)
	}
	if meta.HopLimit != 5 {
		t.Fatalf("unexpected hop limit: %d", meta.HopLimit)
	}
}

func TestValidateGatewayRelayRequestLoopProtection(t *testing.T) {
	meta := gatewayConnectMeta{
		OriginNodeID: "node-self",
		Path:         []string{"node-a"},
		HopLimit:     4,
	}
	if err := validateGatewayRelayRequest("203.0.113.10:443", "127.0.0.1:3900", "node-self", meta); err == nil {
		t.Fatal("expected origin loop rejection")
	}

	meta = gatewayConnectMeta{
		OriginNodeID: "node-a",
		Path:         []string{"node-a", "node-self"},
		HopLimit:     4,
	}
	if err := validateGatewayRelayRequest("203.0.113.10:443", "127.0.0.1:3900", "node-self", meta); err == nil {
		t.Fatal("expected path loop rejection")
	}

	meta = gatewayConnectMeta{HopLimit: 1}
	if err := validateGatewayRelayRequest("127.0.0.1:3900", "127.0.0.1:3900", "node-self", meta); err == nil {
		t.Fatal("expected self-target loop rejection")
	}
}

func TestValidateGatewayGridRequestLoopProtection(t *testing.T) {
	meta := gatewayConnectMeta{
		OriginNodeID: "node-self",
		Path:         []string{"node-a"},
		HopLimit:     4,
	}
	if err := validateGatewayGridRequest("node-self", meta); err == nil {
		t.Fatal("expected origin loop rejection")
	}

	meta = gatewayConnectMeta{
		OriginNodeID: "node-a",
		Path:         []string{"node-a", "node-self"},
		HopLimit:     4,
	}
	if err := validateGatewayGridRequest("node-self", meta); err == nil {
		t.Fatal("expected path loop rejection")
	}
}

func TestGatewayPeerRouteExchangeAndSelection(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-self"
	endpointGatewayRuntime.listenAddr = "127.0.0.1:3900"
	endpointGatewayRuntime.mu.Unlock()

	msg := "APS-GW-PEER/1 node=node-peer addr=127.0.0.2:3900 targets=203.0.113.8:443@0"
	if !applyGatewayPeerAnnounce(msg, nil) {
		t.Fatal("expected peer announce to be accepted")
	}

	nextHopAddr, nextHopNode := selectGatewayRoute("203.0.113.8:443", nil, "node-self")
	if nextHopAddr != "127.0.0.2:3900" || nextHopNode != "node-peer" {
		t.Fatalf("unexpected route selection addr=%s node=%s", nextHopAddr, nextHopNode)
	}

	blockedAddr, _ := selectGatewayRoute("203.0.113.8:443", []string{"node-peer"}, "node-self")
	if blockedAddr != "" {
		t.Fatalf("expected route to be blocked by path loop guard, got %s", blockedAddr)
	}
}

func TestGatewayRoutePrefersShortestPathForAtoBtoC(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:3900"
	endpointGatewayRuntime.token = "gw-token"
	endpointGatewayRuntime.mu.Unlock()

	// First learn a longer path via APS (A->APS->...->C).
	msgAPS := "APS-GW-PEER/1 node=node-aps addr=10.0.0.10:3900 token=gw-token targets=203.0.113.50:443@1"
	if !applyGatewayPeerAnnounce(msgAPS, nil) {
		t.Fatal("expected aps peer announce to be accepted")
	}
	// Then learn a shorter direct gateway path via B (A->B->C).
	msgB := "APS-GW-PEER/1 node=node-b addr=10.0.0.2:3900 token=gw-token targets=203.0.113.50:443@0"
	if !applyGatewayPeerAnnounce(msgB, nil) {
		t.Fatal("expected peer B announce to be accepted")
	}

	nextHopAddr, nextHopNode := selectGatewayRoute("203.0.113.50:443", nil, "node-a")
	if nextHopAddr != "10.0.0.2:3900" || nextHopNode != "node-b" {
		t.Fatalf("expected shortest route via B, got addr=%s node=%s", nextHopAddr, nextHopNode)
	}
}

func TestGatewayRouteFallbackForAtoBtoAPStoC(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:3900"
	endpointGatewayRuntime.mu.Unlock()

	// Simulate A has already traversed B; next hop should fallback to APS peer.
	msgB := "APS-GW-PEER/1 node=node-b addr=10.0.0.2:3900"
	msgAPS := "APS-GW-PEER/1 node=node-aps addr=10.0.0.10:3900"
	if !applyGatewayPeerAnnounce(msgB, nil) {
		t.Fatal("expected peer B announce to be accepted")
	}
	if !applyGatewayPeerAnnounce(msgAPS, nil) {
		t.Fatal("expected peer APS announce to be accepted")
	}

	nextHopAddr, nextHopNode := selectGatewayRoute("198.51.100.77:443", []string{"node-b"}, "node-a")
	if nextHopAddr != "10.0.0.10:3900" || nextHopNode != "node-aps" {
		t.Fatalf("expected fallback route via APS, got addr=%s node=%s", nextHopAddr, nextHopNode)
	}
}

func TestGatewayRouteSelectionBlocksNestedLoops(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:3900"
	endpointGatewayRuntime.mu.Unlock()

	if !applyGatewayPeerAnnounce("APS-GW-PEER/1 node=node-b addr=10.0.0.2:3900 targets=203.0.113.80:443@0 peers=node-c@10.0.0.3:3900", nil) {
		t.Fatal("expected peer B announce to be accepted")
	}
	_ = applyGatewayPeerAnnounce("APS-GW-PEER/1 node=node-c addr=10.0.0.3:3900 peers=node-b@10.0.0.2:3900", nil)

	// Path already contains B and C, so no next hop should be selected to avoid nested loops.
	nextHopAddr, nextHopNode := selectGatewayRoute("203.0.113.80:443", []string{"node-b", "node-c"}, "node-a")
	if nextHopAddr != "" || nextHopNode != "" {
		t.Fatalf("expected loop-safe no-route, got addr=%s node=%s", nextHopAddr, nextHopNode)
	}
}

func TestInvalidateGatewayNodeAndRoutes(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:3900"
	endpointGatewayRuntime.peers["node-b"] = gatewayPeerInfo{
		NodeID:   "node-b",
		Addr:     "10.0.0.2:3900",
		LastSeen: time.Now(),
	}
	endpointGatewayRuntime.targetRoutes["203.0.113.80:443"] = gatewayTargetRoute{
		Target:        "203.0.113.80:443",
		NextHopNodeID: "node-b",
		NextHopAddr:   "10.0.0.2:3900",
		Hop:           1,
		LastSeen:      time.Now(),
	}
	endpointGatewayRuntime.mu.Unlock()

	removed := invalidateGatewayNodeAndRoutes("node-b")
	if removed < 2 {
		t.Fatalf("expected peer and route to be removed, got removed=%d", removed)
	}
	nextHopAddr, nextHopNode := selectGatewayRoute("203.0.113.80:443", nil, "node-a")
	if nextHopAddr != "" || nextHopNode != "" {
		t.Fatalf("expected route to be cleared after offline invalidation, got addr=%s node=%s", nextHopAddr, nextHopNode)
	}
}

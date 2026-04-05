package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
	"time"
)

func resetGatewayRuntimeStateForTest() {
	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.started = false
	endpointGatewayRuntime.startErr = ""
	endpointGatewayRuntime.listenAddr = ""
	endpointGatewayRuntime.nodeID = ""
	endpointGatewayRuntime.discoverPort = 0
	endpointGatewayRuntime.listener = nil
	endpointGatewayRuntime.discoveryConn = nil
	endpointGatewayRuntime.peers = make(map[string]gatewayPeerInfo)
	endpointGatewayRuntime.peerMetrics = make(map[string]gatewayPeerMetric)
	endpointGatewayRuntime.targetRoutes = make(map[string]gatewayTargetRoute)
	endpointGatewayRuntime.directRoutes = make(map[string]map[string]time.Time)
	endpointGatewayRuntime.directTargets = make(map[string]struct{})
	endpointGatewayRuntime.allowedTargets = make(map[string]struct{})
	endpointGatewayRuntime.routeCache = make(map[string]gatewayRouteProbeCandidate)
	endpointGatewayRuntime.routeDenied = make(map[string]map[string]time.Time)
	endpointGatewayRuntime.peerAuthSeen = make(map[string]int64)
	endpointGatewayRuntime.mu.Unlock()
}

func TestValidateGatewayControlPayloadRejectsStructuredAndXML(t *testing.T) {
	if err := validateGatewayControlPayload("APS-GW/1 CONNECT 203.0.113.10:443 hop=4\n"); err != nil {
		t.Fatalf("expected valid control payload, got %v", err)
	}
	if err := validateGatewayControlPayload("{\"type\":\"connect\"}"); err == nil {
		t.Fatal("expected json payload to be rejected")
	}
	if err := validateGatewayControlPayload("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"); err == nil {
		t.Fatal("expected xml entity payload to be rejected")
	}
}

func TestReadGatewayControlLineHonorsMaxSize(t *testing.T) {
	validReader := bufio.NewReader(strings.NewReader("APS-GW/1 GRID hop=4\n"))
	line, err := readGatewayControlLine(validReader)
	if err != nil {
		t.Fatalf("readGatewayControlLine failed: %v", err)
	}
	if strings.TrimSpace(line) != "APS-GW/1 GRID hop=4" {
		t.Fatalf("unexpected line: %q", line)
	}

	oversize := bytes.Repeat([]byte("A"), gatewayMaxControlPayloadSize+1)
	oversize = append(oversize, '\n')
	badReader := bufio.NewReader(bytes.NewReader(oversize))
	if _, err := readGatewayControlLine(badReader); err == nil {
		t.Fatal("expected oversized control payload to fail")
	}
}

func TestNormalizeGatewayRuntimeListenAddress(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		discover   int
		wantListen string
	}{
		{name: "ipv6 wildcard rewritten to ipv4 wildcard", input: "[::]:37990", discover: 37990, wantListen: "0.0.0.0:37990"},
		{name: "ipv4 wildcard kept", input: "0.0.0.0:37990", discover: 37990, wantListen: "0.0.0.0:37990"},
		{name: "explicit host kept", input: "10.1.105.40:37990", discover: 37990, wantListen: "10.1.105.40:37990"},
		{name: "missing port gets discover", input: "0.0.0.0", discover: 37990, wantListen: "0.0.0.0:37990"},
	}
	for _, tt := range tests {
		got := normalizeGatewayRuntimeListenAddress(tt.input, tt.discover)
		if got != tt.wantListen {
			t.Fatalf("%s: got=%s want=%s", tt.name, got, tt.wantListen)
		}
	}
}

func TestGatewayRuntimeListenNetwork(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{addr: "0.0.0.0:37990", want: "tcp4"},
		{addr: "127.0.0.1:37990", want: "tcp4"},
		{addr: "[::1]:37990", want: "tcp6"},
		{addr: "localhost:37990", want: "tcp4"},
	}
	for _, tt := range tests {
		if got := gatewayRuntimeListenNetwork(tt.addr); got != tt.want {
			t.Fatalf("addr=%s got=%s want=%s", tt.addr, got, tt.want)
		}
	}
}

func TestResolveGatewayAddressCandidatesSkipsDenied(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	target := "203.0.113.10:443"
	denyAddr := "198.51.100.22:37990"
	backupAddr := "198.51.100.40:37990"

	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.routeCache[normalizeGatewayAddress(target)] = gatewayRouteProbeCandidate{
		Addr:      normalizeGatewayAddress(denyAddr),
		Backups:   []string{normalizeGatewayAddress(backupAddr)},
		ProbedAt:  now,
		NextProbe: now.Add(gatewayRouteProbeTTL),
		ExpiresAt: now.Add(gatewayRouteProbeTTL),
	}
	endpointGatewayRuntime.mu.Unlock()

	markGatewayRouteDenied(target, denyAddr)
	got := resolveGatewayAddressCandidates(ImmutableConnectionContext{
		ServerAddress:    target,
		GatewayDiscovery: false,
	})
	if len(got) != 1 || got[0] != normalizeGatewayAddress(backupAddr) {
		t.Fatalf("expected backup only, got=%v", got)
	}
}

func TestParseGatewayConnectLineExtended(t *testing.T) {
	line := "APS-GW/1 CONNECT 203.0.113.10:443 origin=node-a path=node-a,node-b hop=6\n"
	target, meta, err := parseGatewayConnectLine(line)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if target != "203.0.113.10:443" {
		t.Fatalf("unexpected target: %s", target)
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
	line := "APS-GW/1 CONNECT 198.51.100.20:8443 legacyField\n"
	target, meta, err := parseGatewayConnectLine(line)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if target != "198.51.100.20:8443" {
		t.Fatalf("unexpected target: %s", target)
	}
	if meta.HopLimit != defaultGatewayHopLimit {
		t.Fatalf("unexpected default hop limit: %d", meta.HopLimit)
	}
}

func TestParseGatewayGridLine(t *testing.T) {
	line := "APS-GW/1 GRID origin=node-a path=node-a,node-b hop=5\n"
	meta, err := parseGatewayGridLine(line)
	if err != nil {
		t.Fatalf("parse grid line failed: %v", err)
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
	endpointGatewayRuntime.mu.Unlock()

	// First learn a longer path via APS (A->APS->...->C).
	msgAPS := "APS-GW-PEER/1 node=node-aps addr=10.0.0.10:3900 targets=203.0.113.50:443@1"
	if !applyGatewayPeerAnnounce(msgAPS, nil) {
		t.Fatal("expected aps peer announce to be accepted")
	}
	// Then learn a shorter direct gateway path via B (A->B->C).
	msgB := "APS-GW-PEER/1 node=node-b addr=10.0.0.2:3900 targets=203.0.113.50:443@0"
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

func TestResolveGatewayAddressRefreshesCacheWithoutBreakingCurrentSelection(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	target := "203.0.113.77:443"
	now := time.Now()

	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:37990"
	endpointGatewayRuntime.peers["node-b"] = gatewayPeerInfo{
		NodeID:   "node-b",
		Addr:     "10.0.0.2:37990",
		LastSeen: now,
	}
	endpointGatewayRuntime.targetRoutes[target] = gatewayTargetRoute{
		Target:        target,
		NextHopNodeID: "node-b",
		NextHopAddr:   "10.0.0.2:37990",
		Hop:           1,
		LastSeen:      now,
	}
	endpointGatewayRuntime.routeCache[target] = gatewayRouteProbeCandidate{
		Addr:      "10.0.0.9:37990",
		NodeID:    "node-old",
		Source:    "route",
		Score:     99,
		ProbedAt:  now.Add(-2 * gatewayRouteProbeTTL),
		NextProbe: now.Add(-time.Second),
		ExpiresAt: now.Add(gatewayRouteProbeTTL),
	}
	endpointGatewayRuntime.mu.Unlock()

	connCtx := ImmutableConnectionContext{
		ServerAddress:       target,
		ConfigID:            "node-a",
		GatewayDiscovery:    false,
		GatewayDiscoverPort: defaultGatewayDiscoverPort,
	}

	first := resolveGatewayAddress(connCtx)
	if first != "10.0.0.9:37990" {
		t.Fatalf("expected first resolution to keep cached route for in-flight stability, got %s", first)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		endpointGatewayRuntime.mu.Lock()
		updated := endpointGatewayRuntime.routeCache[target]
		endpointGatewayRuntime.mu.Unlock()
		if updated.Addr == "10.0.0.2:37990" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	endpointGatewayRuntime.mu.Lock()
	final := endpointGatewayRuntime.routeCache[target]
	endpointGatewayRuntime.mu.Unlock()
	t.Fatalf("expected async refresh to replace route cache with better path, got addr=%s source=%s score=%.2f", final.Addr, final.Source, final.Score)
}

func TestResolveGatewayAddressCandidatesReturnsPrimaryAndBackups(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	target := "203.0.113.90:443"
	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:37990"
	endpointGatewayRuntime.routeCache[target] = gatewayRouteProbeCandidate{
		Addr:      "10.0.0.2:37990",
		Backups:   []string{"10.0.0.3:37990", "10.0.0.4:37990"},
		Score:     1.0,
		ProbedAt:  now,
		NextProbe: now.Add(gatewayRouteProbeTTL),
		ExpiresAt: now.Add(gatewayRouteProbeTTL),
	}
	endpointGatewayRuntime.mu.Unlock()

	got := resolveGatewayAddressCandidates(ImmutableConnectionContext{
		ServerAddress:    target,
		GatewayDiscovery: false,
		ConfigID:         "node-a",
	})
	if len(got) != 3 {
		t.Fatalf("expected 3 route bundle candidates, got %v", got)
	}
	if got[0] != "10.0.0.2:37990" || got[1] != "10.0.0.3:37990" || got[2] != "10.0.0.4:37990" {
		t.Fatalf("unexpected route bundle order: %v", got)
	}
}

func TestPromoteGatewayRouteCacheCandidatePromotesBackup(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	target := "203.0.113.100:443"
	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:37990"
	endpointGatewayRuntime.routeCache[target] = gatewayRouteProbeCandidate{
		Addr:      "10.0.0.2:37990",
		Backups:   []string{"10.0.0.3:37990", "10.0.0.4:37990"},
		Score:     1.0,
		ProbedAt:  now,
		NextProbe: now.Add(gatewayRouteProbeTTL),
		ExpiresAt: now.Add(gatewayRouteProbeTTL),
	}
	endpointGatewayRuntime.mu.Unlock()

	done := make(chan struct{})
	go func() {
		promoteGatewayRouteCacheCandidate(target, "10.0.0.3:37990")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("promoteGatewayRouteCacheCandidate blocked (possible lock regression)")
	}

	endpointGatewayRuntime.mu.Lock()
	updated := endpointGatewayRuntime.routeCache[target]
	endpointGatewayRuntime.mu.Unlock()
	if updated.Addr != "10.0.0.3:37990" {
		t.Fatalf("expected promoted primary 10.0.0.3:37990, got %s", updated.Addr)
	}
	if len(updated.Backups) == 0 || updated.Backups[0] != "10.0.0.2:37990" {
		t.Fatalf("expected previous primary to become backup head, got %v", updated.Backups)
	}
}

func TestMarkGatewayRouteCacheCandidateFailureRotatesPrimary(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	target := "203.0.113.101:443"
	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:37990"
	endpointGatewayRuntime.routeCache[target] = gatewayRouteProbeCandidate{
		Addr:      "10.0.0.2:37990",
		Backups:   []string{"10.0.0.3:37990", "10.0.0.4:37990"},
		Score:     1.0,
		ProbedAt:  now,
		NextProbe: now.Add(gatewayRouteProbeTTL),
		ExpiresAt: now.Add(gatewayRouteProbeTTL),
	}
	endpointGatewayRuntime.mu.Unlock()

	markGatewayRouteCacheCandidateFailure(target, "10.0.0.2:37990")

	endpointGatewayRuntime.mu.Lock()
	updated := endpointGatewayRuntime.routeCache[target]
	endpointGatewayRuntime.mu.Unlock()
	if updated.Addr != "10.0.0.3:37990" {
		t.Fatalf("expected rotated primary 10.0.0.3:37990, got %s", updated.Addr)
	}
	if len(updated.Backups) == 0 || updated.Backups[len(updated.Backups)-1] != "10.0.0.2:37990" {
		t.Fatalf("expected failed primary to be moved to backup tail, got %v", updated.Backups)
	}
}

func TestMarkGatewayRouteCacheCandidateFailureRemovesFailedBackup(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	target := "203.0.113.102:443"
	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:37990"
	endpointGatewayRuntime.routeCache[target] = gatewayRouteProbeCandidate{
		Addr:      "10.0.0.2:37990",
		Backups:   []string{"10.0.0.3:37990", "10.0.0.4:37990"},
		Score:     1.0,
		ProbedAt:  now,
		NextProbe: now.Add(gatewayRouteProbeTTL),
		ExpiresAt: now.Add(gatewayRouteProbeTTL),
	}
	endpointGatewayRuntime.mu.Unlock()

	markGatewayRouteCacheCandidateFailure(target, "10.0.0.4:37990")

	endpointGatewayRuntime.mu.Lock()
	updated := endpointGatewayRuntime.routeCache[target]
	endpointGatewayRuntime.mu.Unlock()
	if updated.Addr != "10.0.0.2:37990" {
		t.Fatalf("expected primary unchanged, got %s", updated.Addr)
	}
	for _, b := range updated.Backups {
		if b == "10.0.0.4:37990" {
			t.Fatalf("expected failed backup removed, got %v", updated.Backups)
		}
	}
}

func TestSelectGatewayPeerDialCandidatesPrimaryAndLimitFive(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:37990"
	endpointGatewayRuntime.peers["node-b"] = gatewayPeerInfo{NodeID: "node-b", Addr: "10.0.0.2:37990", LastSeen: now}
	endpointGatewayRuntime.peers["node-c"] = gatewayPeerInfo{NodeID: "node-c", Addr: "10.0.0.3:37990", LastSeen: now}
	endpointGatewayRuntime.peers["node-d"] = gatewayPeerInfo{NodeID: "node-d", Addr: "10.0.0.4:37990", LastSeen: now}
	endpointGatewayRuntime.peers["node-e"] = gatewayPeerInfo{NodeID: "node-e", Addr: "10.0.0.5:37990", LastSeen: now}
	endpointGatewayRuntime.peers["node-f"] = gatewayPeerInfo{NodeID: "node-f", Addr: "10.0.0.6:37990", LastSeen: now}
	endpointGatewayRuntime.peers["node-g"] = gatewayPeerInfo{NodeID: "node-g", Addr: "10.0.0.7:37990", LastSeen: now}
	endpointGatewayRuntime.mu.Unlock()

	got := selectGatewayPeerDialCandidates("node-b", []string{"node-e"}, gatewayRouteBundleMaxAddrs)
	if len(got) != gatewayRouteBundleMaxAddrs {
		t.Fatalf("expected %d candidates, got %v", gatewayRouteBundleMaxAddrs, got)
	}
	if got[0] != "node-b" {
		t.Fatalf("expected primary node-b first, got %v", got)
	}
	for _, node := range got {
		if node == "node-e" {
			t.Fatalf("expected excluded node-e to be absent, got %v", got)
		}
	}
}

func TestSelectGatewayRouteCandidatesPrefersDirectAPSPeerOverRelayedPeer(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	target := "203.0.113.200:443"
	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:37990"
	endpointGatewayRuntime.peers["node-direct"] = gatewayPeerInfo{NodeID: "node-direct", Addr: "10.0.0.2:37990", LastSeen: now}
	endpointGatewayRuntime.peers["node-relay"] = gatewayPeerInfo{NodeID: "node-relay", Addr: "10.0.0.3:37990", LastSeen: now}
	endpointGatewayRuntime.directRoutes[target] = map[string]time.Time{"node-direct": now}
	endpointGatewayRuntime.targetRoutes[target] = gatewayTargetRoute{
		Target:        target,
		NextHopNodeID: "node-relay",
		NextHopAddr:   "10.0.0.3:37990",
		Hop:           2,
		LastSeen:      now,
	}
	endpointGatewayRuntime.mu.Unlock()

	candidates := selectGatewayRouteCandidates(target, nil, "node-a", 3)
	if len(candidates) == 0 {
		t.Fatal("expected non-empty candidates")
	}
	if candidates[0].NextHopNodeID != "node-direct" {
		t.Fatalf("expected direct APS peer first, got %s", candidates[0].NextHopNodeID)
	}
}

func TestApplyGatewayPeerAnnounceAcceptsUnsigned(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.nodeID = "node-a"
	endpointGatewayRuntime.listenAddr = "10.0.0.1:3900"
	endpointGatewayRuntime.mu.Unlock()

	unsigned := "APS-GW-PEER/1 node=node-b addr=10.0.0.2:3900 targets=203.0.113.10:443@0"
	if !applyGatewayPeerAnnounce(unsigned, nil) {
		t.Fatal("expected unsigned peer announce to be accepted")
	}
}

func TestValidateGatewayRelayRequestOnlyAllowsConfiguredAPSTarget(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()

	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.allowedTargets["203.0.113.10:443"] = struct{}{}
	endpointGatewayRuntime.mu.Unlock()

	meta := gatewayConnectMeta{HopLimit: 4}
	if err := validateGatewayRelayRequest("203.0.113.10:443", "10.0.0.1:3900", "node-a", meta); err != nil {
		t.Fatalf("expected configured APS target to be allowed, got %v", err)
	}
	if err := validateGatewayRelayRequest("198.51.100.20:443", "10.0.0.1:3900", "node-a", meta); err == nil {
		t.Fatal("expected non-APS target to be rejected")
	}
}

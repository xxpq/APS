package main

import (
	"net"
	"os"
	"testing"
	"time"
)

func TestDialGridBackendWithPolicyTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr == nil && conn != nil {
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	payload := ProxyConnectPayload{
		GridEnableTCP:  true,
		GridEnableQUIC: false,
		GridEnableICE:  false,
		GridParallel:   false,
	}
	conn, transport, err := dialGridBackendWithPolicy(addr.IP.String(), addr.Port, false, payload)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if transport != "tcp" {
		t.Fatalf("expected tcp transport, got %s", transport)
	}
	_ = conn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept goroutine timeout")
	}
}

func TestDialGridBackendWithPolicyICECandidate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr == nil && conn != nil {
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().String()
	payload := ProxyConnectPayload{
		GridEnableTCP:     false,
		GridEnableQUIC:    false,
		GridEnableICE:     true,
		GridParallel:      false,
		GridICECandidates: []string{addr},
	}
	host, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		t.Fatalf("split host port failed: %v", splitErr)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	conn, transport, err := dialGridBackendWithPolicy(host, port, false, payload)
	if err != nil {
		t.Fatalf("dial via ice candidate failed: %v", err)
	}
	if transport != "ice" {
		t.Fatalf("expected ice transport, got %s", transport)
	}
	_ = conn.Close()
	_ = portStr

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept goroutine timeout")
	}
}

func TestParseGridICECandidateSDP(t *testing.T) {
	host, port, ok := parseGridICECandidate("candidate:842163049 1 udp 1677729535 10.0.0.25 53547 typ srflx", 443)
	if !ok {
		t.Fatal("expected SDP candidate to parse")
	}
	if host != "10.0.0.25" || port != 53547 {
		t.Fatalf("unexpected parsed candidate host=%s port=%d", host, port)
	}
}

func TestParseGridICECandidateDescriptorSDPMetadata(t *testing.T) {
	desc, ok := parseGridICECandidateDescriptor("candidate:842163049 1 udp 1677729535 10.0.0.25 53547 typ srflx", 443)
	if !ok {
		t.Fatal("expected descriptor parse success")
	}
	if desc.host != "10.0.0.25" || desc.port != 53547 {
		t.Fatalf("unexpected descriptor host=%s port=%d", desc.host, desc.port)
	}
	if desc.candidateType != "srflx" {
		t.Fatalf("expected srflx candidate type, got %s", desc.candidateType)
	}
	if desc.priority != 1677729535 {
		t.Fatalf("unexpected priority %d", desc.priority)
	}
}

func TestParseGridICECandidateURL(t *testing.T) {
	host, port, ok := parseGridICECandidate("udp://198.51.100.2:3478", 443)
	if !ok {
		t.Fatal("expected URL candidate to parse")
	}
	if host != "198.51.100.2" || port != 3478 {
		t.Fatalf("unexpected parsed candidate host=%s port=%d", host, port)
	}
}

func TestGridCandidatePortsWithEnv(t *testing.T) {
	prev := os.Getenv("APS_GRID_ICE_PORTS")
	t.Cleanup(func() {
		_ = os.Setenv("APS_GRID_ICE_PORTS", prev)
	})
	if err := os.Setenv("APS_GRID_ICE_PORTS", "40000, 40001"); err != nil {
		t.Fatalf("setenv failed: %v", err)
	}

	ports := gridCandidatePorts(12345)
	expect := map[int]bool{
		12345: false,
		443:   false,
		8443:  false,
		3478:  false,
		5349:  false,
		40000: false,
		40001: false,
	}
	for _, p := range ports {
		if _, ok := expect[p]; ok {
			expect[p] = true
		}
	}
	for p, ok := range expect {
		if !ok {
			t.Fatalf("missing expected candidate port %d in %v", p, ports)
		}
	}
}

func TestSelectBestGridDialResultQoS(t *testing.T) {
	results := []gridDialResult{
		{name: "ice", rtt: 20 * time.Millisecond},
		{name: "tcp", rtt: 40 * time.Millisecond},
		{name: "quic", rtt: 25 * time.Millisecond},
	}

	latencyBest := selectBestGridDialResult(results, "latency")
	if latencyBest.name != "ice" {
		t.Fatalf("expected latency policy to prefer ice, got %s", latencyBest.name)
	}

	reliabilityBest := selectBestGridDialResult(results, "reliability")
	if reliabilityBest.name != "tcp" {
		t.Fatalf("expected reliability policy to prefer tcp, got %s", reliabilityBest.name)
	}
}

func TestOrderGridICEAddressesByConnectivity(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil && conn != nil {
			_ = conn.Close()
		}
	}()

	reachable := ln.Addr().String()
	unreachable := "127.0.0.1:9"
	ordered := orderGridICEAddressesByConnectivity([]string{unreachable, reachable}, 200*time.Millisecond)
	if len(ordered) != 2 {
		t.Fatalf("unexpected ordered length: %d", len(ordered))
	}
	if ordered[0] != reachable {
		t.Fatalf("expected reachable address first, got %v", ordered)
	}
}

func TestGridICEProbeResultScoreTypeAndPriority(t *testing.T) {
	hostTarget := gridICEProbeTarget{
		addr:           "127.0.0.1:10001",
		candidateType:  "host",
		role:           "peer",
		remotePriority: 2122260223,
		localPriority:  2122260223,
	}
	relayTarget := gridICEProbeTarget{
		addr:           "127.0.0.1:10002",
		candidateType:  "relay",
		role:           "relay",
		remotePriority: 268435456,
		localPriority:  268435456,
	}
	hostScore := gridICEProbeResultScore(hostTarget, true, 40*time.Millisecond)
	relayScore := gridICEProbeResultScore(relayTarget, true, 20*time.Millisecond)
	if hostScore <= relayScore {
		t.Fatalf("expected host/high-priority score > relay score, got host=%f relay=%f", hostScore, relayScore)
	}
}

func TestOrderGridICEProbeTargetsByConnectivityPairPriority(t *testing.T) {
	reachableLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer reachableLn.Close()
	go func() {
		conn, acceptErr := reachableLn.Accept()
		if acceptErr == nil && conn != nil {
			_ = conn.Close()
		}
	}()

	reachableAddr := reachableLn.Addr().String()
	unreachableAddr := "127.0.0.1:9"
	ordered := orderGridICEProbeTargetsByConnectivity([]gridICEProbeTarget{
		{
			addr:           unreachableAddr,
			candidateType:  "host",
			role:           "peer",
			remotePriority: 4294967295,
			localPriority:  4294967295,
		},
		{
			addr:           reachableAddr,
			candidateType:  "relay",
			role:           "relay",
			remotePriority: 268435456,
			localPriority:  268435456,
		},
	}, 200*time.Millisecond)
	if len(ordered) != 2 {
		t.Fatalf("unexpected ordered length: %d", len(ordered))
	}
	if ordered[0] != reachableAddr {
		t.Fatalf("expected reachable candidate first, got %v", ordered)
	}
}

func TestOrderGridICEProbeTargetsByConnectivityMetadataTieBreak(t *testing.T) {
	addrA := "127.0.0.1:9"
	addrB := "127.0.0.1:10"
	ordered := orderGridICEProbeTargetsByConnectivity([]gridICEProbeTarget{
		{
			addr:           addrA,
			candidateType:  "relay",
			role:           "relay",
			remotePriority: 268435456,
			localPriority:  268435456,
		},
		{
			addr:           addrB,
			candidateType:  "host",
			role:           "peer",
			remotePriority: 2122260223,
			localPriority:  2122260223,
		},
	}, 50*time.Millisecond)
	if len(ordered) != 2 {
		t.Fatalf("unexpected ordered length: %d", len(ordered))
	}
	if ordered[0] != addrB {
		t.Fatalf("expected host/high-priority candidate first under equal connectivity failure, got %v", ordered)
	}
}

func TestDedupeGridDialCandidates(t *testing.T) {
	deduped := dedupeGridDialCandidates([]string{
		" 203.0.113.10:443 ",
		"203.0.113.10:443",
		"",
		"turn:turn.example.com:3478?transport=udp",
		"turn:turn.example.com:3478?transport=udp",
	})
	if len(deduped) != 2 {
		t.Fatalf("expected 2 deduped candidates, got %v", deduped)
	}
}

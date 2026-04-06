package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	gatewayProtocolVersion  = "APS-GW/1"
	gatewayCommandConnect   = "CONNECT"
	gatewayCommandGrid      = "GRID"
	gatewayCommandAuth      = "AUTH"
	gatewayCommandChallenge = "CHALLENGE"
	gatewayServiceGrid      = "grid"
	gatewayDiscoverMagic    = "APS-GW-DISCOVER/1"
	gatewayAnnounceMagic    = "APS-GW-ANNOUNCE/1"
	gatewayPeerMagic        = "APS-GW-PEER/1"

	defaultGatewayDiscoverPort = 37990
	defaultGatewayHopLimit     = 8
	maxGatewayHopLimit         = 32

	gatewayPeerBroadcastInterval = 5 * time.Second
	gatewayPeerRouteTTL          = 45 * time.Second
	gatewayRouteProbeTTL         = 100 * time.Second
	gatewayRouteProbeBackoff     = 15 * time.Second
	gatewayRouteDeniedTTL        = 120 * time.Second
	gatewayRouteSwitchEpsilon    = 0.25
	gatewayRouteBundleMaxAddrs   = 5
	maxGatewayPeerEntries        = 128
	maxGatewayRouteEntries       = 256
	maxGatewayAnnounceEntries    = 32
	gatewayPeerAuthWindow        = 60 * time.Second
	gatewayPeerAuthNonceBytes    = 12
	gatewayPeerAuthReplayEntries = 4096
	gatewayKEXNonceBytes         = 16
	gatewayDialTimeout           = 5 * time.Second
	gatewayHandshakeTimeout      = 8 * time.Second
	gatewayPreTLSGuardWindow     = 500 * time.Millisecond
	gatewayMaxControlPayloadSize = 10 * 1024 * 1024
)

func defaultGatewayListenAddress(discoverPort int) string {
	if discoverPort <= 0 {
		discoverPort = defaultGatewayDiscoverPort
	}
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(discoverPort))
}

type gatewayPeerInfo struct {
	NodeID   string
	Addr     string
	LastSeen time.Time
}

type gatewayTargetRoute struct {
	Target        string
	NextHopNodeID string
	NextHopAddr   string
	Hop           int
	LastSeen      time.Time
}

type gatewayPeerMetric struct {
	SuccessCount int
	FailureCount int
	RTTEwmaMs    float64
	JitterEwmaMs float64
	LastRTTMs    float64
	UpdatedAt    time.Time
}

type gatewayRouteCandidate struct {
	NextHopNodeID string
	NextHopAddr   string
	Hop           int
	LastSeen      time.Time
	Cost          float64
}

type gatewayRouteProbeCandidate struct {
	Addr       string
	Backups    []string
	NodeID     string
	Source     string
	Score      float64
	ProbedAt   time.Time
	ExpiresAt  time.Time
	NextProbe  time.Time
	Refreshing bool
}

type gatewayConnectMeta struct {
	OriginNodeID string
	Path         []string
	HopLimit     int
	Service      string
	KEXPublicKey string
	KEXNonce     string
}

type gatewayKEXOffer struct {
	privateKey *ecdh.PrivateKey
	publicKey  string
	nonce      string
}

type gatewayIntegrityKeyConn struct {
	net.Conn
	integrityKey string
}

func (c *gatewayIntegrityKeyConn) GridIntegrityKey() string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.integrityKey)
}

type gatewayRuntimeState struct {
	mu             sync.Mutex
	started        bool
	startErr       string
	listenAddr     string
	nodeID         string
	discoverPort   int
	listener       net.Listener
	discoveryConn  *net.UDPConn
	peers          map[string]gatewayPeerInfo
	peerMetrics    map[string]gatewayPeerMetric
	targetRoutes   map[string]gatewayTargetRoute
	directRoutes   map[string]map[string]time.Time
	directTargets  map[string]struct{}
	allowedTargets map[string]struct{}
	routeCache     map[string]gatewayRouteProbeCandidate
	routeDenied    map[string]map[string]time.Time
	peerAuthSeen   map[string]int64
}

var endpointGatewayRuntime = gatewayRuntimeState{
	peers:          make(map[string]gatewayPeerInfo),
	peerMetrics:    make(map[string]gatewayPeerMetric),
	targetRoutes:   make(map[string]gatewayTargetRoute),
	directRoutes:   make(map[string]map[string]time.Time),
	directTargets:  make(map[string]struct{}),
	allowedTargets: make(map[string]struct{}),
	routeCache:     make(map[string]gatewayRouteProbeCandidate),
	routeDenied:    make(map[string]map[string]time.Time),
	peerAuthSeen:   make(map[string]int64),
}

func ensureBootstrapGatewayRuntimeForConfigFetch(serverAddress, configID string) {
	configID = strings.TrimSpace(configID)
	if configID == "" {
		return
	}
	serverAddress = normalizeServerAddressForSession(serverAddress)
	if serverAddress == "" {
		return
	}

	discoverPort := endpointBootstrapGatewayDiscoverPort()
	if discoverPort <= 0 {
		discoverPort = defaultGatewayDiscoverPort
	}
	ensureGatewayRuntime(ImmutableConnectionContext{
		ServerAddress:       serverAddress,
		ConfigID:            configID,
		EndpointName:        configID,
		GatewayListen:       defaultGatewayListenAddress(discoverPort),
		GatewayDiscovery:    true,
		GatewayDiscoverPort: discoverPort,
	})
}

func ensureGatewayRuntime(connCtx ImmutableConnectionContext) {
	listenAddr := strings.TrimSpace(connCtx.GatewayListen)
	if listenAddr == "" {
		return
	}
	if connCtx.GatewayDiscoverPort <= 0 {
		connCtx.GatewayDiscoverPort = defaultGatewayDiscoverPort
	}
	listenAddr = normalizeGatewayRuntimeListenAddress(listenAddr, connCtx.GatewayDiscoverPort)
	listenNetwork := gatewayRuntimeListenNetwork(listenAddr)

	nodeID := normalizeGatewayNodeID(connCtx.ConfigID)
	if nodeID == "" {
		nodeID = normalizeGatewayNodeID(connCtx.EndpointName)
	}
	allowedTarget := normalizeGatewayAddress(connCtx.ServerAddress)

	endpointGatewayRuntime.mu.Lock()
	if allowedTarget != "" {
		endpointGatewayRuntime.allowedTargets[allowedTarget] = struct{}{}
	}
	if endpointGatewayRuntime.started {
		endpointGatewayRuntime.startErr = ""
		if nodeID != "" {
			endpointGatewayRuntime.nodeID = nodeID
		}
		if connCtx.GatewayDiscoverPort > 0 {
			endpointGatewayRuntime.discoverPort = connCtx.GatewayDiscoverPort
		}
		endpointGatewayRuntime.mu.Unlock()
		return
	}

	ln, err := net.Listen(listenNetwork, listenAddr)
	if err != nil {
		endpointGatewayRuntime.startErr = err.Error()
		endpointGatewayRuntime.mu.Unlock()
		log.Printf("[GATEWAY] Failed to listen on %s (%s): %v", listenAddr, listenNetwork, err)
		return
	}

	endpointGatewayRuntime.started = true
	endpointGatewayRuntime.startErr = ""
	endpointGatewayRuntime.listenAddr = ln.Addr().String()
	endpointGatewayRuntime.nodeID = nodeID
	endpointGatewayRuntime.discoverPort = connCtx.GatewayDiscoverPort
	endpointGatewayRuntime.listener = ln
	discoverPort := endpointGatewayRuntime.discoverPort
	listenAddr = endpointGatewayRuntime.listenAddr
	endpointGatewayRuntime.mu.Unlock()

	log.Printf("[GATEWAY] Relay listener started on %s", listenAddr)
	go acceptGatewayRelayLoop(ln, listenAddr)

	if discoverPort > 0 {
		discoveryConn, discoverErr := net.ListenUDP("udp4", &net.UDPAddr{Port: discoverPort})
		if discoverErr != nil {
			log.Printf("[GATEWAY] Failed to start discovery responder on UDP/%d: %v", discoverPort, discoverErr)
			return
		}

		endpointGatewayRuntime.mu.Lock()
		endpointGatewayRuntime.discoveryConn = discoveryConn
		endpointGatewayRuntime.mu.Unlock()

		log.Printf("[GATEWAY] Discovery responder started on UDP/%d", discoverPort)
		go serveGatewayDiscovery(discoveryConn, listenAddr)
		go broadcastGatewayPresence(discoveryConn, discoverPort, listenAddr)
	}
}

func gatewayRuntimeStateSnapshot() (started bool, listenAddr string, startErr string) {
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()
	return endpointGatewayRuntime.started, strings.TrimSpace(endpointGatewayRuntime.listenAddr), strings.TrimSpace(endpointGatewayRuntime.startErr)
}

func normalizeGatewayRuntimeListenAddress(listenAddr string, discoverPort int) string {
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		return defaultGatewayListenAddress(discoverPort)
	}

	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "missing port") {
			host = strings.Trim(strings.TrimSpace(listenAddr), "[]")
			if host == "" {
				host = "0.0.0.0"
			}
			return net.JoinHostPort(host, strconv.Itoa(discoverPort))
		}
		return listenAddr
	}

	normalizedHost := strings.Trim(strings.TrimSpace(host), "[]")
	switch normalizedHost {
	case "", "::":
		// Gateway discovery and peer dials are IPv4-first; avoid IPv6-only wildcard bind.
		return net.JoinHostPort("0.0.0.0", port)
	default:
		return listenAddr
	}
}

func gatewayRuntimeListenNetwork(listenAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(listenAddr))
	if err != nil {
		return "tcp4"
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || host == "0.0.0.0" {
		return "tcp4"
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return "tcp4"
		}
		return "tcp6"
	}
	if strings.EqualFold(host, "localhost") {
		return "tcp4"
	}
	return "tcp4"
}

func resolveGatewayAddress(connCtx ImmutableConnectionContext) string {
	candidates := resolveGatewayAddressCandidates(connCtx)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func resolveGatewayAddressCandidates(connCtx ImmutableConnectionContext) []string {
	target := normalizeGatewayAddress(connCtx.ServerAddress)
	if target == "" {
		return nil
	}

	now := time.Now()
	cached, shouldRefresh := loadGatewayRouteCacheCandidate(target, now)
	if cached.Addr != "" && (isLocalGatewayAddress(cached.Addr) || isGatewayRouteDenied(target, cached.Addr, now)) {
		markGatewayRouteCacheCandidateFailure(target, cached.Addr)
		cached, shouldRefresh = loadGatewayRouteCacheCandidate(target, now)
	}
	if cached.Addr != "" {
		if shouldRefresh {
			go refreshGatewayRouteCacheCandidate(target, connCtx)
		}
		bundle := gatewayRouteCandidateBundle(cached)
		filtered := make([]string, 0, len(bundle))
		for _, addr := range bundle {
			if isGatewayRouteDenied(target, addr, now) {
				continue
			}
			filtered = append(filtered, addr)
		}
		if len(filtered) > 0 {
			return filtered
		}
		clearGatewayRouteCacheCandidate(target)
	}

	selected, err := probeGatewayRouteCandidate(connCtx, now)
	if err != nil {
		return nil
	}
	storeGatewayRouteCacheCandidate(target, selected)
	bundle := gatewayRouteCandidateBundle(selected)
	filtered := make([]string, 0, len(bundle))
	for _, addr := range bundle {
		if isGatewayRouteDenied(target, addr, now) {
			continue
		}
		filtered = append(filtered, addr)
	}
	return filtered
}

func gatewayRouteCandidateBundle(candidate gatewayRouteProbeCandidate) []string {
	if candidate.Addr == "" {
		return nil
	}
	out := make([]string, 0, gatewayRouteBundleMaxAddrs)
	seen := make(map[string]struct{}, gatewayRouteBundleMaxAddrs)
	add := func(addr string) {
		addr = normalizeGatewayAddress(addr)
		if addr == "" || isLocalGatewayAddress(addr) {
			return
		}
		if _, exists := seen[addr]; exists {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	add(candidate.Addr)
	for _, backup := range candidate.Backups {
		if len(out) >= gatewayRouteBundleMaxAddrs {
			break
		}
		add(backup)
	}
	return out
}

func clearGatewayRouteCacheCandidate(target string) {
	target = normalizeGatewayAddress(target)
	if target == "" {
		return
	}
	endpointGatewayRuntime.mu.Lock()
	delete(endpointGatewayRuntime.routeCache, target)
	endpointGatewayRuntime.mu.Unlock()
}

func markGatewayRouteDenied(target, gatewayAddr string) {
	target = normalizeGatewayAddress(target)
	gatewayAddr = normalizeGatewayAddress(gatewayAddr)
	if target == "" || gatewayAddr == "" {
		return
	}
	expiresAt := time.Now().Add(gatewayRouteDeniedTTL)
	endpointGatewayRuntime.mu.Lock()
	deniedByTarget, exists := endpointGatewayRuntime.routeDenied[target]
	if !exists || deniedByTarget == nil {
		deniedByTarget = make(map[string]time.Time)
		endpointGatewayRuntime.routeDenied[target] = deniedByTarget
	}
	deniedByTarget[gatewayAddr] = expiresAt
	endpointGatewayRuntime.mu.Unlock()
}

func isGatewayRouteDenied(target, gatewayAddr string, now time.Time) bool {
	target = normalizeGatewayAddress(target)
	gatewayAddr = normalizeGatewayAddress(gatewayAddr)
	if target == "" || gatewayAddr == "" {
		return false
	}
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()
	deniedByTarget, exists := endpointGatewayRuntime.routeDenied[target]
	if !exists || deniedByTarget == nil {
		return false
	}
	expiresAt, denied := deniedByTarget[gatewayAddr]
	if !denied {
		return false
	}
	if now.After(expiresAt) {
		delete(deniedByTarget, gatewayAddr)
		if len(deniedByTarget) == 0 {
			delete(endpointGatewayRuntime.routeDenied, target)
		}
		return false
	}
	return true
}

func markGatewayDirectTargetReachable(target string) {
	target = normalizeGatewayAddress(target)
	if target == "" {
		return
	}
	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.directTargets[target] = struct{}{}
	delete(endpointGatewayRuntime.targetRoutes, target)
	endpointGatewayRuntime.mu.Unlock()
}

func markGatewayDirectTargetUnreachable(target string) {
	target = normalizeGatewayAddress(target)
	if target == "" {
		return
	}
	endpointGatewayRuntime.mu.Lock()
	delete(endpointGatewayRuntime.directTargets, target)
	endpointGatewayRuntime.mu.Unlock()
}

func isGatewayDirectTargetReachable(target string) bool {
	target = normalizeGatewayAddress(target)
	if target == "" {
		return false
	}
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()
	_, ok := endpointGatewayRuntime.directTargets[target]
	return ok
}

func promoteGatewayRouteCacheCandidate(target, successAddr string) {
	target = normalizeGatewayAddress(target)
	successAddr = normalizeGatewayAddress(successAddr)
	if target == "" || successAddr == "" || isLocalGatewayAddress(successAddr) {
		return
	}

	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()
	current, exists := endpointGatewayRuntime.routeCache[target]
	if !exists {
		endpointGatewayRuntime.routeCache[target] = gatewayRouteProbeCandidate{
			Addr:      successAddr,
			Backups:   nil,
			Source:    "runtime-success",
			Score:     current.Score,
			ProbedAt:  now,
			NextProbe: now.Add(gatewayRouteProbeTTL),
			ExpiresAt: now.Add(gatewayRouteProbeTTL),
		}
		return
	}
	if sameGatewayAddress(current.Addr, successAddr) {
		current.ExpiresAt = now.Add(gatewayRouteProbeTTL)
		current.NextProbe = now.Add(gatewayRouteProbeTTL)
		current.Refreshing = false
		endpointGatewayRuntime.routeCache[target] = current
		return
	}
	newBackups := make([]string, 0, gatewayRouteBundleMaxAddrs-1)
	newBackups = append(newBackups, current.Addr)
	newBackups = append(newBackups, current.Backups...)
	current.Addr = successAddr
	current.Backups = normalizeGatewayAddressList(newBackups, current.Addr, gatewayRouteBundleMaxAddrs-1)
	current.Source = "runtime-success"
	current.ExpiresAt = now.Add(gatewayRouteProbeTTL)
	current.NextProbe = now.Add(gatewayRouteProbeTTL)
	current.Refreshing = false
	endpointGatewayRuntime.routeCache[target] = current
}

func markGatewayRouteCacheCandidateFailure(target, failedAddr string) {
	target = normalizeGatewayAddress(target)
	failedAddr = normalizeGatewayAddress(failedAddr)
	if target == "" || failedAddr == "" {
		return
	}

	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()

	current, exists := endpointGatewayRuntime.routeCache[target]
	if !exists || current.Addr == "" {
		return
	}

	if sameGatewayAddress(current.Addr, failedAddr) {
		if len(current.Backups) == 0 {
			delete(endpointGatewayRuntime.routeCache, target)
			return
		}
		nextPrimary := normalizeGatewayAddress(current.Backups[0])
		if nextPrimary == "" {
			delete(endpointGatewayRuntime.routeCache, target)
			return
		}
		rotatedBackups := make([]string, 0, gatewayRouteBundleMaxAddrs-1)
		seen := map[string]struct{}{nextPrimary: {}}
		for _, raw := range current.Backups[1:] {
			addr := normalizeGatewayAddress(raw)
			if addr == "" || sameGatewayAddress(addr, failedAddr) {
				continue
			}
			if _, exists := seen[addr]; exists {
				continue
			}
			seen[addr] = struct{}{}
			rotatedBackups = append(rotatedBackups, addr)
			if len(rotatedBackups) >= gatewayRouteBundleMaxAddrs-1 {
				break
			}
		}
		oldPrimary := normalizeGatewayAddress(current.Addr)
		if oldPrimary != "" && !sameGatewayAddress(oldPrimary, nextPrimary) {
			if _, exists := seen[oldPrimary]; !exists && len(rotatedBackups) < gatewayRouteBundleMaxAddrs-1 {
				rotatedBackups = append(rotatedBackups, oldPrimary)
			}
		}
		current.Addr = nextPrimary
		current.Backups = rotatedBackups
		current.Source = "runtime-failure-rotate"
		current.NextProbe = now.Add(gatewayRouteProbeBackoff)
		current.ExpiresAt = now.Add(gatewayRouteProbeTTL)
		current.Refreshing = false
		endpointGatewayRuntime.routeCache[target] = current
		return
	}

	filtered := make([]string, 0, gatewayRouteBundleMaxAddrs-1)
	seen := make(map[string]struct{}, len(current.Backups)+1)
	primary := normalizeGatewayAddress(current.Addr)
	if primary != "" {
		seen[primary] = struct{}{}
	}
	for _, raw := range current.Backups {
		backup := normalizeGatewayAddress(raw)
		if backup == "" || sameGatewayAddress(backup, failedAddr) {
			continue
		}
		if _, exists := seen[backup]; exists {
			continue
		}
		seen[backup] = struct{}{}
		filtered = append(filtered, backup)
		if len(filtered) >= gatewayRouteBundleMaxAddrs-1 {
			break
		}
	}
	current.Backups = filtered
	current.NextProbe = now.Add(gatewayRouteProbeBackoff)
	current.ExpiresAt = now.Add(gatewayRouteProbeTTL)
	current.Refreshing = false
	endpointGatewayRuntime.routeCache[target] = current
}

func loadGatewayRouteCacheCandidate(target string, now time.Time) (gatewayRouteProbeCandidate, bool) {
	target = normalizeGatewayAddress(target)
	if target == "" {
		return gatewayRouteProbeCandidate{}, false
	}

	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()

	cached, exists := endpointGatewayRuntime.routeCache[target]
	if !exists || cached.Addr == "" {
		return gatewayRouteProbeCandidate{}, false
	}
	if cached.ExpiresAt.IsZero() || now.After(cached.ExpiresAt) {
		cached.ExpiresAt = now.Add(gatewayRouteProbeTTL)
	}
	shouldRefresh := !cached.Refreshing && (cached.NextProbe.IsZero() || !now.Before(cached.NextProbe))
	if shouldRefresh {
		cached.Refreshing = true
		endpointGatewayRuntime.routeCache[target] = cached
	}
	return cached, shouldRefresh
}

func storeGatewayRouteCacheCandidate(target string, candidate gatewayRouteProbeCandidate) {
	target = normalizeGatewayAddress(target)
	candidate.Addr = normalizeGatewayAddress(candidate.Addr)
	if target == "" || candidate.Addr == "" {
		return
	}
	if isLocalGatewayAddress(candidate.Addr) {
		return
	}

	now := time.Now()
	candidate.ProbedAt = now
	candidate.Backups = normalizeGatewayAddressList(candidate.Backups, candidate.Addr, gatewayRouteBundleMaxAddrs-1)
	candidate.NextProbe = now.Add(gatewayRouteProbeTTL)
	candidate.ExpiresAt = now.Add(gatewayRouteProbeTTL)
	candidate.Refreshing = false

	endpointGatewayRuntime.mu.Lock()
	endpointGatewayRuntime.routeCache[target] = candidate
	endpointGatewayRuntime.mu.Unlock()
}

func refreshGatewayRouteCacheCandidate(target string, connCtx ImmutableConnectionContext) {
	target = normalizeGatewayAddress(target)
	if target == "" {
		return
	}
	now := time.Now()
	candidate, err := probeGatewayRouteCandidate(connCtx, now)
	candidate.Addr = normalizeGatewayAddress(candidate.Addr)
	candidateIsLocal := candidate.Addr != "" && isLocalGatewayAddress(candidate.Addr)

	endpointGatewayRuntime.mu.Lock()
	current := endpointGatewayRuntime.routeCache[target]
	current.Refreshing = false
	current.ExpiresAt = now.Add(gatewayRouteProbeTTL)
	if err != nil || candidate.Addr == "" {
		current.NextProbe = now.Add(gatewayRouteProbeBackoff)
		endpointGatewayRuntime.routeCache[target] = current
		endpointGatewayRuntime.mu.Unlock()
		return
	}

	if candidate.Addr == "" || candidateIsLocal {
		current.NextProbe = now.Add(gatewayRouteProbeBackoff)
		endpointGatewayRuntime.routeCache[target] = current
		endpointGatewayRuntime.mu.Unlock()
		return
	}
	candidate.ProbedAt = now
	candidate.Backups = normalizeGatewayAddressList(candidate.Backups, candidate.Addr, gatewayRouteBundleMaxAddrs-1)
	candidate.NextProbe = now.Add(gatewayRouteProbeTTL)
	candidate.ExpiresAt = now.Add(gatewayRouteProbeTTL)
	candidate.Refreshing = false

	replace := false
	if current.Addr == "" {
		replace = true
	} else if sameGatewayAddress(current.Addr, candidate.Addr) {
		replace = true
	} else {
		replace = candidate.Score+gatewayRouteSwitchEpsilon < current.Score
	}
	if replace {
		endpointGatewayRuntime.routeCache[target] = candidate
	} else {
		current.Backups = mergeGatewayBackupCandidates(current.Backups, candidate.Backups, current.Addr, gatewayRouteBundleMaxAddrs-1)
		current.NextProbe = now.Add(gatewayRouteProbeTTL)
		endpointGatewayRuntime.routeCache[target] = current
	}
	endpointGatewayRuntime.mu.Unlock()
}

func mergeGatewayBackupCandidates(existing, incoming []string, primary string, limit int) []string {
	merged := make([]string, 0, len(existing)+len(incoming))
	merged = append(merged, existing...)
	merged = append(merged, incoming...)
	return normalizeGatewayAddressList(merged, primary, limit)
}

func normalizeGatewayAddressList(addrs []string, primary string, limit int) []string {
	if len(addrs) == 0 || limit <= 0 {
		return nil
	}
	primary = normalizeGatewayAddress(primary)
	seen := make(map[string]struct{}, len(addrs))
	out := make([]string, 0, limit)
	for _, raw := range addrs {
		addr := normalizeGatewayAddress(raw)
		if addr == "" || sameGatewayAddress(addr, primary) {
			continue
		}
		if _, exists := seen[addr]; exists {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func probeGatewayRouteCandidate(connCtx ImmutableConnectionContext, now time.Time) (gatewayRouteProbeCandidate, error) {
	type candidate struct {
		addr   string
		nodeID string
		source string
		score  float64
	}
	candidates := make([]candidate, 0, 8)
	addCandidate := func(addr, nodeID, source string, score float64) {
		addr = normalizeGatewayAddress(addr)
		nodeID = normalizeGatewayNodeID(nodeID)
		if addr == "" || isLocalGatewayAddress(addr) {
			return
		}
		if isGatewayRouteDenied(connCtx.ServerAddress, addr, now) {
			return
		}
		if score < 0 {
			score = 0
		}
		candidates = append(candidates, candidate{
			addr:   addr,
			nodeID: nodeID,
			source: strings.TrimSpace(source),
			score:  score,
		})
	}

	if addr := normalizeGatewayAddress(connCtx.GatewayAddress); addr != "" {
		addCandidate(addr, "", "config", 0.10)
	}

	if connCtx.GatewayDiscovery && connCtx.GatewayDiscoverPort > 0 {
		if discoveredList, err := discoverGatewayAddresses(connCtx.GatewayDiscoverPort, gatewayRouteBundleMaxAddrs); err == nil {
			for idx, discovered := range discoveredList {
				addCandidate(discovered, "", "discovery", 1.00+float64(idx)*0.01)
			}
		}
	}

	selfNode := normalizeGatewayNodeID(connCtx.ConfigID)
	if selfNode == "" {
		selfNode = normalizeGatewayNodeID(connCtx.EndpointName)
	}
	for _, route := range selectGatewayRouteCandidates(connCtx.ServerAddress, nil, selfNode, gatewayRouteBundleMaxAddrs) {
		addCandidate(route.NextHopAddr, route.NextHopNodeID, "route", route.Cost)
	}

	if len(candidates) == 0 {
		return gatewayRouteProbeCandidate{}, errors.New("no gateway candidate available")
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score == candidates[j].score {
			if candidates[i].source == candidates[j].source {
				return candidates[i].addr < candidates[j].addr
			}
			return candidates[i].source < candidates[j].source
		}
		return candidates[i].score < candidates[j].score
	})

	best := candidates[0]
	backups := make([]string, 0, gatewayRouteBundleMaxAddrs-1)
	seenNodes := map[string]struct{}{}
	if best.nodeID != "" {
		seenNodes[best.nodeID] = struct{}{}
	}
	for i := 1; i < len(candidates) && len(backups) < gatewayRouteBundleMaxAddrs-1; i++ {
		c := candidates[i]
		if c.addr == "" || sameGatewayAddress(c.addr, best.addr) {
			continue
		}
		if c.nodeID != "" {
			if _, exists := seenNodes[c.nodeID]; exists {
				continue
			}
			seenNodes[c.nodeID] = struct{}{}
		}
		backups = append(backups, c.addr)
	}

	return gatewayRouteProbeCandidate{
		Addr:      best.addr,
		Backups:   backups,
		NodeID:    best.nodeID,
		Source:    best.source,
		Score:     best.score,
		ProbedAt:  now,
		NextProbe: now.Add(gatewayRouteProbeTTL),
		ExpiresAt: now.Add(gatewayRouteProbeTTL),
	}, nil
}

func acceptGatewayRelayLoop(listener net.Listener, listenAddr string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return
		}
		go handleGatewayRelayConnection(conn, listenAddr)
	}
}

func handleGatewayRelayConnection(clientConn net.Conn, listenAddr string) {
	defer clientConn.Close()
	remoteAddr := ""
	if clientConn.RemoteAddr() != nil {
		remoteAddr = clientConn.RemoteAddr().String()
	}
	DebugLog("[GATEWAY] Inbound relay accepted remote=%s", remoteAddr)

	_ = clientConn.SetDeadline(time.Now().Add(gatewayPreTLSGuardWindow))
	reader := bufio.NewReader(clientConn)
	line, err := readGatewayControlLine(reader)
	if err != nil {
		return
	}

	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) >= 2 && fields[0] == gatewayProtocolVersion && strings.EqualFold(fields[1], gatewayCommandGrid) {
		meta, parseErr := parseGatewayGridLine(line)
		if parseErr != nil {
			_, _ = io.WriteString(clientConn, "ERR invalid request\n")
			return
		}
		rateLimitExempt := shouldExemptInboundGridRateLimit(clientConn.RemoteAddr(), meta)
		session, sessionErr := acquireInboundConnectionSessionWithExemption(clientConn.RemoteAddr(), rateLimitExempt)
		if sessionErr != nil {
			DebugLog("[GATEWAY] Inbound grid relay rate limited remote=%s origin=%s service=%s exempt=%t",
				remoteAddr, meta.OriginNodeID, meta.Service, rateLimitExempt)
			_, _ = io.WriteString(clientConn, "ERR rate limited\n")
			return
		}
		authenticated := false
		defer releaseInboundConnectionSession(session.SessionID, authenticated)
		authenticated = handleGatewayGridConnection(clientConn, reader, meta, session.SessionID)
		return
	}

	targetAddr, meta, parseErr := parseGatewayConnectLine(line)
	if parseErr != nil {
		DebugLog("[GATEWAY] Inbound relay invalid request remote=%s err=%v", remoteAddr, parseErr)
		_, _ = io.WriteString(clientConn, "ERR invalid request\n")
		return
	}
	DebugLog("[GATEWAY] Inbound relay request remote=%s target=%s origin=%s hop=%d service=%s", remoteAddr, targetAddr, meta.OriginNodeID, meta.HopLimit, meta.Service)

	runtimeNodeID := currentGatewayNodeID()
	if !isGatewayRelayAuthorized(targetAddr, meta) {
		DebugLog("[GATEWAY] Inbound relay unauthorized remote=%s target=%s", remoteAddr, targetAddr)
		_, _ = io.WriteString(clientConn, "ERR unauthorized\n")
		return
	}
	if err := validateGatewayRelayRequest(targetAddr, listenAddr, runtimeNodeID, meta); err != nil {
		DebugLog("[GATEWAY] Inbound relay rejected remote=%s target=%s err=%v", remoteAddr, targetAddr, err)
		if strings.Contains(strings.ToLower(err.Error()), "target not allowed") {
			_, _ = io.WriteString(clientConn, "ERR target not allowed\n")
			return
		}
		_, _ = io.WriteString(clientConn, "ERR loop detected\n")
		return
	}

	rateLimitExempt := normalizeGatewayService(meta.Service) == gatewayServiceGrid && isGatewayAllowedTarget(targetAddr)
	session, sessionErr := acquireInboundConnectionSessionWithExemption(clientConn.RemoteAddr(), rateLimitExempt)
	if sessionErr != nil {
		DebugLog("[GATEWAY] Inbound relay rate limited remote=%s target=%s service=%s exempt=%t", remoteAddr, targetAddr, meta.Service, rateLimitExempt)
		_, _ = io.WriteString(clientConn, "ERR rate limited\n")
		return
	}
	authenticated := false
	defer releaseInboundConnectionSession(session.SessionID, authenticated)

	_ = clientConn.SetDeadline(time.Now().Add(gatewayHandshakeTimeout))
	if _, err := completeGatewayKEXServer(clientConn, reader, gatewayCommandConnect, targetAddr, meta); err != nil {
		DebugLog("[GATEWAY] Inbound relay KEX failed remote=%s target=%s err=%v", remoteAddr, targetAddr, err)
		_, _ = io.WriteString(clientConn, "ERR unauthorized\n")
		return
	}
	markInboundConnectionTLSEstablished(session.SessionID)
	authenticated = true

	relayMeta := meta
	if runtimeNodeID != "" {
		relayMeta.Path = appendGatewayPath(relayMeta.Path, runtimeNodeID)
	}

	upstreamConn, err := net.DialTimeout("tcp", targetAddr, 15*time.Second)
	if err != nil {
		DebugLog("[GATEWAY] Inbound relay direct dial failed remote=%s target=%s err=%v", remoteAddr, targetAddr, err)
		if relayMeta.HopLimit <= 1 {
			_, _ = io.WriteString(clientConn, "ERR hop limit exceeded\n")
			return
		}

		candidates := selectGatewayRouteCandidates(targetAddr, relayMeta.Path, runtimeNodeID, 3)
		if len(candidates) == 0 {
			_, _ = io.WriteString(clientConn, "ERR dial upstream failed\n")
			return
		}
		var forwarded bool
		for _, candidate := range candidates {
			forwardMeta := relayMeta
			forwardMeta.HopLimit--
			log.Printf("[GATEWAY] Forward target=%s via peer node=%s addr=%s hop=%d cost=%.3f", targetAddr, candidate.NextHopNodeID, candidate.NextHopAddr, forwardMeta.HopLimit, candidate.Cost)
			started := time.Now()
			upstreamConn, err = dialTunnelServerViaGatewayWithMeta(candidate.NextHopAddr, targetAddr, forwardMeta)
			recordGatewayPeerDialResult(candidate.NextHopNodeID, time.Since(started), err == nil)
			if err == nil {
				forwarded = true
				break
			}
		}
		if !forwarded {
			_, _ = io.WriteString(clientConn, "ERR dial upstream failed\n")
			return
		}
	}
	DebugLog("[GATEWAY] Inbound relay established remote=%s target=%s", remoteAddr, targetAddr)
	defer upstreamConn.Close()

	_, _ = io.WriteString(clientConn, "OK\n")
	_ = clientConn.SetDeadline(time.Time{})

	clientReaderConn := net.Conn(clientConn)
	if buffered := reader.Buffered(); buffered > 0 {
		prefix, peekErr := reader.Peek(buffered)
		if peekErr == nil && len(prefix) > 0 {
			clientReaderConn = &prefixedConn{
				Conn:   clientConn,
				prefix: append([]byte(nil), prefix...),
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamConn, clientReaderConn)
		_ = upstreamConn.SetReadDeadline(time.Now())
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstreamConn)
		_ = clientConn.SetReadDeadline(time.Now())
	}()
	wg.Wait()
}

func handleGatewayGridConnection(clientConn net.Conn, reader *bufio.Reader, meta gatewayConnectMeta, sessionID string) bool {
	runtimeNodeID := currentGatewayNodeID()
	if err := validateGatewayGridRequest(runtimeNodeID, meta); err != nil {
		_, _ = io.WriteString(clientConn, "ERR loop detected\n")
		return false
	}
	_ = clientConn.SetDeadline(time.Now().Add(gatewayHandshakeTimeout))
	integrityKey, err := completeGatewayKEXServer(clientConn, reader, gatewayCommandGrid, "", meta)
	if err != nil {
		_, _ = io.WriteString(clientConn, "ERR unauthorized\n")
		return false
	}
	markInboundConnectionTLSEstablished(sessionID)

	_, _ = io.WriteString(clientConn, "OK\n")
	_ = clientConn.SetDeadline(time.Time{})

	gridConn := net.Conn(clientConn)
	if buffered := reader.Buffered(); buffered > 0 {
		prefix, peekErr := reader.Peek(buffered)
		if peekErr == nil && len(prefix) > 0 {
			gridConn = &prefixedConn{
				Conn:   clientConn,
				prefix: append([]byte(nil), prefix...),
			}
		}
	}
	if strings.TrimSpace(integrityKey) != "" {
		gridConn = &gatewayIntegrityKeyConn{Conn: gridConn, integrityKey: integrityKey}
	}

	handleEndpointGridTransitConnection(gridConn)
	return true
}

func parseGatewayConnectLine(line string) (targetAddr string, meta gatewayConnectMeta, err error) {
	fields, err := parseGatewayCommandFields(line, gatewayCommandConnect, 3)
	meta = gatewayConnectMeta{HopLimit: defaultGatewayHopLimit}
	if err != nil {
		return "", meta, err
	}

	targetAddr = normalizeGatewayAddress(fields[2])
	if targetAddr == "" {
		return "", meta, errors.New("target addr is required")
	}
	if _, _, splitErr := net.SplitHostPort(targetAddr); splitErr != nil {
		return "", meta, fmt.Errorf("invalid target addr: %w", splitErr)
	}

	meta = parseGatewayMetaFields(fields[3:])
	if meta.HopLimit <= 0 {
		return "", meta, errors.New("hop limit exceeded")
	}
	return targetAddr, meta, nil
}

func parseGatewayGridLine(line string) (gatewayConnectMeta, error) {
	fields, err := parseGatewayCommandFields(line, gatewayCommandGrid, 2)
	if err != nil {
		return gatewayConnectMeta{HopLimit: defaultGatewayHopLimit}, err
	}
	meta := parseGatewayMetaFields(fields[2:])
	if normalizeGatewayService(meta.Service) != gatewayServiceGrid {
		return meta, errors.New("grid service is required")
	}
	meta.Service = gatewayServiceGrid
	if meta.HopLimit <= 0 {
		return meta, errors.New("hop limit exceeded")
	}
	return meta, nil
}

func shouldExemptInboundGridRateLimit(remoteAddr net.Addr, meta gatewayConnectMeta) bool {
	if normalizeGatewayService(meta.Service) != gatewayServiceGrid {
		return false
	}
	remoteIP := parseRemoteIP(remoteAddr)
	if remoteIP == "" {
		return false
	}

	origin := normalizeGatewayNodeID(meta.OriginNodeID)
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()

	if origin != "" {
		if peer, ok := endpointGatewayRuntime.peers[origin]; ok && gatewayPeerAddressMatchesRemoteIP(peer.Addr, remoteIP) {
			return true
		}
	}
	for _, peer := range endpointGatewayRuntime.peers {
		if gatewayPeerAddressMatchesRemoteIP(peer.Addr, remoteIP) {
			return true
		}
	}
	return false
}

func gatewayPeerAddressMatchesRemoteIP(peerAddr, remoteIP string) bool {
	peerAddr = normalizeGatewayAddress(peerAddr)
	if peerAddr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(peerAddr)
	if err != nil {
		return false
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, remoteIP) {
		return true
	}
	hostIP := net.ParseIP(host)
	remoteParsed := net.ParseIP(strings.TrimSpace(remoteIP))
	if hostIP != nil && remoteParsed != nil {
		return hostIP.Equal(remoteParsed)
	}
	return false
}

func resolveGatewayAnnouncedPeerAddr(announcedAddr string, remoteAddr *net.UDPAddr) string {
	announcedAddr = normalizeGatewayAddress(announcedAddr)
	if announcedAddr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(announcedAddr)
	if err != nil {
		return ""
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	useRemote := false
	if host == "" || strings.EqualFold(host, "localhost") {
		useRemote = true
	} else if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		useRemote = true
	}
	if isLocalGatewayAddress(announcedAddr) {
		useRemote = true
	}
	if !useRemote {
		return announcedAddr
	}
	if remoteAddr == nil || remoteAddr.IP == nil || remoteAddr.IP.IsUnspecified() {
		return announcedAddr
	}
	return net.JoinHostPort(remoteAddr.IP.String(), port)
}

func parseGatewayCommandFields(line string, command string, minFields int) ([]string, error) {
	if err := validateGatewayControlPayload(line); err != nil {
		return nil, err
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < minFields {
		return nil, errors.New("invalid gateway command")
	}
	if fields[0] != gatewayProtocolVersion || !strings.EqualFold(fields[1], command) {
		return nil, errors.New("unsupported gateway request")
	}
	return fields, nil
}

func parseGatewayMetaFields(fields []string) gatewayConnectMeta {
	meta := gatewayConnectMeta{HopLimit: defaultGatewayHopLimit}
	for _, raw := range fields {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}

		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		value := decodeGatewayField(strings.TrimSpace(part[eq+1:]))
		switch key {
		case "origin":
			meta.OriginNodeID = normalizeGatewayNodeID(value)
		case "path":
			meta.Path = parseGatewayPath(value)
		case "hop":
			if hop, convErr := strconv.Atoi(strings.TrimSpace(value)); convErr == nil {
				meta.HopLimit = hop
			}
		case "service":
			meta.Service = normalizeGatewayService(value)
		case "kex":
			meta.KEXPublicKey = strings.TrimSpace(value)
		case "nonce":
			meta.KEXNonce = strings.TrimSpace(value)
		}
	}

	meta.Path = normalizeGatewayPath(meta.Path)
	if meta.OriginNodeID == "" && len(meta.Path) > 0 {
		meta.OriginNodeID = meta.Path[0]
	}
	if meta.HopLimit > maxGatewayHopLimit {
		meta.HopLimit = maxGatewayHopLimit
	}
	meta.Service = normalizeGatewayService(meta.Service)
	return meta
}

func validateGatewayRelayRequest(targetAddr, listenAddr, nodeID string, meta gatewayConnectMeta) error {
	if meta.HopLimit <= 0 {
		return errors.New("hop limit exceeded")
	}
	if sameGatewayAddress(targetAddr, listenAddr) {
		return errors.New("self-loop target")
	}
	if !isGatewayAllowedTarget(targetAddr) {
		return errors.New("target not allowed")
	}

	selfNode := normalizeGatewayNodeID(nodeID)
	if selfNode != "" {
		if normalizeGatewayNodeID(meta.OriginNodeID) == selfNode {
			return errors.New("origin loop")
		}
		if gatewayPathContains(meta.Path, selfNode) {
			return errors.New("path loop")
		}
	}
	return nil
}

func validateGatewayGridRequest(nodeID string, meta gatewayConnectMeta) error {
	if meta.HopLimit <= 0 {
		return errors.New("hop limit exceeded")
	}
	selfNode := normalizeGatewayNodeID(nodeID)
	if selfNode == "" {
		return nil
	}
	if normalizeGatewayNodeID(meta.OriginNodeID) == selfNode {
		return errors.New("origin loop")
	}
	if gatewayPathContains(meta.Path, selfNode) {
		return errors.New("path loop")
	}
	return nil
}

func dialTunnelServerViaGateway(gatewayAddr, targetAddr, originNodeID string) (net.Conn, error) {
	meta := gatewayConnectMeta{
		OriginNodeID: normalizeGatewayNodeID(originNodeID),
		HopLimit:     defaultGatewayHopLimit,
	}
	if meta.OriginNodeID != "" {
		meta.Path = []string{meta.OriginNodeID}
	}
	return dialTunnelServerViaGatewayWithMeta(gatewayAddr, targetAddr, meta)
}

func dialTunnelServerViaGatewayWithMeta(gatewayAddr, targetAddr string, meta gatewayConnectMeta) (net.Conn, error) {
	gatewayAddr = normalizeGatewayAddress(gatewayAddr)
	if gatewayAddr == "" {
		return nil, errors.New("gateway address is required")
	}
	targetAddr = normalizeGatewayAddress(targetAddr)
	if targetAddr == "" {
		return nil, errors.New("target address is required")
	}
	if sameGatewayAddress(gatewayAddr, targetAddr) {
		return nil, errors.New("gateway and target are identical")
	}

	if meta.HopLimit <= 0 {
		meta.HopLimit = defaultGatewayHopLimit
	}
	if meta.HopLimit > maxGatewayHopLimit {
		meta.HopLimit = maxGatewayHopLimit
	}
	meta.Path = normalizeGatewayPath(meta.Path)
	kexOffer, err := newGatewayKEXOffer()
	if err != nil {
		return nil, err
	}
	meta.KEXPublicKey = kexOffer.publicKey
	meta.KEXNonce = kexOffer.nonce

	dialer := &net.Dialer{Timeout: gatewayDialTimeout, KeepAlive: 30 * time.Second}
	conn, err := dialer.Dial("tcp", gatewayAddr)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(gatewayHandshakeTimeout))
	connectLine := buildGatewayConnectLine(targetAddr, meta)
	if _, err := io.WriteString(conn, connectLine); err != nil {
		_ = conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	respLine, err := readGatewayControlLine(reader)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	integrityKey, err := completeGatewayKEXClient(conn, reader, respLine, gatewayCommandConnect, targetAddr, meta, kexOffer)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})
	buffered := reader.Buffered()
	if buffered == 0 {
		if strings.TrimSpace(integrityKey) != "" {
			return &gatewayIntegrityKeyConn{Conn: conn, integrityKey: integrityKey}, nil
		}
		return conn, nil
	}
	prefixBytes, err := reader.Peek(buffered)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	prefix := make([]byte, len(prefixBytes))
	copy(prefix, prefixBytes)
	out := net.Conn(&prefixedConn{Conn: conn, prefix: prefix})
	if strings.TrimSpace(integrityKey) != "" {
		out = &gatewayIntegrityKeyConn{Conn: out, integrityKey: integrityKey}
	}
	return out, nil
}

func dialGatewayPeerGrid(nodeID string) (net.Conn, error) {
	nodeID = normalizeGatewayNodeID(nodeID)
	if nodeID == "" {
		return nil, errors.New("peer node id is required")
	}

	endpointGatewayRuntime.mu.Lock()
	peer, ok := endpointGatewayRuntime.peers[nodeID]
	origin := normalizeGatewayNodeID(endpointGatewayRuntime.nodeID)
	endpointGatewayRuntime.mu.Unlock()

	if !ok || strings.TrimSpace(peer.Addr) == "" {
		return nil, fmt.Errorf("gateway peer %s not discovered", nodeID)
	}

	meta := gatewayConnectMeta{
		OriginNodeID: origin,
		HopLimit:     defaultGatewayHopLimit,
	}
	if origin != "" {
		meta.Path = []string{origin}
	}
	started := time.Now()
	conn, err := dialGatewayGridWithMeta(peer.Addr, meta)
	recordGatewayPeerDialResult(nodeID, time.Since(started), err == nil)
	return conn, err
}

func selectGatewayPeerDialCandidates(primaryNodeID string, exclude []string, limit int) []string {
	primaryNodeID = normalizeGatewayNodeID(primaryNodeID)
	if limit <= 0 {
		limit = gatewayRouteBundleMaxAddrs
	}

	excludeSet := make(map[string]struct{}, len(exclude)+1)
	for _, raw := range exclude {
		node := normalizeGatewayNodeID(raw)
		if node == "" {
			continue
		}
		excludeSet[node] = struct{}{}
	}

	type peerCandidate struct {
		nodeID string
		cost   float64
	}
	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	pruneGatewayStateLocked(now)
	localListenAddr := endpointGatewayRuntime.listenAddr
	localNodeSet := make(map[string]struct{}, len(endpointGatewayRuntime.peers))
	peerCandidates := make([]peerCandidate, 0, len(endpointGatewayRuntime.peers))
	for nodeID, peer := range endpointGatewayRuntime.peers {
		nodeID = normalizeGatewayNodeID(nodeID)
		if nodeID == "" || strings.TrimSpace(peer.Addr) == "" {
			continue
		}
		if isLocalGatewayAddressWithListenAddr(peer.Addr, localListenAddr) {
			localNodeSet[nodeID] = struct{}{}
			continue
		}
		if _, blocked := excludeSet[nodeID]; blocked {
			continue
		}
		metric := endpointGatewayRuntime.peerMetrics[nodeID]
		cost := gatewayRouteCost(1, peer.LastSeen, metric, now)
		peerCandidates = append(peerCandidates, peerCandidate{nodeID: nodeID, cost: cost})
	}
	endpointGatewayRuntime.mu.Unlock()

	sort.SliceStable(peerCandidates, func(i, j int) bool {
		if peerCandidates[i].cost == peerCandidates[j].cost {
			return peerCandidates[i].nodeID < peerCandidates[j].nodeID
		}
		return peerCandidates[i].cost < peerCandidates[j].cost
	})

	out := make([]string, 0, limit)
	seen := make(map[string]struct{}, limit)
	add := func(nodeID string) {
		nodeID = normalizeGatewayNodeID(nodeID)
		if nodeID == "" {
			return
		}
		if _, isLocal := localNodeSet[nodeID]; isLocal {
			return
		}
		if _, blocked := excludeSet[nodeID]; blocked {
			return
		}
		if _, exists := seen[nodeID]; exists {
			return
		}
		seen[nodeID] = struct{}{}
		out = append(out, nodeID)
	}

	if primaryNodeID != "" {
		add(primaryNodeID)
	}
	for _, c := range peerCandidates {
		if len(out) >= limit {
			break
		}
		add(c.nodeID)
	}
	return out
}

func dialGatewayPeerGridBundle(primaryNodeID string, exclude []string, limit int) (net.Conn, string, error) {
	candidates := selectGatewayPeerDialCandidates(primaryNodeID, exclude, limit)
	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("no gateway peer candidate available (primary=%s)", strings.TrimSpace(primaryNodeID))
	}
	if len(candidates) == 1 {
		conn, err := dialGatewayPeerGrid(candidates[0])
		if err != nil {
			return nil, "", err
		}
		return conn, candidates[0], nil
	}

	type dialResult struct {
		nodeID string
		conn   net.Conn
		err    error
	}
	results := make(chan dialResult, len(candidates))
	for _, nodeID := range candidates {
		nodeID := nodeID
		go func() {
			conn, err := dialGatewayPeerGrid(nodeID)
			results <- dialResult{nodeID: nodeID, conn: conn, err: err}
		}()
	}

	var (
		lastErr  error
		received int
	)
	for received < len(candidates) {
		res := <-results
		received++
		if res.err == nil && res.conn != nil {
			winnerConn := res.conn
			winnerNodeID := res.nodeID
			go func(remaining int) {
				for i := 0; i < remaining; i++ {
					r := <-results
					if r.err == nil && r.conn != nil && r.conn != winnerConn {
						_ = r.conn.Close()
					}
				}
			}(len(candidates) - received)
			return winnerConn, winnerNodeID, nil
		}
		lastErr = res.err
	}
	return nil, "", fmt.Errorf("gateway peer bundle failed (primary=%s): %w", strings.TrimSpace(primaryNodeID), lastErr)
}

func dialGatewayGridWithMeta(peerAddr string, meta gatewayConnectMeta) (net.Conn, error) {
	peerAddr = normalizeGatewayAddress(peerAddr)
	if peerAddr == "" {
		return nil, errors.New("peer address is required")
	}

	if meta.HopLimit <= 0 {
		meta.HopLimit = defaultGatewayHopLimit
	}
	if meta.HopLimit > maxGatewayHopLimit {
		meta.HopLimit = maxGatewayHopLimit
	}
	if normalizeGatewayService(meta.Service) == "" {
		meta.Service = gatewayServiceGrid
	}
	meta.Path = normalizeGatewayPath(meta.Path)
	kexOffer, err := newGatewayKEXOffer()
	if err != nil {
		return nil, err
	}
	meta.KEXPublicKey = kexOffer.publicKey
	meta.KEXNonce = kexOffer.nonce

	dialer := &net.Dialer{Timeout: gatewayDialTimeout, KeepAlive: 30 * time.Second}
	conn, err := dialer.Dial("tcp", peerAddr)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(gatewayHandshakeTimeout))
	if _, err := io.WriteString(conn, buildGatewayGridLine(meta)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	respLine, err := readGatewayControlLine(reader)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	integrityKey, err := completeGatewayKEXClient(conn, reader, respLine, gatewayCommandGrid, "", meta, kexOffer)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})
	buffered := reader.Buffered()
	if buffered == 0 {
		if strings.TrimSpace(integrityKey) != "" {
			return &gatewayIntegrityKeyConn{Conn: conn, integrityKey: integrityKey}, nil
		}
		return conn, nil
	}
	prefixBytes, err := reader.Peek(buffered)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	prefix := make([]byte, len(prefixBytes))
	copy(prefix, prefixBytes)
	out := net.Conn(&prefixedConn{Conn: conn, prefix: prefix})
	if strings.TrimSpace(integrityKey) != "" {
		out = &gatewayIntegrityKeyConn{Conn: out, integrityKey: integrityKey}
	}
	return out, nil
}

func buildGatewayConnectLine(targetAddr string, meta gatewayConnectMeta) string {
	parts := []string{
		gatewayProtocolVersion,
		gatewayCommandConnect,
		normalizeGatewayAddress(targetAddr),
	}
	if origin := normalizeGatewayNodeID(meta.OriginNodeID); origin != "" {
		parts = append(parts, "origin="+encodeGatewayField(origin))
	}
	if len(meta.Path) > 0 {
		parts = append(parts, "path="+encodeGatewayField(strings.Join(normalizeGatewayPath(meta.Path), ",")))
	}
	hop := meta.HopLimit
	if hop <= 0 {
		hop = defaultGatewayHopLimit
	}
	parts = append(parts, "hop="+strconv.Itoa(hop))
	if service := normalizeGatewayService(meta.Service); service != "" {
		parts = append(parts, "service="+encodeGatewayField(service))
	}
	if kex := strings.TrimSpace(meta.KEXPublicKey); kex != "" {
		parts = append(parts, "kex="+encodeGatewayField(kex))
	}
	if nonce := strings.TrimSpace(meta.KEXNonce); nonce != "" {
		parts = append(parts, "nonce="+encodeGatewayField(nonce))
	}
	return strings.Join(parts, " ") + "\n"
}

func buildGatewayGridLine(meta gatewayConnectMeta) string {
	parts := []string{
		gatewayProtocolVersion,
		gatewayCommandGrid,
	}
	if origin := normalizeGatewayNodeID(meta.OriginNodeID); origin != "" {
		parts = append(parts, "origin="+encodeGatewayField(origin))
	}
	if len(meta.Path) > 0 {
		parts = append(parts, "path="+encodeGatewayField(strings.Join(normalizeGatewayPath(meta.Path), ",")))
	}
	hop := meta.HopLimit
	if hop <= 0 {
		hop = defaultGatewayHopLimit
	}
	parts = append(parts, "hop="+strconv.Itoa(hop))
	if service := normalizeGatewayService(meta.Service); service != "" {
		parts = append(parts, "service="+encodeGatewayField(service))
	}
	if kex := strings.TrimSpace(meta.KEXPublicKey); kex != "" {
		parts = append(parts, "kex="+encodeGatewayField(kex))
	}
	if nonce := strings.TrimSpace(meta.KEXNonce); nonce != "" {
		parts = append(parts, "nonce="+encodeGatewayField(nonce))
	}
	return strings.Join(parts, " ") + "\n"
}

func parseGatewayKVFields(fields []string) map[string]string {
	kv := make(map[string]string, len(fields))
	for _, raw := range fields {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		value := decodeGatewayField(strings.TrimSpace(part[eq+1:]))
		kv[key] = strings.TrimSpace(value)
	}
	return kv
}

func newGatewayKEXOffer() (*gatewayKEXOffer, error) {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nonceRaw := make([]byte, gatewayKEXNonceBytes)
	if _, err := rand.Read(nonceRaw); err != nil {
		return nil, err
	}
	return &gatewayKEXOffer{
		privateKey: privateKey,
		publicKey:  base64.RawStdEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		nonce:      hex.EncodeToString(nonceRaw),
	}, nil
}

func deriveGatewayKEXShared(privateKey *ecdh.PrivateKey, peerPublicKey string) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("missing local kex private key")
	}
	peerPublicKey = strings.TrimSpace(peerPublicKey)
	if peerPublicKey == "" {
		return nil, errors.New("missing peer kex public key")
	}
	peerRaw, err := base64.RawStdEncoding.DecodeString(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid peer kex key encoding: %w", err)
	}
	curve := ecdh.X25519()
	peer, err := curve.NewPublicKey(peerRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid peer kex public key: %w", err)
	}
	return privateKey.ECDH(peer)
}

func deriveGatewayKEXAuthKey(shared []byte, command, targetAddr string, meta gatewayConnectMeta, clientPublicKey, serverPublicKey, clientNonce, serverNonce string) []byte {
	mac := hmac.New(sha256.New, shared)
	writeField := func(v string) {
		mac.Write([]byte(strings.TrimSpace(v)))
		mac.Write([]byte{'\n'})
	}
	writeField("gw-kex-auth-v1")
	writeField(gatewayProtocolVersion)
	writeField(strings.ToUpper(strings.TrimSpace(command)))
	writeField(normalizeGatewayAddress(targetAddr))
	writeField(normalizeGatewayNodeID(meta.OriginNodeID))
	writeField(strings.Join(normalizeGatewayPath(meta.Path), ","))
	hop := meta.HopLimit
	if hop <= 0 {
		hop = defaultGatewayHopLimit
	}
	writeField(strconv.Itoa(hop))
	writeField(normalizeGatewayService(meta.Service))
	writeField(clientPublicKey)
	writeField(serverPublicKey)
	writeField(clientNonce)
	writeField(serverNonce)
	return mac.Sum(nil)
}

func computeGatewayKEXProof(authKey []byte, role string) string {
	mac := hmac.New(sha256.New, authKey)
	mac.Write([]byte("gw-kex-proof-v1"))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(role))))
	return hex.EncodeToString(mac.Sum(nil))
}

func deriveGatewayKEXIntegritySecret(authKey []byte) string {
	h := sha256.New()
	h.Write(authKey)
	h.Write([]byte(":gw-grid-integrity-v1"))
	return hex.EncodeToString(h.Sum(nil))
}

func buildGatewayChallengeLine(serverPublicKey, serverNonce, proof string) string {
	parts := []string{
		gatewayProtocolVersion,
		gatewayCommandChallenge,
		"skey=" + encodeGatewayField(strings.TrimSpace(serverPublicKey)),
		"snonce=" + encodeGatewayField(strings.TrimSpace(serverNonce)),
		"proof=" + encodeGatewayField(strings.TrimSpace(proof)),
	}
	return strings.Join(parts, " ") + "\n"
}

func buildGatewayAuthLine(proof string) string {
	parts := []string{
		gatewayProtocolVersion,
		gatewayCommandAuth,
		"proof=" + encodeGatewayField(strings.TrimSpace(proof)),
	}
	return strings.Join(parts, " ") + "\n"
}

func completeGatewayKEXClient(conn net.Conn, reader *bufio.Reader, initialResponseLine, command, targetAddr string, meta gatewayConnectMeta, offer *gatewayKEXOffer) (string, error) {
	if offer == nil || offer.privateKey == nil {
		return "", errors.New("missing local kex offer")
	}
	fields, err := parseGatewayCommandFields(initialResponseLine, gatewayCommandChallenge, 3)
	if err != nil {
		return "", fmt.Errorf("gateway rejected kex challenge: %s", strings.TrimSpace(initialResponseLine))
	}
	kv := parseGatewayKVFields(fields[2:])
	serverPublicKey := strings.TrimSpace(kv["skey"])
	serverNonce := strings.TrimSpace(kv["snonce"])
	serverProof := strings.ToLower(strings.TrimSpace(kv["proof"]))
	if serverPublicKey == "" || serverNonce == "" || serverProof == "" {
		return "", errors.New("gateway kex challenge missing fields")
	}
	shared, err := deriveGatewayKEXShared(offer.privateKey, serverPublicKey)
	if err != nil {
		return "", err
	}
	authKey := deriveGatewayKEXAuthKey(shared, command, targetAddr, meta, offer.publicKey, serverPublicKey, offer.nonce, serverNonce)
	expectedServerProof := computeGatewayKEXProof(authKey, "server")
	if !hmac.Equal([]byte(serverProof), []byte(strings.ToLower(expectedServerProof))) {
		return "", errors.New("gateway kex server proof mismatch")
	}
	clientProof := computeGatewayKEXProof(authKey, "client")
	if _, err := io.WriteString(conn, buildGatewayAuthLine(clientProof)); err != nil {
		return "", err
	}
	finalLine, err := readGatewayControlLine(reader)
	if err != nil {
		return "", err
	}
	finalLine = strings.TrimSpace(finalLine)
	if !strings.HasPrefix(finalLine, "OK") {
		return "", fmt.Errorf("gateway rejected auth: %s", finalLine)
	}
	return deriveGatewayKEXIntegritySecret(authKey), nil
}

func completeGatewayKEXServer(conn net.Conn, reader *bufio.Reader, command, targetAddr string, meta gatewayConnectMeta) (string, error) {
	clientPublicKey := strings.TrimSpace(meta.KEXPublicKey)
	clientNonce := strings.TrimSpace(meta.KEXNonce)
	if clientPublicKey == "" || clientNonce == "" {
		return "", errors.New("missing kex parameters")
	}
	offer, err := newGatewayKEXOffer()
	if err != nil {
		return "", err
	}
	shared, err := deriveGatewayKEXShared(offer.privateKey, clientPublicKey)
	if err != nil {
		return "", err
	}
	authKey := deriveGatewayKEXAuthKey(shared, command, targetAddr, meta, clientPublicKey, offer.publicKey, clientNonce, offer.nonce)
	serverProof := computeGatewayKEXProof(authKey, "server")
	if _, err := io.WriteString(conn, buildGatewayChallengeLine(offer.publicKey, offer.nonce, serverProof)); err != nil {
		return "", err
	}
	authLine, err := readGatewayControlLine(reader)
	if err != nil {
		return "", err
	}
	fields, err := parseGatewayCommandFields(authLine, gatewayCommandAuth, 3)
	if err != nil {
		return "", errors.New("invalid auth response")
	}
	kv := parseGatewayKVFields(fields[2:])
	clientProof := strings.ToLower(strings.TrimSpace(kv["proof"]))
	if clientProof == "" {
		return "", errors.New("missing auth proof")
	}
	expectedClientProof := computeGatewayKEXProof(authKey, "client")
	if !hmac.Equal([]byte(clientProof), []byte(strings.ToLower(expectedClientProof))) {
		return "", errors.New("auth proof mismatch")
	}
	return deriveGatewayKEXIntegritySecret(authKey), nil
}

func serveGatewayDiscovery(conn *net.UDPConn, listenAddr string) {
	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg := strings.TrimSpace(string(buf[:n]))
		if msg == "" {
			continue
		}

		if strings.HasPrefix(msg, gatewayDiscoverMagic) {
			announceAddr := buildGatewayAnnounceAddr(listenAddr, remoteAddr.IP)
			resp := fmt.Sprintf("%s %s\n", gatewayAnnounceMagic, announceAddr)
			_, _ = conn.WriteToUDP([]byte(resp), remoteAddr)
			if peerLine := buildGatewayPeerAnnounceLine(listenAddr); peerLine != "" {
				_, _ = conn.WriteToUDP([]byte(peerLine+"\n"), remoteAddr)
			}
			continue
		}

		if strings.HasPrefix(msg, gatewayPeerMagic+" ") {
			if applyGatewayPeerAnnounce(msg, remoteAddr) {
				if peerLine := buildGatewayPeerAnnounceLine(listenAddr); peerLine != "" {
					_, _ = conn.WriteToUDP([]byte(peerLine+"\n"), remoteAddr)
				}
			}
		}
	}
}

func broadcastGatewayPresence(conn *net.UDPConn, discoverPort int, listenAddr string) {
	if discoverPort <= 0 {
		return
	}

	send := func() {
		peerLine := buildGatewayPeerAnnounceLine(listenAddr)
		if peerLine == "" {
			return
		}
		payload := []byte(peerLine + "\n")
		_, _ = conn.WriteToUDP(payload, &net.UDPAddr{IP: net.IPv4bcast, Port: discoverPort})
	}

	send()
	ticker := time.NewTicker(gatewayPeerBroadcastInterval)
	defer ticker.Stop()
	for range ticker.C {
		send()
		pruneGatewayState(time.Now())
	}
}

func buildGatewayPeerAnnounceLine(listenAddr string) string {
	listenAddr = normalizeGatewayAddress(listenAddr)
	if listenAddr == "" {
		return ""
	}

	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()

	now := time.Now()
	pruneGatewayStateLocked(now)

	nodeID := normalizeGatewayNodeID(endpointGatewayRuntime.nodeID)
	if nodeID == "" {
		return ""
	}

	parts := []string{
		gatewayPeerMagic,
		"node=" + encodeGatewayField(nodeID),
		"addr=" + encodeGatewayField(listenAddr),
	}

	peerEntries := make([]string, 0, len(endpointGatewayRuntime.peers))
	for peerNodeID, peer := range endpointGatewayRuntime.peers {
		if peerNodeID == "" || peer.Addr == "" || peerNodeID == nodeID {
			continue
		}
		peerEntries = append(peerEntries, peerNodeID+"@"+peer.Addr)
		if len(peerEntries) >= maxGatewayAnnounceEntries {
			break
		}
	}
	if len(peerEntries) > 0 {
		parts = append(parts, "peers="+encodeGatewayField(strings.Join(peerEntries, ",")))
	}

	targetEntries := make([]string, 0, len(endpointGatewayRuntime.directTargets)+len(endpointGatewayRuntime.targetRoutes))
	directSeen := make(map[string]struct{}, len(endpointGatewayRuntime.directTargets))
	for target := range endpointGatewayRuntime.directTargets {
		if target == "" {
			continue
		}
		directSeen[target] = struct{}{}
		targetEntries = append(targetEntries, target+"@0")
		if len(targetEntries) >= maxGatewayAnnounceEntries {
			break
		}
	}
	if len(targetEntries) < maxGatewayAnnounceEntries {
		for target, route := range endpointGatewayRuntime.targetRoutes {
			if target == "" {
				continue
			}
			if _, exists := directSeen[target]; exists {
				continue
			}
			hop := route.Hop
			if hop <= 0 {
				hop = 1
			}
			targetEntries = append(targetEntries, target+"@"+strconv.Itoa(hop))
			if len(targetEntries) >= maxGatewayAnnounceEntries {
				break
			}
		}
	}
	if len(targetEntries) > 0 {
		parts = append(parts, "targets="+encodeGatewayField(strings.Join(targetEntries, ",")))
	}

	return strings.Join(parts, " ")
}

func generateGatewayPeerAuthNonce() string {
	buf := make([]byte, gatewayPeerAuthNonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func isGatewayPeerAuthTimestampFresh(ts int64) bool {
	if ts <= 0 {
		return false
	}
	now := time.Now().UTC().Unix()
	delta := now - ts
	if delta < 0 {
		delta = -delta
	}
	return time.Duration(delta)*time.Second <= gatewayPeerAuthWindow
}

func computeGatewayPeerAnnounceSignature(token, nodeID, addr, peers, targets string, ts int64, nonce string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(token))
	writeField := func(v string) {
		mac.Write([]byte(v))
		mac.Write([]byte{'\n'})
	}
	writeField("gw-peer-auth-v1")
	writeField(normalizeGatewayNodeID(nodeID))
	writeField(normalizeGatewayAddress(addr))
	writeField(strings.TrimSpace(peers))
	writeField(strings.TrimSpace(targets))
	writeField(strconv.FormatInt(ts, 10))
	writeField(strings.TrimSpace(nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

func consumeGatewayPeerAuthReplayLocked(nodeID, nonce string, ts int64, now time.Time) bool {
	nowUnix := now.UTC().Unix()
	for key, exp := range endpointGatewayRuntime.peerAuthSeen {
		if exp < nowUnix {
			delete(endpointGatewayRuntime.peerAuthSeen, key)
		}
	}
	key := normalizeGatewayNodeID(nodeID) + "|" + strings.TrimSpace(nonce)
	if key == "|" {
		return false
	}
	if exp, exists := endpointGatewayRuntime.peerAuthSeen[key]; exists && exp >= nowUnix {
		return false
	}
	expiry := ts + int64((gatewayPeerAuthWindow + time.Minute).Seconds())
	endpointGatewayRuntime.peerAuthSeen[key] = expiry
	if len(endpointGatewayRuntime.peerAuthSeen) > gatewayPeerAuthReplayEntries {
		toDelete := len(endpointGatewayRuntime.peerAuthSeen) - gatewayPeerAuthReplayEntries
		for k := range endpointGatewayRuntime.peerAuthSeen {
			delete(endpointGatewayRuntime.peerAuthSeen, k)
			toDelete--
			if toDelete <= 0 {
				break
			}
		}
	}
	return true
}

func applyGatewayPeerAnnounce(msg string, remoteAddr *net.UDPAddr) bool {
	if len(msg) > gatewayMaxControlPayloadSize {
		return false
	}
	if err := validateGatewayControlPayload(msg); err != nil {
		return false
	}
	fields := strings.Fields(strings.TrimSpace(msg))
	if len(fields) < 2 || fields[0] != gatewayPeerMagic {
		return false
	}

	kv := make(map[string]string, len(fields)-1)
	for _, field := range fields[1:] {
		eq := strings.IndexByte(field, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(field[:eq]))
		value := decodeGatewayField(strings.TrimSpace(field[eq+1:]))
		kv[key] = value
	}

	nodeID := normalizeGatewayNodeID(kv["node"])
	announcedAddr := normalizeGatewayAddress(kv["addr"])
	peerAddr := resolveGatewayAnnouncedPeerAddr(announcedAddr, remoteAddr)
	if peerAddr == "" || nodeID == "" {
		return false
	}

	peerTargets := parseGatewayTargetEntries(kv["targets"])
	peerRoutes := parseGatewayPeerEntries(kv["peers"])

	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()

	pruneGatewayStateLocked(now)

	selfNodeID := normalizeGatewayNodeID(endpointGatewayRuntime.nodeID)
	if selfNodeID != "" && nodeID == selfNodeID {
		return false
	}

	updated := upsertGatewayPeerLocked(nodeID, peerAddr, now)

	for _, target := range peerTargets {
		if target.Hop == 0 {
			targetKey := normalizeGatewayAddress(target.Target)
			if targetKey != "" {
				entry, exists := endpointGatewayRuntime.directRoutes[targetKey]
				if !exists || entry == nil {
					entry = make(map[string]time.Time)
					endpointGatewayRuntime.directRoutes[targetKey] = entry
				}
				entry[nodeID] = now
			}
		}
		hop := target.Hop + 1
		if hop > maxGatewayHopLimit {
			continue
		}
		if upsertGatewayTargetRouteLocked(target.Target, nodeID, peerAddr, hop, now) {
			updated = true
		}
	}

	for _, peerRoute := range peerRoutes {
		if peerRoute.NodeID == "" || peerRoute.Addr == "" {
			continue
		}
		if selfNodeID != "" && peerRoute.NodeID == selfNodeID {
			continue
		}
		if upsertGatewayPeerLocked(peerRoute.NodeID, peerRoute.Addr, now) {
			updated = true
		}
	}

	return updated
}

func parseGatewayTargetEntries(raw string) []gatewayTargetRoute {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	items := strings.Split(raw, ",")
	out := make([]gatewayTargetRoute, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.Split(item, "@")
		if len(parts) != 2 {
			continue
		}
		target := normalizeGatewayAddress(parts[0])
		if target == "" {
			continue
		}
		hop, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}
		if hop < 0 {
			hop = 0
		}
		out = append(out, gatewayTargetRoute{Target: target, Hop: hop})
	}
	return out
}

func parseGatewayPeerEntries(raw string) []gatewayPeerInfo {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	items := strings.Split(raw, ",")
	out := make([]gatewayPeerInfo, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "@", 2)
		if len(parts) != 2 {
			continue
		}
		nodeID := normalizeGatewayNodeID(parts[0])
		addr := normalizeGatewayAddress(parts[1])
		if nodeID == "" || addr == "" {
			continue
		}
		out = append(out, gatewayPeerInfo{NodeID: nodeID, Addr: addr})
	}
	return out
}

func selectGatewayRoute(targetAddr string, path []string, selfNodeID string) (string, string) {
	candidates := selectGatewayRouteCandidates(targetAddr, path, selfNodeID, 1)
	if len(candidates) == 0 {
		return "", ""
	}
	return candidates[0].NextHopAddr, candidates[0].NextHopNodeID
}

func selectGatewayRouteCandidates(targetAddr string, path []string, selfNodeID string, limit int) []gatewayRouteCandidate {
	target := normalizeGatewayAddress(targetAddr)
	if limit <= 0 {
		limit = 1
	}
	now := time.Now()
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()

	pruneGatewayStateLocked(now)
	path = normalizeGatewayPath(path)
	selfNodeID = normalizeGatewayNodeID(selfNodeID)
	localListenAddr := endpointGatewayRuntime.listenAddr
	selfAddr := normalizeGatewayAddress(localListenAddr)

	candidates := make([]gatewayRouteCandidate, 0, len(endpointGatewayRuntime.peers)+1)
	seen := make(map[string]struct{}, len(endpointGatewayRuntime.peers)+1)
	addCandidate := func(nodeID, addr string, hop int, lastSeen time.Time) {
		nodeID = normalizeGatewayNodeID(nodeID)
		addr = normalizeGatewayAddress(addr)
		if nodeID == "" || addr == "" {
			return
		}
		if isLocalGatewayAddressWithListenAddr(addr, localListenAddr) {
			return
		}
		if sameGatewayAddress(addr, selfAddr) {
			return
		}
		if gatewayPathContains(path, nodeID) {
			return
		}
		if selfNodeID != "" && nodeID == selfNodeID {
			return
		}
		if _, exists := seen[nodeID]; exists {
			return
		}
		seen[nodeID] = struct{}{}
		metric := endpointGatewayRuntime.peerMetrics[nodeID]
		cost := gatewayRouteCost(hop, lastSeen, metric, now)
		candidates = append(candidates, gatewayRouteCandidate{
			NextHopNodeID: nodeID,
			NextHopAddr:   addr,
			Hop:           hop,
			LastSeen:      lastSeen,
			Cost:          cost,
		})
	}

	if target != "" {
		if directPeers, exists := endpointGatewayRuntime.directRoutes[target]; exists {
			for peerNodeID, directSeenAt := range directPeers {
				peer, ok := endpointGatewayRuntime.peers[peerNodeID]
				if !ok {
					continue
				}
				lastSeen := peer.LastSeen
				if directSeenAt.After(lastSeen) {
					lastSeen = directSeenAt
				}
				addCandidate(peerNodeID, peer.Addr, 1, lastSeen)
			}
		}
		if route, exists := endpointGatewayRuntime.targetRoutes[target]; exists {
			addCandidate(route.NextHopNodeID, route.NextHopAddr, route.Hop, route.LastSeen)
		}
	}
	for peerNodeID, peer := range endpointGatewayRuntime.peers {
		addCandidate(peerNodeID, peer.Addr, 2, peer.LastSeen)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Cost == candidates[j].Cost {
			if candidates[i].Hop == candidates[j].Hop {
				return candidates[i].NextHopNodeID < candidates[j].NextHopNodeID
			}
			return candidates[i].Hop < candidates[j].Hop
		}
		return candidates[i].Cost < candidates[j].Cost
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

func gatewayRouteCost(hop int, lastSeen time.Time, metric gatewayPeerMetric, now time.Time) float64 {
	if hop <= 0 {
		hop = 1
	}
	rttMs := metric.RTTEwmaMs
	if rttMs <= 0 {
		rttMs = 35
	}
	jitterMs := metric.JitterEwmaMs
	if jitterMs < 0 {
		jitterMs = 0
	}
	lossPct := 0.0
	total := metric.SuccessCount + metric.FailureCount
	if total > 0 {
		lossPct = (float64(metric.FailureCount) / float64(total)) * 100.0
	}
	staleSeconds := 0.0
	if !lastSeen.IsZero() {
		age := now.Sub(lastSeen)
		if age > 0 {
			staleSeconds = age.Seconds()
		}
	}
	// Dijkstra-compatible local edge cost:
	// hop + latency + jitter + loss + stale penalty, lower is better.
	return float64(hop)*1.0 + rttMs*0.02 + jitterMs*0.05 + lossPct*2.0 + staleSeconds*0.03
}

func recordGatewayPeerDialResult(nodeID string, rtt time.Duration, success bool) {
	nodeID = normalizeGatewayNodeID(nodeID)
	if nodeID == "" {
		return
	}
	now := time.Now()
	rttMs := float64(rtt.Milliseconds())
	if rttMs <= 0 {
		rttMs = 1
	}
	endpointGatewayRuntime.mu.Lock()
	metric := endpointGatewayRuntime.peerMetrics[nodeID]
	if success {
		metric.SuccessCount++
		if metric.RTTEwmaMs <= 0 {
			metric.RTTEwmaMs = rttMs
			metric.JitterEwmaMs = 0
		} else {
			delta := absFloat64(metric.RTTEwmaMs - rttMs)
			metric.JitterEwmaMs = metric.JitterEwmaMs*0.7 + delta*0.3
			metric.RTTEwmaMs = metric.RTTEwmaMs*0.8 + rttMs*0.2
		}
		metric.LastRTTMs = rttMs
	} else {
		metric.FailureCount++
	}
	metric.UpdatedAt = now
	endpointGatewayRuntime.peerMetrics[nodeID] = metric
	endpointGatewayRuntime.mu.Unlock()
}

func absFloat64(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func pruneGatewayState(now time.Time) {
	endpointGatewayRuntime.mu.Lock()
	pruneGatewayStateLocked(now)
	endpointGatewayRuntime.mu.Unlock()
}

func pruneGatewayStateLocked(now time.Time) {
	cutoff := now.Add(-gatewayPeerRouteTTL)
	for nodeID, peer := range endpointGatewayRuntime.peers {
		if peer.LastSeen.Before(cutoff) {
			delete(endpointGatewayRuntime.peers, nodeID)
			delete(endpointGatewayRuntime.peerMetrics, nodeID)
		}
	}
	for target, route := range endpointGatewayRuntime.targetRoutes {
		if route.LastSeen.Before(cutoff) {
			delete(endpointGatewayRuntime.targetRoutes, target)
		}
	}
	for target, peers := range endpointGatewayRuntime.directRoutes {
		for nodeID, seenAt := range peers {
			if seenAt.Before(cutoff) {
				delete(peers, nodeID)
				continue
			}
			if _, exists := endpointGatewayRuntime.peers[nodeID]; !exists {
				delete(peers, nodeID)
			}
		}
		if len(peers) == 0 {
			delete(endpointGatewayRuntime.directRoutes, target)
		}
	}
	for target, cached := range endpointGatewayRuntime.routeCache {
		if cached.Addr == "" {
			delete(endpointGatewayRuntime.routeCache, target)
			continue
		}
		if !cached.ExpiresAt.IsZero() && now.After(cached.ExpiresAt.Add(gatewayRouteProbeTTL)) {
			delete(endpointGatewayRuntime.routeCache, target)
		}
	}
	for target, deniedByTarget := range endpointGatewayRuntime.routeDenied {
		for addr, expiresAt := range deniedByTarget {
			if now.After(expiresAt) {
				delete(deniedByTarget, addr)
			}
		}
		if len(deniedByTarget) == 0 {
			delete(endpointGatewayRuntime.routeDenied, target)
		}
	}
	nowUnix := now.UTC().Unix()
	for key, exp := range endpointGatewayRuntime.peerAuthSeen {
		if exp < nowUnix {
			delete(endpointGatewayRuntime.peerAuthSeen, key)
		}
	}
	for len(endpointGatewayRuntime.peerAuthSeen) > gatewayPeerAuthReplayEntries {
		for key := range endpointGatewayRuntime.peerAuthSeen {
			delete(endpointGatewayRuntime.peerAuthSeen, key)
			break
		}
	}
	trimGatewayPeerMapLocked()
	trimGatewayRouteMapLocked()
}

func trimGatewayPeerMapLocked() {
	for len(endpointGatewayRuntime.peers) > maxGatewayPeerEntries {
		var oldestNode string
		var oldestTime time.Time
		for nodeID, peer := range endpointGatewayRuntime.peers {
			if oldestNode == "" || peer.LastSeen.Before(oldestTime) {
				oldestNode = nodeID
				oldestTime = peer.LastSeen
			}
		}
		if oldestNode == "" {
			break
		}
		delete(endpointGatewayRuntime.peers, oldestNode)
	}
}

func trimGatewayRouteMapLocked() {
	for len(endpointGatewayRuntime.targetRoutes) > maxGatewayRouteEntries {
		var oldestTarget string
		var oldestTime time.Time
		for target, route := range endpointGatewayRuntime.targetRoutes {
			if oldestTarget == "" || route.LastSeen.Before(oldestTime) {
				oldestTarget = target
				oldestTime = route.LastSeen
			}
		}
		if oldestTarget == "" {
			break
		}
		delete(endpointGatewayRuntime.targetRoutes, oldestTarget)
	}
}

func upsertGatewayPeerLocked(nodeID, addr string, now time.Time) bool {
	nodeID = normalizeGatewayNodeID(nodeID)
	addr = normalizeGatewayAddress(addr)
	if nodeID == "" || addr == "" {
		return false
	}
	if existing, ok := endpointGatewayRuntime.peers[nodeID]; ok {
		if existing.Addr == addr {
			existing.LastSeen = now
			endpointGatewayRuntime.peers[nodeID] = existing
			return false
		}
	}
	endpointGatewayRuntime.peers[nodeID] = gatewayPeerInfo{
		NodeID:   nodeID,
		Addr:     addr,
		LastSeen: now,
	}
	return true
}

func upsertGatewayTargetRouteLocked(target, nextHopNodeID, nextHopAddr string, hop int, now time.Time) bool {
	target = normalizeGatewayAddress(target)
	nextHopNodeID = normalizeGatewayNodeID(nextHopNodeID)
	nextHopAddr = normalizeGatewayAddress(nextHopAddr)
	if target == "" || nextHopNodeID == "" || nextHopAddr == "" {
		return false
	}
	if hop <= 0 {
		hop = 1
	}
	if hop > maxGatewayHopLimit {
		return false
	}
	if _, direct := endpointGatewayRuntime.directTargets[target]; direct {
		return false
	}

	existing, exists := endpointGatewayRuntime.targetRoutes[target]
	if exists {
		if existing.NextHopNodeID == nextHopNodeID {
			existing.NextHopAddr = nextHopAddr
			existing.Hop = hop
			existing.LastSeen = now
			endpointGatewayRuntime.targetRoutes[target] = existing
			return false
		}
		if existing.Hop < hop && now.Sub(existing.LastSeen) <= gatewayPeerRouteTTL/2 {
			return false
		}
	}

	endpointGatewayRuntime.targetRoutes[target] = gatewayTargetRoute{
		Target:        target,
		NextHopNodeID: nextHopNodeID,
		NextHopAddr:   nextHopAddr,
		Hop:           hop,
		LastSeen:      now,
	}
	return true
}

func invalidateGatewayNodeAndRoutes(nodeID string) int {
	nodeID = normalizeGatewayNodeID(nodeID)
	if nodeID == "" {
		return 0
	}
	removed := 0
	endpointGatewayRuntime.mu.Lock()
	if _, exists := endpointGatewayRuntime.peers[nodeID]; exists {
		delete(endpointGatewayRuntime.peers, nodeID)
		delete(endpointGatewayRuntime.peerMetrics, nodeID)
		removed++
	}
	for target, route := range endpointGatewayRuntime.targetRoutes {
		if normalizeGatewayNodeID(route.NextHopNodeID) == nodeID {
			delete(endpointGatewayRuntime.targetRoutes, target)
			removed++
		}
	}
	for target, peers := range endpointGatewayRuntime.directRoutes {
		if _, exists := peers[nodeID]; exists {
			delete(peers, nodeID)
		}
		if len(peers) == 0 {
			delete(endpointGatewayRuntime.directRoutes, target)
		}
	}
	for target, cached := range endpointGatewayRuntime.routeCache {
		if normalizeGatewayNodeID(cached.NodeID) == nodeID {
			delete(endpointGatewayRuntime.routeCache, target)
		}
	}
	endpointGatewayRuntime.mu.Unlock()
	return removed
}

func currentGatewayNodeID() string {
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()
	return normalizeGatewayNodeID(endpointGatewayRuntime.nodeID)
}

func isGatewayAllowedTarget(targetAddr string) bool {
	target := normalizeGatewayAddress(targetAddr)
	if target == "" {
		return false
	}
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()
	if _, exists := endpointGatewayRuntime.allowedTargets[target]; exists {
		return true
	}
	for addr := range endpointGatewayRuntime.allowedTargets {
		if sameGatewayAddress(addr, target) {
			return true
		}
	}
	return false
}

func isGatewayBootstrapDirectTarget(targetAddr string) bool {
	target := normalizeGatewayAddress(targetAddr)
	if target == "" {
		return false
	}
	endpointGatewayRuntime.mu.Lock()
	defer endpointGatewayRuntime.mu.Unlock()
	if _, exists := endpointGatewayRuntime.directTargets[target]; exists {
		return true
	}
	for addr := range endpointGatewayRuntime.directTargets {
		if sameGatewayAddress(addr, target) {
			return true
		}
	}
	return false
}

func isGatewayRelayAuthorized(targetAddr string, meta gatewayConnectMeta) bool {
	_ = targetAddr
	_ = meta
	return true
}

func isLocalGatewayAddress(addr string) bool {
	addr = normalizeGatewayAddress(addr)
	if addr == "" {
		return false
	}
	endpointGatewayRuntime.mu.Lock()
	listenAddr := endpointGatewayRuntime.listenAddr
	endpointGatewayRuntime.mu.Unlock()
	return isLocalGatewayAddressWithListenAddr(addr, listenAddr)
}

func isLocalGatewayAddressWithListenAddr(addr, listenAddr string) bool {
	addr = normalizeGatewayAddress(addr)
	if addr == "" {
		return false
	}
	targetHost, targetPort, err := net.SplitHostPort(addr)
	if err != nil {
		return sameGatewayAddress(addr, listenAddr)
	}
	targetHost = strings.Trim(strings.TrimSpace(targetHost), "[]")
	if targetHost == "" {
		return false
	}
	if sameGatewayAddress(addr, listenAddr) {
		return true
	}

	listenHost, listenPort, listenErr := net.SplitHostPort(strings.TrimSpace(listenAddr))
	if listenErr == nil {
		listenHost = strings.Trim(strings.TrimSpace(listenHost), "[]")
		if strings.TrimSpace(targetPort) == strings.TrimSpace(listenPort) {
			// Wildcard listener means any local interface address is self.
			if listenHost == "" || listenHost == "0.0.0.0" || listenHost == "::" {
				if gatewayHostBelongsToLocalInterface(targetHost) {
					return true
				}
			}
		}
	}

	return gatewayHostBelongsToLocalInterface(targetHost)
}

func gatewayHostBelongsToLocalInterface(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return true
		}
		ifaces, err := net.Interfaces()
		if err != nil {
			return false
		}
		for _, iface := range ifaces {
			addrs, addrErr := iface.Addrs()
			if addrErr != nil {
				continue
			}
			for _, rawAddr := range addrs {
				switch v := rawAddr.(type) {
				case *net.IPNet:
					if v.IP != nil && v.IP.Equal(ip) {
						return true
					}
				case *net.IPAddr:
					if v.IP != nil && v.IP.Equal(ip) {
						return true
					}
				}
			}
		}
		return false
	}

	hostname, err := os.Hostname()
	if err == nil && strings.EqualFold(strings.TrimSpace(hostname), host) {
		return true
	}
	return false
}

func buildGatewayAnnounceAddr(listenAddr string, responderIP net.IP) string {
	listenAddr = strings.TrimSpace(listenAddr)
	if _, port, err := net.SplitHostPort(listenAddr); err == nil {
		if sourceIP := resolveGatewaySourceIPForResponder(responderIP); sourceIP != nil {
			return net.JoinHostPort(sourceIP.String(), port)
		}
		return listenAddr
	}
	return listenAddr
}

func resolveGatewaySourceIPForResponder(responderIP net.IP) net.IP {
	if responderIP == nil || responderIP.IsUnspecified() {
		return nil
	}
	network := "udp4"
	if responderIP.To4() == nil {
		network = "udp6"
	}
	probeConn, err := net.DialUDP(network, nil, &net.UDPAddr{IP: responderIP, Port: 9})
	if err != nil {
		return nil
	}
	defer probeConn.Close()

	localAddr, ok := probeConn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr == nil || localAddr.IP == nil || localAddr.IP.IsUnspecified() {
		return nil
	}
	return localAddr.IP
}

func discoverGatewayAddress(discoverPort int) (string, error) {
	addrs, err := discoverGatewayAddresses(discoverPort, 1)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", errors.New("no gateway discovered")
	}
	return addrs[0], nil
}

func discoverGatewayAddresses(discoverPort int, limit int) ([]string, error) {
	if discoverPort <= 0 {
		return nil, errors.New("invalid discovery port")
	}
	if limit <= 0 {
		limit = gatewayRouteBundleMaxAddrs
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	request := gatewayDiscoverMagic + "\n"
	_, err = conn.WriteToUDP([]byte(request), &net.UDPAddr{IP: net.IPv4bcast, Port: discoverPort})
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	out := make([]string, 0, limit)
	seen := make(map[string]struct{}, limit)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(remaining))
		n, remoteAddr, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				break
			}
			return nil, readErr
		}
		resp := strings.TrimSpace(string(buf[:n]))
		if strings.HasPrefix(resp, gatewayAnnounceMagic+" ") {
			announceAddr := strings.TrimSpace(strings.TrimPrefix(resp, gatewayAnnounceMagic))
			if announceAddr == "" {
				continue
			}
			normalized := normalizeGatewayAddress(announceAddr)
			if normalized == "" {
				continue
			}
			if isLocalGatewayAddress(normalized) {
				continue
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			out = append(out, normalized)
			if len(out) >= limit {
				break
			}
			continue
		}
		if strings.HasPrefix(resp, gatewayPeerMagic+" ") {
			_ = applyGatewayPeerAnnounce(resp, remoteAddr)
			continue
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no gateway discovered")
	}
	return out, nil
}

func normalizeGatewayAddress(addr string) string {
	return normalizeServerAddressForSession(strings.TrimSpace(addr))
}

func normalizeGatewayNodeID(id string) string {
	return strings.TrimSpace(id)
}

func normalizeGatewayService(service string) string {
	service = strings.ToLower(strings.TrimSpace(service))
	if service == gatewayServiceGrid {
		return service
	}
	return ""
}

func parseGatewayPath(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	items := strings.Split(raw, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		nodeID := normalizeGatewayNodeID(item)
		if nodeID == "" {
			continue
		}
		out = append(out, nodeID)
	}
	return out
}

func normalizeGatewayPath(path []string) []string {
	if len(path) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(path))
	out := make([]string, 0, len(path))
	for _, nodeID := range path {
		n := normalizeGatewayNodeID(nodeID)
		if n == "" {
			continue
		}
		if _, exists := seen[n]; exists {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func appendGatewayPath(path []string, nodeID string) []string {
	nodeID = normalizeGatewayNodeID(nodeID)
	if nodeID == "" {
		return normalizeGatewayPath(path)
	}
	if gatewayPathContains(path, nodeID) {
		return normalizeGatewayPath(path)
	}
	out := normalizeGatewayPath(path)
	out = append(out, nodeID)
	return out
}

func gatewayPathContains(path []string, nodeID string) bool {
	nodeID = normalizeGatewayNodeID(nodeID)
	if nodeID == "" {
		return false
	}
	for _, hop := range path {
		if normalizeGatewayNodeID(hop) == nodeID {
			return true
		}
	}
	return false
}

func sameGatewayAddress(a, b string) bool {
	na := normalizeGatewayAddress(a)
	nb := normalizeGatewayAddress(b)
	if na == "" || nb == "" {
		return false
	}
	return strings.EqualFold(na, nb)
}

func encodeGatewayField(v string) string {
	return url.QueryEscape(strings.TrimSpace(v))
}

func decodeGatewayField(v string) string {
	decoded, err := url.QueryUnescape(strings.TrimSpace(v))
	if err != nil {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(decoded)
}

func readGatewayControlLine(reader *bufio.Reader) (string, error) {
	if reader == nil {
		return "", errors.New("gateway reader is required")
	}

	buf := make([]byte, 0, 256)
	for {
		part, err := reader.ReadSlice('\n')
		if len(part) > 0 {
			if len(buf)+len(part) > gatewayMaxControlPayloadSize {
				return "", errors.New("gateway control payload too large")
			}
			buf = append(buf, part...)
		}
		if err == nil {
			return string(buf), nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return "", err
	}
}

func validateGatewayControlPayload(line string) error {
	if len(line) > gatewayMaxControlPayloadSize {
		return errors.New("gateway control payload too large")
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return errors.New("empty gateway payload")
	}
	if strings.IndexByte(trimmed, 0) >= 0 {
		return errors.New("gateway payload contains invalid null byte")
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return errors.New("unexpected json payload")
	}
	if strings.Contains(lower, "<?xml") || strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<!entity") {
		return errors.New("xml entity payload rejected")
	}
	return nil
}

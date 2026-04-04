package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type memoryGridStore struct {
	mu     sync.RWMutex
	nodes  map[string]NodeIdentity
	leases map[string]NodeLease
	routes map[string]RouteDescriptor
	tokens map[string]SessionToken
	ice    map[string]ICECandidateSet
}

func newMemoryGridStore() *memoryGridStore {
	return &memoryGridStore{
		nodes:  make(map[string]NodeIdentity),
		leases: make(map[string]NodeLease),
		routes: make(map[string]RouteDescriptor),
		tokens: make(map[string]SessionToken),
		ice:    make(map[string]ICECandidateSet),
	}
}

func (m *memoryGridStore) UpsertNode(_ context.Context, node *NodeIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node.NodeID] = *node
	return nil
}

func (m *memoryGridStore) GetNode(_ context.Context, nodeID string) (*NodeIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.nodes[nodeID]
	if !ok {
		return nil, nil
	}
	c := n
	return &c, nil
}

func (m *memoryGridStore) ListNodes(_ context.Context) ([]NodeIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]NodeIdentity, 0, len(m.nodes))
	for _, v := range m.nodes {
		out = append(out, v)
	}
	return out, nil
}

func (m *memoryGridStore) DeleteNode(_ context.Context, nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, nodeID)
	return nil
}

func (m *memoryGridStore) UpsertLease(_ context.Context, lease *NodeLease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leases[lease.NodeID] = *lease
	return nil
}

func (m *memoryGridStore) GetLease(_ context.Context, nodeID string) (*NodeLease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.leases[nodeID]
	if !ok {
		return nil, nil
	}
	c := v
	return &c, nil
}

func (m *memoryGridStore) DeleteLease(_ context.Context, nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.leases, nodeID)
	return nil
}

func (m *memoryGridStore) AnnounceRoute(_ context.Context, route *RouteDescriptor) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[route.RouteID] = *route
	return nil
}

func (m *memoryGridStore) QueryRoutes(_ context.Context, sourceNode, destinationNode string, limit int) ([]RouteDescriptor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]RouteDescriptor, 0)
	now := time.Now().UTC().Unix()
	for _, route := range m.routes {
		if route.SourceNode == sourceNode && route.DestinationNode == destinationNode && route.ExpiresAt >= now {
			out = append(out, route)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memoryGridStore) ListRoutes(_ context.Context, limit int) ([]RouteDescriptor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]RouteDescriptor, 0, len(m.routes))
	now := time.Now().UTC().Unix()
	for _, route := range m.routes {
		if route.ExpiresAt > 0 && route.ExpiresAt < now {
			continue
		}
		out = append(out, route)
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memoryGridStore) RevokeRoute(_ context.Context, routeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.routes, routeID)
	return nil
}

func (m *memoryGridStore) SaveToken(_ context.Context, token *SessionToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[token.Token] = *token
	return nil
}

func (m *memoryGridStore) GetToken(_ context.Context, tokenValue string) (*SessionToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	token, ok := m.tokens[tokenValue]
	if !ok {
		return nil, nil
	}
	c := token
	return &c, nil
}

func (m *memoryGridStore) RevokeToken(_ context.Context, tokenValue string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	token, ok := m.tokens[tokenValue]
	if !ok {
		return nil
	}
	token.Revoked = true
	m.tokens[tokenValue] = token
	return nil
}

func (m *memoryGridStore) UpsertICECandidateSet(_ context.Context, set *ICECandidateSet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ice[set.NodeID] = *set
	return nil
}

func (m *memoryGridStore) GetICECandidateSet(_ context.Context, nodeID string) (*ICECandidateSet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set, ok := m.ice[nodeID]
	if !ok {
		return nil, nil
	}
	c := set
	return &c, nil
}

func buildTestGridControlPlane(t *testing.T, mode string) *GridControlPlane {
	t.Helper()
	gridRouting := &GridRoutingConfig{}
	hopGuard := true
	maxHop := 32
	pathTTL := 120
	gridRouting.HopGuard = &hopGuard
	gridRouting.MaxHop = &maxHop
	gridRouting.PathTTLSeconds = &pathTTL
	gridSecurity := &GridSecurityConfig{}
	tokenTTL := 300
	gridSecurity.DefaultTokenTTLSeconds = &tokenTTL
	gridRelay := &GridRelayConfig{}
	relayEnabled := true
	relayHops := 6
	relayTimeout := 1000
	gridRelay.Enabled = &relayEnabled
	gridRelay.MaxRelayHops = &relayHops
	gridRelay.FallbackTimeoutMs = &relayTimeout

	if mode == GridDeploymentModeStandalone {
		store, err := NewSQLiteGridStore(":memory:")
		if err != nil {
			t.Fatalf("NewSQLiteGridStore failed: %v", err)
		}
		bus := NewInProcEventBus()
		return &GridControlPlane{
			mode:        mode,
			stateStore:  store,
			leaseStore:  store,
			routeStore:  store,
			tokenStore:  store,
			iceStore:    store,
			eventBus:    bus,
			storeCloser: store,
			busCloser:   bus,
			routingCfg:  gridRouting,
			securityCfg: gridSecurity,
			relayCfg:    gridRelay,
		}
	}

	mem := newMemoryGridStore()
	bus := NewInProcEventBus()
	return &GridControlPlane{
		mode:        mode,
		stateStore:  mem,
		leaseStore:  mem,
		routeStore:  mem,
		tokenStore:  mem,
		iceStore:    mem,
		eventBus:    bus,
		busCloser:   bus,
		routingCfg:  gridRouting,
		securityCfg: gridSecurity,
		relayCfg:    gridRelay,
	}
}

func TestGridControlPlaneSemanticParity(t *testing.T) {
	modes := []string{GridDeploymentModeStandalone, GridDeploymentModeCluster}
	for _, mode := range modes {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			cp := buildTestGridControlPlane(t, mode)
			defer cp.Close()

			ctx := context.Background()
			registerResp, err := cp.RegisterNode(ctx, &GridRegisterRequest{
				Node: NodeIdentity{
					NodeID:       "node-a",
					Capabilities: []string{"quic", "tcp"},
				},
				LeaseTTLSecond: 20,
			})
			if err != nil {
				t.Fatalf("RegisterNode failed: %v", err)
			}
			if !registerResp.Success || registerResp.Lease == nil {
				t.Fatalf("unexpected register response: %+v", registerResp)
			}

			hbResp, err := cp.HeartbeatNode(ctx, &GridHeartbeatRequest{
				NodeID:          "node-a",
				LeaseTTLSeconds: 25,
			})
			if err != nil {
				t.Fatalf("HeartbeatNode failed: %v", err)
			}
			if !hbResp.Success || hbResp.Lease == nil {
				t.Fatalf("unexpected heartbeat response: %+v", hbResp)
			}

			announceResp, err := cp.AnnounceRoute(ctx, &GridAnnounceRouteRequest{
				Route: RouteDescriptor{
					SourceNode:      "node-a",
					DestinationNode: "node-b",
					Hops:            []string{"node-a", "node-x", "node-b"},
				},
			})
			if err != nil {
				t.Fatalf("AnnounceRoute failed: %v", err)
			}
			if !announceResp.Success || announceResp.Route == nil {
				t.Fatalf("unexpected announce response: %+v", announceResp)
			}

			queryResp, err := cp.QueryRoutes(ctx, &GridQueryRouteRequest{
				SourceNode:      "node-a",
				DestinationNode: "node-b",
				Limit:           5,
			})
			if err != nil {
				t.Fatalf("QueryRoutes failed: %v", err)
			}
			if !queryResp.Success || len(queryResp.Routes) == 0 || len(queryResp.Candidates) == 0 {
				t.Fatalf("unexpected query response: %+v", queryResp)
			}

			issueResp, err := cp.IssueSessionToken(ctx, &GridIssueTokenRequest{
				NodeID: "node-a",
				Scope:  "route:announce",
			})
			if err != nil {
				t.Fatalf("IssueSessionToken failed: %v", err)
			}
			if !issueResp.Success || issueResp.Token == nil || issueResp.Token.Token == "" {
				t.Fatalf("unexpected issue response: %+v", issueResp)
			}

			revokeResp, err := cp.RevokeSessionToken(ctx, &GridRevokeTokenRequest{
				Token: issueResp.Token.Token,
			})
			if err != nil {
				t.Fatalf("RevokeSessionToken failed: %v", err)
			}
			if !revokeResp.Success {
				t.Fatalf("unexpected revoke response: %+v", revokeResp)
			}
		})
	}
}

func TestGridControlPlaneValidateSessionToken(t *testing.T) {
	modes := []string{GridDeploymentModeStandalone, GridDeploymentModeCluster}
	for _, mode := range modes {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			cp := buildTestGridControlPlane(t, mode)
			defer cp.Close()

			ctx := context.Background()
			issueResp, err := cp.IssueSessionToken(ctx, &GridIssueTokenRequest{
				NodeID: "node-token-a",
				Scope:  GridScopeRouteQuery + "," + GridScopeICEQuery,
			})
			if err != nil {
				t.Fatalf("IssueSessionToken failed: %v", err)
			}
			if issueResp == nil || !issueResp.Success || issueResp.Token == nil {
				t.Fatalf("unexpected issue response: %+v", issueResp)
			}

			tokenValue := issueResp.Token.Token
			if _, err := cp.ValidateSessionToken(ctx, tokenValue, "node-token-a", GridScopeRouteQuery); err != nil {
				t.Fatalf("ValidateSessionToken expected success, got %v", err)
			}

			if _, err := cp.ValidateSessionToken(ctx, tokenValue, "node-token-b", GridScopeRouteQuery); !errors.Is(err, ErrGridTokenNodeMismatch) {
				t.Fatalf("expected node mismatch error, got %v", err)
			}

			if _, err := cp.ValidateSessionToken(ctx, tokenValue, "node-token-a", GridScopeRouteAnnounce); !errors.Is(err, ErrGridScopeDenied) {
				t.Fatalf("expected scope denied error, got %v", err)
			}

			emptyScopeResp, err := cp.IssueSessionToken(ctx, &GridIssueTokenRequest{
				NodeID: "node-token-a",
				Scope:  "",
			})
			if err != nil {
				t.Fatalf("IssueSessionToken(empty scope) failed: %v", err)
			}
			if emptyScopeResp == nil || !emptyScopeResp.Success || emptyScopeResp.Token == nil {
				t.Fatalf("unexpected empty-scope issue response: %+v", emptyScopeResp)
			}
			if _, err := cp.ValidateSessionToken(ctx, emptyScopeResp.Token.Token, "node-token-a", GridScopeRouteQuery); !errors.Is(err, ErrGridScopeDenied) {
				t.Fatalf("expected scope denied for empty scope token, got %v", err)
			}

			if _, err := cp.RevokeSessionToken(ctx, &GridRevokeTokenRequest{Token: tokenValue}); err != nil {
				t.Fatalf("RevokeSessionToken failed: %v", err)
			}
			if _, err := cp.ValidateSessionToken(ctx, tokenValue, "node-token-a", GridScopeRouteQuery); !errors.Is(err, ErrGridTokenRevoked) {
				t.Fatalf("expected revoked error, got %v", err)
			}
		})
	}
}

func TestGridControlPlaneRefreshSessionToken(t *testing.T) {
	modes := []string{GridDeploymentModeStandalone, GridDeploymentModeCluster}
	for _, mode := range modes {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			cp := buildTestGridControlPlane(t, mode)
			defer cp.Close()

			ctx := context.Background()
			issueResp, err := cp.IssueSessionToken(ctx, &GridIssueTokenRequest{
				NodeID: "node-refresh-a",
				Scope:  defaultGridEndpointControlScopes(),
			})
			if err != nil {
				t.Fatalf("IssueSessionToken failed: %v", err)
			}
			if issueResp == nil || !issueResp.Success || issueResp.Token == nil {
				t.Fatalf("unexpected issue response: %+v", issueResp)
			}

			oldToken := issueResp.Token.Token
			refreshResp, err := cp.RefreshSessionToken(ctx, oldToken, &GridRefreshTokenRequest{NodeID: "node-refresh-a"})
			if err != nil {
				t.Fatalf("RefreshSessionToken failed: %v", err)
			}
			if refreshResp == nil || !refreshResp.Success || refreshResp.Token == nil || refreshResp.Token.Token == "" {
				t.Fatalf("unexpected refresh response: %+v", refreshResp)
			}
			if refreshResp.Token.Token == oldToken {
				t.Fatalf("expected rotated token, got same token=%s", oldToken)
			}

			if _, err := cp.ValidateSessionToken(ctx, oldToken, "node-refresh-a", GridScopeICEQuery); !errors.Is(err, ErrGridTokenRevoked) {
				t.Fatalf("expected old token revoked, got %v", err)
			}
			if _, err := cp.ValidateSessionToken(ctx, refreshResp.Token.Token, "node-refresh-a", GridScopeICEQuery); err != nil {
				t.Fatalf("expected refreshed token valid, got %v", err)
			}
		})
	}
}

func TestEnsureGridConfigSettingsFailFast(t *testing.T) {
	enabled := true
	cfg := &Config{
		Grid: &GridConfig{
			Deployment: &GridDeploymentConfig{
				Enabled: &enabled,
				Mode:    GridDeploymentModeCluster,
			},
		},
	}
	if err := ensureGridConfigSettings(cfg); err == nil {
		t.Fatal("expected cluster mode validation to fail without etcd/nats")
	}

	cfg = &Config{
		Grid: &GridConfig{
			Deployment: &GridDeploymentConfig{
				Enabled: &enabled,
				Mode:    GridDeploymentModeStandalone,
			},
		},
	}
	if err := ensureGridConfigSettings(cfg); err != nil {
		t.Fatalf("unexpected standalone validation error: %v", err)
	}
	if cfg.Grid.Deployment.SQLitePath == "" {
		t.Fatal("expected default sqlite path")
	}
}

func TestGridControlPlaneQueryRoutesIncludesTransportCandidates(t *testing.T) {
	cp := buildTestGridControlPlane(t, GridDeploymentModeStandalone)
	defer cp.Close()

	ctx := context.Background()
	_, err := cp.AnnounceRoute(ctx, &GridAnnounceRouteRequest{
		Route: RouteDescriptor{
			RouteID:          "route-transport",
			SourceNode:       "node-a",
			DestinationNode:  "node-b",
			Hops:             []string{"node-a", "node-x", "node-b"},
			ReliabilityScore: 0.9,
			LatencyMs:        12,
			Epoch:            time.Now().UTC().UnixNano(),
			ExpiresAt:        time.Now().UTC().Add(2 * time.Minute).Unix(),
		},
	})
	if err != nil {
		t.Fatalf("announce route failed: %v", err)
	}

	resp, err := cp.QueryRoutes(ctx, &GridQueryRouteRequest{
		SourceNode:      "node-a",
		DestinationNode: "node-b",
		Limit:           8,
	})
	if err != nil {
		t.Fatalf("query routes failed: %v", err)
	}

	seen := map[string]bool{}
	for _, c := range resp.Candidates {
		seen[c.Transport] = true
	}
	if !seen["ice"] || !seen["quic"] || !seen["tcp"] {
		t.Fatalf("expected ice/quic/tcp candidates, got %#v", seen)
	}

	priorityCount := 0
	for _, c := range resp.Candidates {
		if c.Priority > 0 {
			priorityCount++
		}
	}
	if priorityCount == 0 {
		t.Fatal("expected top candidates to include primary/standby priorities")
	}
}

func TestGridControlPlaneQueryRoutesDestinationOffline(t *testing.T) {
	cp := buildTestGridControlPlane(t, GridDeploymentModeStandalone)
	defer cp.Close()

	resp, err := cp.QueryRoutes(context.Background(), &GridQueryRouteRequest{
		SourceNode:      "node-a",
		DestinationNode: "node-offline",
		Limit:           8,
	})
	if err != nil {
		t.Fatalf("query routes failed: %v", err)
	}
	if resp.Success {
		t.Fatalf("expected query to fail for offline destination: %+v", resp)
	}
	if resp.ErrorCode != GridRouteErrorNotFound {
		t.Fatalf("expected error code %s got %s", GridRouteErrorNotFound, resp.ErrorCode)
	}
	if !resp.Unreachable {
		t.Fatal("expected unreachable flag to be true")
	}
}

func TestGridControlPlaneQueryRoutesDijkstraTopK(t *testing.T) {
	cp := buildTestGridControlPlane(t, GridDeploymentModeStandalone)
	defer cp.Close()

	ctx := context.Background()
	_, err := cp.RegisterNode(ctx, &GridRegisterRequest{Node: NodeIdentity{NodeID: "node-c"}, LeaseTTLSecond: 30})
	if err != nil {
		t.Fatalf("register node-c failed: %v", err)
	}

	announce := func(route RouteDescriptor) {
		if _, err := cp.AnnounceRoute(ctx, &GridAnnounceRouteRequest{Route: route}); err != nil {
			t.Fatalf("announce route %s failed: %v", route.RouteID, err)
		}
	}

	expireAt := time.Now().UTC().Add(2 * time.Minute).Unix()
	announce(RouteDescriptor{
		RouteID:          "ab",
		SourceNode:       "node-a",
		DestinationNode:  "node-b",
		Hops:             []string{"node-a", "node-b"},
		ReliabilityScore: 0.98,
		LatencyMs:        10,
		ExpiresAt:        expireAt,
	})
	announce(RouteDescriptor{
		RouteID:          "bc",
		SourceNode:       "node-b",
		DestinationNode:  "node-c",
		Hops:             []string{"node-b", "node-c"},
		ReliabilityScore: 0.98,
		LatencyMs:        10,
		ExpiresAt:        expireAt,
	})
	announce(RouteDescriptor{
		RouteID:          "ad",
		SourceNode:       "node-a",
		DestinationNode:  "node-d",
		Hops:             []string{"node-a", "node-d"},
		ReliabilityScore: 0.90,
		LatencyMs:        8,
		ExpiresAt:        expireAt,
	})
	announce(RouteDescriptor{
		RouteID:          "dc",
		SourceNode:       "node-d",
		DestinationNode:  "node-c",
		Hops:             []string{"node-d", "node-c"},
		ReliabilityScore: 0.90,
		LatencyMs:        8,
		ExpiresAt:        expireAt,
	})

	resp, err := cp.QueryRoutes(ctx, &GridQueryRouteRequest{
		SourceNode:      "node-a",
		DestinationNode: "node-c",
		Limit:           8,
	})
	if err != nil {
		t.Fatalf("query routes failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected success query response, got %+v", resp)
	}
	if len(resp.Routes) == 0 {
		t.Fatal("expected at least one computed route")
	}
	foundPlanner := false
	for _, route := range resp.Routes {
		if route.Metadata != nil && route.Metadata["planner"] == "dijkstra" {
			foundPlanner = true
			break
		}
	}
	if !foundPlanner {
		t.Fatalf("expected dijkstra planned route in response, got %+v", resp.Routes)
	}
}

func TestGridControlPlaneICEPublishAndQuery(t *testing.T) {
	cp := buildTestGridControlPlane(t, GridDeploymentModeStandalone)
	defer cp.Close()

	ctx := context.Background()
	pubResp, err := cp.PublishICECandidates(ctx, &GridICEPublishRequest{
		NodeID:     "node-ice-a",
		Candidates: []string{"192.168.1.10:4000", "203.0.113.9:443"},
		TTLSeconds: 60,
	})
	if err != nil {
		t.Fatalf("PublishICECandidates failed: %v", err)
	}
	if !pubResp.Success || pubResp.Set == nil || len(pubResp.Set.Candidates) == 0 {
		t.Fatalf("unexpected publish response: %+v", pubResp)
	}

	queryResp, err := cp.QueryICECandidates(ctx, &GridICEQueryRequest{NodeID: "node-ice-a"})
	if err != nil {
		t.Fatalf("QueryICECandidates failed: %v", err)
	}
	if !queryResp.Success || len(queryResp.Candidates) == 0 {
		t.Fatalf("unexpected query response: %+v", queryResp)
	}
}

func TestGridControlPlaneICESessionIssueAndRefresh(t *testing.T) {
	cp := buildTestGridControlPlane(t, GridDeploymentModeStandalone)
	defer cp.Close()

	ctx := context.Background()
	issueResp, err := cp.IssueICESession(ctx, &GridICEIssueSessionRequest{
		NodeID:     "node-ice-session",
		TTLSeconds: 45,
		Metadata: map[string]string{
			"role": "edge",
		},
	})
	if err != nil {
		t.Fatalf("IssueICESession failed: %v", err)
	}
	if !issueResp.Success || issueResp.Session == nil {
		t.Fatalf("unexpected issue response: %+v", issueResp)
	}
	if issueResp.Session.NodeID != "node-ice-session" || issueResp.Session.SessionID == "" {
		t.Fatalf("unexpected session payload: %+v", issueResp.Session)
	}
	if issueResp.Session.ExpiresAt <= issueResp.Session.IssuedAt {
		t.Fatalf("invalid session ttl: %+v", issueResp.Session)
	}
	if issueResp.Session.Username == "" || issueResp.Session.Password == "" {
		t.Fatalf("expected issued credentials, got %+v", issueResp.Session)
	}

	refreshResp, err := cp.RefreshICESession(ctx, &GridICERefreshSessionRequest{
		NodeID: "node-ice-session",
	})
	if err != nil {
		t.Fatalf("RefreshICESession failed: %v", err)
	}
	if !refreshResp.Success || refreshResp.Session == nil {
		t.Fatalf("unexpected refresh response: %+v", refreshResp)
	}
	if refreshResp.Session.SessionID == issueResp.Session.SessionID {
		t.Fatalf("expected refreshed session id to rotate, got same id=%s", refreshResp.Session.SessionID)
	}
}

func TestGridControlPlaneMarkNodeOfflinePrunesRoutesAndPublishesEvent(t *testing.T) {
	cp := buildTestGridControlPlane(t, GridDeploymentModeStandalone)
	defer cp.Close()

	ctx := context.Background()
	for _, nodeID := range []string{"node-a", "node-b", "node-c"} {
		if _, err := cp.RegisterNode(ctx, &GridRegisterRequest{
			Node:           NodeIdentity{NodeID: nodeID},
			LeaseTTLSecond: 30,
		}); err != nil {
			t.Fatalf("register %s failed: %v", nodeID, err)
		}
	}
	expireAt := time.Now().UTC().Add(2 * time.Minute).Unix()
	if _, err := cp.AnnounceRoute(ctx, &GridAnnounceRouteRequest{
		Route: RouteDescriptor{
			RouteID:          "route-a-b-c",
			SourceNode:       "node-a",
			DestinationNode:  "node-c",
			Hops:             []string{"node-a", "node-b", "node-c"},
			ReliabilityScore: 0.97,
			LatencyMs:        12,
			Epoch:            time.Now().UTC().UnixNano(),
			ExpiresAt:        expireAt,
		},
	}); err != nil {
		t.Fatalf("announce route failed: %v", err)
	}

	event, err := cp.MarkNodeOffline(ctx, "node-b", "test_disconnect")
	if err != nil {
		t.Fatalf("MarkNodeOffline failed: %v", err)
	}
	if event == nil || event.OfflineNodeID != "node-b" {
		t.Fatalf("unexpected offline event: %+v", event)
	}

	resp, err := cp.QueryRoutes(ctx, &GridQueryRouteRequest{
		SourceNode:      "node-a",
		DestinationNode: "node-c",
		Limit:           8,
	})
	if err != nil {
		t.Fatalf("query routes failed: %v", err)
	}
	if resp.Success && len(resp.Routes) > 0 {
		t.Fatalf("expected routes through offline node to be pruned: %+v", resp.Routes)
	}

	pullResp, err := cp.PullEvents(ctx, &GridEventsPullRequest{
		NodeID: "node-a",
		Cursor: 0,
		Limit:  16,
	})
	if err != nil {
		t.Fatalf("pull events failed: %v", err)
	}
	if !pullResp.Success || len(pullResp.Events) == 0 {
		t.Fatalf("expected offline event to be delivered, got %+v", pullResp)
	}
	if pullResp.Events[0].OfflineNodeID != "node-b" {
		t.Fatalf("expected offline node event for node-b, got %+v", pullResp.Events[0])
	}
}

func TestGridControlPlaneTopologySnapshot(t *testing.T) {
	cp := buildTestGridControlPlane(t, GridDeploymentModeStandalone)
	defer cp.Close()

	ctx := context.Background()
	for _, nodeID := range []string{"node-x", "node-y"} {
		if _, err := cp.RegisterNode(ctx, &GridRegisterRequest{
			Node:           NodeIdentity{NodeID: nodeID},
			LeaseTTLSecond: 30,
		}); err != nil {
			t.Fatalf("register %s failed: %v", nodeID, err)
		}
	}
	if _, err := cp.AnnounceRoute(ctx, &GridAnnounceRouteRequest{
		Route: RouteDescriptor{
			RouteID:          "route-x-y",
			SourceNode:       "node-x",
			DestinationNode:  "node-y",
			Hops:             []string{"node-x", "node-y"},
			ReliabilityScore: 0.95,
			LatencyMs:        10,
			Epoch:            time.Now().UTC().UnixNano(),
			ExpiresAt:        time.Now().UTC().Add(2 * time.Minute).Unix(),
		},
	}); err != nil {
		t.Fatalf("announce route failed: %v", err)
	}

	topology, err := cp.TopologySnapshot(ctx, &GridTopologyRequest{Limit: 128})
	if err != nil {
		t.Fatalf("TopologySnapshot failed: %v", err)
	}
	if !topology.Success {
		t.Fatalf("unexpected topology response: %+v", topology)
	}
	if len(topology.Nodes) < 2 {
		t.Fatalf("expected at least 2 nodes, got %+v", topology.Nodes)
	}
	if len(topology.Edges) == 0 {
		t.Fatalf("expected topology edges, got %+v", topology.Edges)
	}
}

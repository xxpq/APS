package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	gridSubjectNodeRegistered = "grid.node.registered"
	gridSubjectNodeHeartbeat  = "grid.node.heartbeat"
	gridSubjectNodeOffline    = "grid.node.offline"
	gridSubjectRouteAnnounce  = "grid.route.announce"
	gridSubjectRoutePrune     = "grid.route.prune"
	gridSubjectSessionIssue   = "grid.session.issue"
	gridSubjectSessionRevoke  = "grid.session.revoke"

	GridRouteErrorNotFound        = "ROUTE_NOT_FOUND"
	GridRouteErrorPolicyDenied    = "ROUTE_POLICY_DENIED"
	GridRouteErrorTempUnreachable = "ROUTE_TEMP_UNREACHABLE"
)

var (
	ErrGridTokenMissing      = errors.New("missing session token")
	ErrGridTokenInvalid      = errors.New("invalid session token")
	ErrGridTokenExpired      = errors.New("session token expired")
	ErrGridTokenRevoked      = errors.New("session token revoked")
	ErrGridTokenNodeMismatch = errors.New("session token node mismatch")
	ErrGridScopeDenied       = errors.New("session token scope denied")
)

type gridClosable interface {
	Close() error
}

type GridControlPlane struct {
	mu sync.RWMutex

	mode string

	stateStore StateStore
	leaseStore LeaseStore
	routeStore RouteStore
	tokenStore TokenStore
	iceStore   ICEStore
	eventBus   EventBus

	storeCloser gridClosable
	busCloser   gridClosable

	routingCfg   *GridRoutingConfig
	securityCfg  *GridSecurityConfig
	relayCfg     *GridRelayConfig
	transportCfg *GridTransportConfig
	iceCfg       *GridICEConfig

	lifecycleCancel context.CancelFunc
	lifecycleDone   chan struct{}

	eventMu     sync.Mutex
	eventSeq    int64
	eventLog    []gridEventEnvelope
	offlineMu   sync.Mutex
	offlineSeen map[string]struct{}
}

type gridEventEnvelope struct {
	event      GridEvent
	recipients map[string]struct{}
}

func NewGridControlPlaneFromConfig(config *Config) (*GridControlPlane, error) {
	if !isGridEnabled(config) {
		return nil, nil
	}
	gridCfg := config.Grid
	if gridCfg == nil || gridCfg.Deployment == nil {
		return nil, errors.New("grid deployment config is missing")
	}

	var (
		stateStore  StateStore
		leaseStore  LeaseStore
		routeStore  RouteStore
		tokenStore  TokenStore
		iceStore    ICEStore
		eventBus    EventBus
		storeCloser gridClosable
		busCloser   gridClosable
	)

	switch gridCfg.Deployment.Mode {
	case GridDeploymentModeStandalone:
		sqliteStore, err := NewSQLiteGridStore(gridCfg.Deployment.SQLitePath)
		if err != nil {
			return nil, fmt.Errorf("init standalone grid store failed: %w", err)
		}
		stateStore = sqliteStore
		leaseStore = sqliteStore
		routeStore = sqliteStore
		tokenStore = sqliteStore
		iceStore = sqliteStore
		storeCloser = sqliteStore
		inProcBus := NewInProcEventBus()
		eventBus = inProcBus
		busCloser = inProcBus
	case GridDeploymentModeCluster:
		etcdStore, err := NewEtcdGridStore(gridCfg.Deployment.EtcdEndpoints)
		if err != nil {
			return nil, fmt.Errorf("init etcd grid store failed: %w", err)
		}
		stateStore = etcdStore
		leaseStore = etcdStore
		routeStore = etcdStore
		tokenStore = etcdStore
		iceStore = etcdStore
		storeCloser = etcdStore

		natsBus, err := NewNatsEventBus(gridCfg.Deployment.NatsURL)
		if err != nil {
			_ = etcdStore.Close()
			return nil, fmt.Errorf("init nats event bus failed: %w", err)
		}
		eventBus = natsBus
		busCloser = natsBus
	default:
		return nil, fmt.Errorf("unsupported grid deployment mode: %s", gridCfg.Deployment.Mode)
	}

	cp := &GridControlPlane{
		mode:         gridCfg.Deployment.Mode,
		stateStore:   stateStore,
		leaseStore:   leaseStore,
		routeStore:   routeStore,
		tokenStore:   tokenStore,
		iceStore:     iceStore,
		eventBus:     eventBus,
		storeCloser:  storeCloser,
		busCloser:    busCloser,
		routingCfg:   gridCfg.Routing,
		securityCfg:  gridCfg.Security,
		relayCfg:     gridCfg.Relay,
		transportCfg: gridCfg.Transport,
		iceCfg:       gridCfg.ICE,
		lifecycleDone: make(chan struct{}),
		offlineSeen:   make(map[string]struct{}),
	}
	cp.startLifecycleLoop()
	return cp, nil
}

func (g *GridControlPlane) Close() error {
	if g == nil {
		return nil
	}
	if g.lifecycleCancel != nil {
		g.lifecycleCancel()
	}
	if g.lifecycleDone != nil {
		select {
		case <-g.lifecycleDone:
		case <-time.After(2 * time.Second):
		}
	}
	var errs []string
	if g.busCloser != nil {
		if err := g.busCloser.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if g.storeCloser != nil {
		if err := g.storeCloser.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (g *GridControlPlane) startLifecycleLoop() {
	if g == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	g.lifecycleCancel = cancel
	go func() {
		defer close(g.lifecycleDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.sweepExpiredNodes(ctx)
			}
		}
	}()
}

func (g *GridControlPlane) sweepExpiredNodes(ctx context.Context) {
	if g == nil || g.stateStore == nil || g.leaseStore == nil {
		return
	}
	nodes, err := g.stateStore.ListNodes(ctx)
	if err != nil {
		return
	}
	now := time.Now().UTC().Unix()
	for _, node := range nodes {
		nodeID := strings.TrimSpace(node.NodeID)
		if nodeID == "" {
			continue
		}
		lease, leaseErr := g.leaseStore.GetLease(ctx, nodeID)
		if leaseErr != nil {
			continue
		}
		if lease == nil || lease.ExpiresAt <= now {
			_, _ = g.MarkNodeOffline(ctx, nodeID, "lease_expired")
		}
	}
}

func (g *GridControlPlane) clearOfflineMark(nodeID string) {
	nodeID = strings.TrimSpace(nodeID)
	if g == nil || nodeID == "" {
		return
	}
	g.offlineMu.Lock()
	if g.offlineSeen == nil {
		g.offlineSeen = make(map[string]struct{})
	}
	delete(g.offlineSeen, nodeID)
	g.offlineMu.Unlock()
}

func (g *GridControlPlane) markOfflineOnce(nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	if g == nil || nodeID == "" {
		return false
	}
	g.offlineMu.Lock()
	defer g.offlineMu.Unlock()
	if g.offlineSeen == nil {
		g.offlineSeen = make(map[string]struct{})
	}
	if _, exists := g.offlineSeen[nodeID]; exists {
		return false
	}
	g.offlineSeen[nodeID] = struct{}{}
	return true
}

func (g *GridControlPlane) UpdateConfig(config *Config) {
	if g == nil || config == nil || config.Grid == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if config.Grid.Routing != nil {
		g.routingCfg = config.Grid.Routing
	}
	if config.Grid.Security != nil {
		g.securityCfg = config.Grid.Security
	}
	if config.Grid.Relay != nil {
		g.relayCfg = config.Grid.Relay
	}
	if config.Grid.Transport != nil {
		g.transportCfg = config.Grid.Transport
	}
	if config.Grid.ICE != nil {
		g.iceCfg = config.Grid.ICE
	}
}

func (g *GridControlPlane) RegisterNode(ctx context.Context, req *GridRegisterRequest) (*GridRegisterResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	nodeID := strings.TrimSpace(req.Node.NodeID)
	if nodeID == "" {
		return &GridRegisterResponse{Success: false, Error: "node.node_id is required", ServerUTC: time.Now().UTC().Unix()}, nil
	}

	node := req.Node
	node.NodeID = nodeID
	node.UpdatedAt = time.Now().UTC().Unix()
	if err := g.stateStore.UpsertNode(ctx, &node); err != nil {
		return nil, err
	}
	g.clearOfflineMark(nodeID)

	ttl := req.LeaseTTLSecond
	if ttl <= 0 {
		ttl = 30
	}
	lease := &NodeLease{
		NodeID:    nodeID,
		ExpiresAt: time.Now().UTC().Add(time.Duration(ttl) * time.Second).Unix(),
	}
	if err := g.leaseStore.UpsertLease(ctx, lease); err != nil {
		return nil, err
	}

	g.publishJSON(ctx, gridSubjectNodeRegistered, node)
	return &GridRegisterResponse{
		Success:   true,
		Node:      node,
		Lease:     lease,
		ServerUTC: time.Now().UTC().Unix(),
	}, nil
}

func (g *GridControlPlane) HeartbeatNode(ctx context.Context, req *GridHeartbeatRequest) (*GridHeartbeatResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		return &GridHeartbeatResponse{Success: false, Error: "node_id is required"}, nil
	}
	ttl := req.LeaseTTLSeconds
	if ttl <= 0 {
		ttl = 30
	}
	lease := &NodeLease{
		NodeID:    nodeID,
		ExpiresAt: time.Now().UTC().Add(time.Duration(ttl) * time.Second).Unix(),
	}
	if err := g.leaseStore.UpsertLease(ctx, lease); err != nil {
		return nil, err
	}
	g.clearOfflineMark(nodeID)
	g.publishJSON(ctx, gridSubjectNodeHeartbeat, lease)
	return &GridHeartbeatResponse{Success: true, Lease: lease}, nil
}

func (g *GridControlPlane) AnnounceRoute(ctx context.Context, req *GridAnnounceRouteRequest) (*GridAnnounceRouteResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	route := req.Route
	route.SourceNode = strings.TrimSpace(route.SourceNode)
	route.DestinationNode = strings.TrimSpace(route.DestinationNode)
	if route.SourceNode == "" || route.DestinationNode == "" {
		return &GridAnnounceRouteResponse{Success: false, Error: "source_node and destination_node are required"}, nil
	}
	if route.RouteID == "" {
		id, err := randomHex(16)
		if err != nil {
			return nil, err
		}
		route.RouteID = fmt.Sprintf("%s-%s-%s", route.SourceNode, route.DestinationNode, id)
	}
	if route.Epoch == 0 {
		route.Epoch = time.Now().UTC().UnixNano()
	}
	if route.ExpiresAt == 0 {
		ttl := g.routingPathTTLSeconds()
		route.ExpiresAt = time.Now().UTC().Add(time.Duration(ttl) * time.Second).Unix()
	}
	if route.LatencyMs <= 0 {
		route.LatencyMs = int64(maxInt(1, len(route.Hops)) * 15)
	}
	if route.ReliabilityScore <= 0 {
		route.ReliabilityScore = 1 / float64(maxInt(1, len(route.Hops)))
	}

	if g.isHopGuardEnabled() && len(route.Hops) > g.maxHop() {
		return &GridAnnounceRouteResponse{
			Success: false,
			Error:   fmt.Sprintf("hop_guard rejected route hops=%d max_hop=%d", len(route.Hops), g.maxHop()),
		}, nil
	}

	if err := g.routeStore.AnnounceRoute(ctx, &route); err != nil {
		return nil, err
	}
	g.publishJSON(ctx, gridSubjectRouteAnnounce, route)
	return &GridAnnounceRouteResponse{Success: true, Route: &route}, nil
}

func (g *GridControlPlane) QueryRoutes(ctx context.Context, req *GridQueryRouteRequest) (*GridQueryRouteResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	src := strings.TrimSpace(req.SourceNode)
	dst := strings.TrimSpace(req.DestinationNode)
	if src == "" || dst == "" {
		return &GridQueryRouteResponse{Success: false, Error: "source_node and destination_node are required"}, nil
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 16
	}
	routes, err := g.routeStore.QueryRoutes(ctx, src, dst, limit)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Unix()
	if len(routes) == 0 {
		lease, leaseErr := g.leaseStore.GetLease(ctx, dst)
		if leaseErr != nil {
			return nil, leaseErr
		}
		if lease == nil || lease.ExpiresAt <= now {
			_, _ = g.MarkNodeOffline(ctx, dst, "lease_expired")
			return &GridQueryRouteResponse{
				Success:     false,
				Relay:       g.relayPolicy(),
				Error:       "destination node is offline or not joined",
				ErrorCode:   GridRouteErrorNotFound,
				Unreachable: true,
			}, nil
		}
	}
	if len(routes) == 0 {
		allRoutes, err := g.routeStore.ListRoutes(ctx, 4096)
		if err != nil {
			return nil, err
		}
		graphTopK := buildWeightedTopKRoutesFromGraph(
			allRoutes,
			src,
			dst,
			g.maxHop(),
			minInt(limit, 3),
			g.routingPathTTLSeconds(),
		)
		routes = mergeRouteDescriptors(routes, graphTopK, limit)
	}
	sort.Slice(routes, func(i, j int) bool {
		iCost := routeQualityCost(routes[i])
		jCost := routeQualityCost(routes[j])
		if iCost == jCost {
			return routes[i].Epoch > routes[j].Epoch
		}
		return iCost < jCost
	})

	enableQUIC, enableTCP, _ := g.transportCapabilities()
	iceEnabled := g.isICEEnabled()
	destinationICE := []string(nil)
	if iceEnabled && g.iceStore != nil {
		if set, getErr := g.iceStore.GetICECandidateSet(ctx, dst); getErr == nil && set != nil && set.ExpiresAt >= time.Now().UTC().Unix() {
			destinationICE = normalizeICECandidates(set.Candidates)
		}
	}
	candidates := make([]PathCandidate, 0, len(routes)*3+1)
	for _, route := range routes {
		nextHop := ""
		if len(route.Hops) > 0 {
			nextHop = route.Hops[0]
			for i := range route.Hops {
				if route.Hops[i] == src && i+1 < len(route.Hops) {
					nextHop = route.Hops[i+1]
					break
				}
			}
		}
		baseCandidate := PathCandidate{
			RouteID:       route.RouteID,
			NextHop:       nextHop,
			Hops:          append([]string(nil), route.Hops...),
			IsRelay:       false,
			Score:         routeToCandidateScore(route),
			LatencyMs:     route.LatencyMs,
			MaxHop:        g.maxHop(),
			RouteEpoch:    route.Epoch,
			ICECandidates: append([]string(nil), destinationICE...),
		}
		if iceEnabled {
			iceCandidate := baseCandidate
			iceCandidate.Transport = "ice"
			iceCandidate.Score = baseCandidate.Score + 0.02
			candidates = append(candidates, iceCandidate)
		}
		if enableQUIC {
			quicCandidate := baseCandidate
			quicCandidate.Transport = "quic"
			quicCandidate.Score = baseCandidate.Score + 0.01
			candidates = append(candidates, quicCandidate)
		}
		if enableTCP {
			tcpCandidate := baseCandidate
			tcpCandidate.Transport = "tcp"
			candidates = append(candidates, tcpCandidate)
		}
	}

	relayPolicy := g.relayPolicy()
	if relayPolicy.Enabled {
		candidates = append(candidates, PathCandidate{
			NextHop:   "aps-relay",
			Transport: "relay",
			IsRelay:   true,
			Score:     0.01,
			MaxHop:    relayPolicy.MaxRelayHops,
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Score == candidates[j].Score {
			if candidates[i].LatencyMs == candidates[j].LatencyMs {
				return candidates[i].RouteEpoch > candidates[j].RouteEpoch
			}
			return candidates[i].LatencyMs < candidates[j].LatencyMs
		}
		return candidates[i].Score > candidates[j].Score
	})
	assignTopCandidatePriorities(candidates)
	if len(candidates) == 0 {
		return &GridQueryRouteResponse{
			Success:     false,
			Relay:       relayPolicy,
			Error:       "no route candidates available",
			ErrorCode:   GridRouteErrorTempUnreachable,
			Unreachable: true,
		}, nil
	}
	return &GridQueryRouteResponse{
		Success:    true,
		Routes:     routes,
		Candidates: candidates,
		Relay:      relayPolicy,
	}, nil
}

func (g *GridControlPlane) MarkNodeOffline(ctx context.Context, nodeID string, reason string) (*GridEvent, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil, errors.New("node_id is required")
	}
	if !g.markOfflineOnce(nodeID) {
		return nil, nil
	}

	_ = g.leaseStore.DeleteLease(ctx, nodeID)
	_ = g.stateStore.DeleteNode(ctx, nodeID)

	allRoutes, err := g.routeStore.ListRoutes(ctx, 8192)
	if err != nil {
		return nil, err
	}
	affectedRouteIDs := make([]string, 0, 32)
	recipientSet := make(map[string]struct{}, 16)
	for _, route := range allRoutes {
		if !routeContainsNode(route, nodeID) {
			continue
		}
		if revokeErr := g.routeStore.RevokeRoute(ctx, strings.TrimSpace(route.RouteID)); revokeErr != nil {
			DebugLog("[GRID] revoke route for offline node failed route=%s node=%s err=%v", route.RouteID, nodeID, revokeErr)
			continue
		}
		affectedRouteIDs = append(affectedRouteIDs, strings.TrimSpace(route.RouteID))
		for _, hop := range route.Hops {
			h := strings.TrimSpace(hop)
			if h == "" || strings.EqualFold(h, nodeID) {
				continue
			}
			recipientSet[h] = struct{}{}
		}
	}
	if len(recipientSet) == 0 {
		online := g.onlineNodeIDs(ctx)
		for _, onlineNode := range online {
			if !strings.EqualFold(onlineNode, nodeID) {
				recipientSet[onlineNode] = struct{}{}
			}
		}
	}
	recipients := make([]string, 0, len(recipientSet))
	for recipient := range recipientSet {
		recipients = append(recipients, recipient)
	}
	sort.Strings(recipients)
	sort.Strings(affectedRouteIDs)

	now := time.Now().UTC().Unix()
	event := GridEvent{
		Type:           "node_offline",
		NodeID:         nodeID,
		OfflineNodeID:  nodeID,
		Reason:         strings.TrimSpace(reason),
		AffectedRoutes: affectedRouteIDs,
		GeneratedAt:    now,
		ExpiresAt:      now + 600,
	}
	seq := g.enqueueEvent(event, recipients)
	event.Seq = seq
	g.publishJSON(ctx, gridSubjectNodeOffline, event)
	if len(affectedRouteIDs) > 0 {
		g.publishJSON(ctx, gridSubjectRoutePrune, map[string]any{
			"node_id":         nodeID,
			"affected_routes": affectedRouteIDs,
			"reason":          strings.TrimSpace(reason),
			"generated_at":    now,
		})
	}
	return &event, nil
}

func (g *GridControlPlane) PullEvents(ctx context.Context, req *GridEventsPullRequest) (*GridEventsPullResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	if req == nil {
		return &GridEventsPullResponse{Success: false, Error: "request is required"}, nil
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		return &GridEventsPullResponse{Success: false, Error: "node_id is required"}, nil
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 64
	}
	if limit > 256 {
		limit = 256
	}
	events, cursor := g.pullEventsForNode(nodeID, req.Cursor, limit)
	return &GridEventsPullResponse{
		Success: true,
		Cursor:  cursor,
		Events:  events,
	}, nil
}

func (g *GridControlPlane) TopologySnapshot(ctx context.Context, req *GridTopologyRequest) (*GridTopologyResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	limit := 4096
	if req != nil && req.Limit > 0 {
		limit = req.Limit
	}
	nodes, err := g.stateStore.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Unix()
	outNodes := make([]GridTopologyNode, 0, len(nodes))
	for _, node := range nodes {
		lease, _ := g.leaseStore.GetLease(ctx, strings.TrimSpace(node.NodeID))
		leaseExpires := int64(0)
		online := false
		if lease != nil {
			leaseExpires = lease.ExpiresAt
			online = lease.ExpiresAt > now
		}
		outNodes = append(outNodes, GridTopologyNode{
			NodeID:       strings.TrimSpace(node.NodeID),
			TunnelName:   strings.TrimSpace(node.TunnelName),
			EndpointName: strings.TrimSpace(node.EndpointName),
			Online:       online,
			LeaseExpires: leaseExpires,
			UpdatedAt:    node.UpdatedAt,
			Metadata:     copyStringMap(node.Metadata),
		})
	}
	sort.SliceStable(outNodes, func(i, j int) bool {
		return outNodes[i].NodeID < outNodes[j].NodeID
	})

	routes, err := g.routeStore.ListRoutes(ctx, limit)
	if err != nil {
		return nil, err
	}
	edges := make([]GridTopologyEdge, 0, len(routes)*2)
	for _, route := range routes {
		hops := normalizeRouteHops(route.Hops)
		if len(hops) < 2 {
			continue
		}
		for i := 0; i+1 < len(hops); i++ {
			edges = append(edges, GridTopologyEdge{
				RouteID:          strings.TrimSpace(route.RouteID),
				From:             hops[i],
				To:               hops[i+1],
				ReliabilityScore: route.ReliabilityScore,
				LatencyMs:        route.LatencyMs,
				Epoch:            route.Epoch,
				ExpiresAt:        route.ExpiresAt,
			})
		}
	}
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].From == edges[j].From {
			if edges[i].To == edges[j].To {
				return edges[i].RouteID < edges[j].RouteID
			}
			return edges[i].To < edges[j].To
		}
		return edges[i].From < edges[j].From
	})

	return &GridTopologyResponse{
		Success:     true,
		GeneratedAt: now,
		Nodes:       outNodes,
		Edges:       edges,
	}, nil
}

func (g *GridControlPlane) IssueSessionToken(ctx context.Context, req *GridIssueTokenRequest) (*GridIssueTokenResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		return &GridIssueTokenResponse{Success: false, Error: "node_id is required"}, nil
	}

	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = g.defaultTokenTTLSeconds()
	}
	tokenValue, err := randomHex(24)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Unix()
	token := &SessionToken{
		Token:     tokenValue,
		NodeID:    nodeID,
		Scope:     strings.TrimSpace(req.Scope),
		IssuedAt:  now,
		ExpiresAt: now + int64(ttl),
	}
	if err := g.tokenStore.SaveToken(ctx, token); err != nil {
		return nil, err
	}
	g.publishJSON(ctx, gridSubjectSessionIssue, token)
	return &GridIssueTokenResponse{Success: true, Token: token}, nil
}

func (g *GridControlPlane) RevokeSessionToken(ctx context.Context, req *GridRevokeTokenRequest) (*GridRevokeTokenResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return &GridRevokeTokenResponse{Success: false, Error: "token is required"}, nil
	}
	if err := g.tokenStore.RevokeToken(ctx, token); err != nil {
		return nil, err
	}
	g.publishJSON(ctx, gridSubjectSessionRevoke, map[string]string{"token": token})
	return &GridRevokeTokenResponse{Success: true}, nil
}

func (g *GridControlPlane) RefreshSessionToken(ctx context.Context, currentTokenValue string, req *GridRefreshTokenRequest) (*GridRefreshTokenResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	if req == nil {
		req = &GridRefreshTokenRequest{}
	}
	nodeID := strings.TrimSpace(req.NodeID)
	currentToken, err := g.ValidateSessionToken(ctx, currentTokenValue, nodeID, GridScopeSessionRefresh)
	if err != nil {
		return &GridRefreshTokenResponse{Success: false, Error: err.Error()}, nil
	}
	if currentToken == nil {
		return &GridRefreshTokenResponse{Success: false, Error: ErrGridTokenInvalid.Error()}, nil
	}
	if nodeID == "" {
		nodeID = strings.TrimSpace(currentToken.NodeID)
	}
	if nodeID == "" {
		return &GridRefreshTokenResponse{Success: false, Error: "node_id is required"}, nil
	}

	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = g.defaultTokenTTLSeconds()
	}
	tokenValue, err := randomHex(24)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Unix()
	rotated := &SessionToken{
		Token:     tokenValue,
		NodeID:    nodeID,
		Scope:     strings.TrimSpace(currentToken.Scope),
		IssuedAt:  now,
		ExpiresAt: now + int64(ttl),
	}
	if err := g.tokenStore.SaveToken(ctx, rotated); err != nil {
		return nil, err
	}
	if err := g.tokenStore.RevokeToken(ctx, strings.TrimSpace(currentToken.Token)); err != nil {
		return nil, err
	}
	g.publishJSON(ctx, gridSubjectSessionIssue, rotated)
	g.publishJSON(ctx, gridSubjectSessionRevoke, map[string]string{"token": strings.TrimSpace(currentToken.Token)})
	return &GridRefreshTokenResponse{Success: true, Token: rotated}, nil
}

func (g *GridControlPlane) ValidateSessionToken(ctx context.Context, tokenValue string, nodeID string, requiredScopes ...string) (*SessionToken, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	tokenValue = strings.TrimSpace(tokenValue)
	if tokenValue == "" {
		return nil, ErrGridTokenMissing
	}
	token, err := g.tokenStore.GetToken(ctx, tokenValue)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, ErrGridTokenInvalid
	}
	if token.Revoked {
		return nil, ErrGridTokenRevoked
	}
	now := time.Now().UTC().Unix()
	if token.ExpiresAt > 0 && token.ExpiresAt <= now {
		return nil, ErrGridTokenExpired
	}

	nodeID = strings.TrimSpace(nodeID)
	if nodeID != "" && !strings.EqualFold(strings.TrimSpace(token.NodeID), nodeID) {
		return nil, ErrGridTokenNodeMismatch
	}

	if !gridTokenScopeAllows(token.Scope, requiredScopes) {
		return nil, ErrGridScopeDenied
	}

	return token, nil
}

func (g *GridControlPlane) PublishICECandidates(ctx context.Context, req *GridICEPublishRequest) (*GridICEPublishResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	if g.iceStore == nil {
		return nil, errors.New("ice store is not initialized")
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		return &GridICEPublishResponse{Success: false, Error: "node_id is required"}, nil
	}
	candidates := normalizeICECandidates(req.Candidates)
	if len(candidates) == 0 {
		return &GridICEPublishResponse{Success: false, Error: "candidates are required"}, nil
	}
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 90
	}
	now := time.Now().UTC().Unix()
	set := &ICECandidateSet{
		NodeID:      nodeID,
		Candidates:  candidates,
		Metadata:    copyStringMap(req.Metadata),
		ExpiresAt:   now + int64(ttl),
		UpdatedAt:   now,
		PublishedBy: strings.TrimSpace(req.PublishedBy),
	}
	if err := g.iceStore.UpsertICECandidateSet(ctx, set); err != nil {
		return nil, err
	}
	g.publishJSON(ctx, "grid.ice.publish", set)
	return &GridICEPublishResponse{
		Success: true,
		Set:     set,
	}, nil
}

func (g *GridControlPlane) QueryICECandidates(ctx context.Context, req *GridICEQueryRequest) (*GridICEQueryResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	if g.iceStore == nil {
		return nil, errors.New("ice store is not initialized")
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		return &GridICEQueryResponse{Success: false, Error: "node_id is required"}, nil
	}
	set, err := g.iceStore.GetICECandidateSet(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return &GridICEQueryResponse{
			Success:     false,
			Error:       "ice candidates not found",
			ErrorCode:   GridRouteErrorNotFound,
			Unreachable: true,
		}, nil
	}
	if set.ExpiresAt > 0 && set.ExpiresAt < time.Now().UTC().Unix() {
		return &GridICEQueryResponse{
			Success:     false,
			Error:       "ice candidates expired",
			ErrorCode:   GridRouteErrorTempUnreachable,
			Unreachable: true,
		}, nil
	}
	return &GridICEQueryResponse{
		Success:    true,
		Set:        set,
		Candidates: append([]string(nil), set.Candidates...),
	}, nil
}

func (g *GridControlPlane) IssueICESession(ctx context.Context, req *GridICEIssueSessionRequest) (*GridICEIssueSessionResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	if req == nil {
		return &GridICEIssueSessionResponse{Success: false, Error: "request is required"}, nil
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		return &GridICEIssueSessionResponse{Success: false, Error: "node_id is required"}, nil
	}

	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = g.defaultICESessionTTLSeconds()
	}
	now := time.Now().UTC().Unix()
	sessionID, err := randomHex(12)
	if err != nil {
		return nil, err
	}
	username, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	password, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	session := &ICESessionDescriptor{
		NodeID:      nodeID,
		SessionID:   sessionID,
		Username:    "ice-" + username,
		Password:    password,
		Candidates:  g.iceRelayCandidates(),
		Metadata:    copyStringMap(req.Metadata),
		IssuedAt:    now,
		ExpiresAt:   now + int64(ttl),
		PublishedBy: strings.TrimSpace(req.PublishedBy),
	}
	g.publishJSON(ctx, "grid.ice.session.issue", session)
	return &GridICEIssueSessionResponse{
		Success: true,
		Session: session,
	}, nil
}

func (g *GridControlPlane) RefreshICESession(ctx context.Context, req *GridICERefreshSessionRequest) (*GridICERefreshSessionResponse, error) {
	if g == nil {
		return nil, errors.New("grid control plane not initialized")
	}
	if req == nil {
		return &GridICERefreshSessionResponse{Success: false, Error: "request is required"}, nil
	}
	issueResp, err := g.IssueICESession(ctx, &GridICEIssueSessionRequest{
		NodeID:      req.NodeID,
		TTLSeconds:  req.TTLSeconds,
		Metadata:    req.Metadata,
		PublishedBy: req.PublishedBy,
	})
	if err != nil {
		return nil, err
	}
	return &GridICERefreshSessionResponse{
		Success: issueResp.Success,
		Session: issueResp.Session,
		Error:   issueResp.Error,
	}, nil
}

func (g *GridControlPlane) publishJSON(ctx context.Context, subject string, value interface{}) {
	if g == nil || g.eventBus == nil {
		return
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return
	}
	if err := g.eventBus.Publish(ctx, subject, payload); err != nil {
		DebugLog("[GRID] publish event %s failed: %v", subject, err)
	}
}

func (g *GridControlPlane) isHopGuardEnabled() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.routingCfg != nil && g.routingCfg.HopGuard != nil && *g.routingCfg.HopGuard
}

func (g *GridControlPlane) maxHop() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.routingCfg == nil || g.routingCfg.MaxHop == nil || *g.routingCfg.MaxHop <= 0 {
		return 128
	}
	return *g.routingCfg.MaxHop
}

func (g *GridControlPlane) routingPathTTLSeconds() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.routingCfg == nil || g.routingCfg.PathTTLSeconds == nil || *g.routingCfg.PathTTLSeconds <= 0 {
		return 120
	}
	return *g.routingCfg.PathTTLSeconds
}

func (g *GridControlPlane) defaultTokenTTLSeconds() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.securityCfg == nil || g.securityCfg.DefaultTokenTTLSeconds == nil || *g.securityCfg.DefaultTokenTTLSeconds <= 0 {
		return 300
	}
	return *g.securityCfg.DefaultTokenTTLSeconds
}

func (g *GridControlPlane) relayPolicy() RelayFallbackPolicy {
	g.mu.RLock()
	defer g.mu.RUnlock()
	policy := RelayFallbackPolicy{
		Enabled:           true,
		MaxRelayHops:      6,
		FallbackTimeoutMs: 3000,
	}
	if g.relayCfg == nil {
		return policy
	}
	if g.relayCfg.Enabled != nil {
		policy.Enabled = *g.relayCfg.Enabled
	}
	if g.relayCfg.MaxRelayHops != nil && *g.relayCfg.MaxRelayHops > 0 {
		policy.MaxRelayHops = *g.relayCfg.MaxRelayHops
	}
	if g.relayCfg.FallbackTimeoutMs != nil && *g.relayCfg.FallbackTimeoutMs > 0 {
		policy.FallbackTimeoutMs = *g.relayCfg.FallbackTimeoutMs
	}
	return policy
}

func (g *GridControlPlane) transportCapabilities() (enableQUIC, enableTCP, parallel bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	enableQUIC, enableTCP, parallel = true, true, true
	if g.transportCfg == nil {
		return
	}
	if g.transportCfg.EnableQUIC != nil {
		enableQUIC = *g.transportCfg.EnableQUIC
	}
	if g.transportCfg.EnableTCP != nil {
		enableTCP = *g.transportCfg.EnableTCP
	}
	if g.transportCfg.Parallel != nil {
		parallel = *g.transportCfg.Parallel
	}
	return
}

func (g *GridControlPlane) isICEEnabled() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.iceCfg == nil || g.iceCfg.Enabled == nil {
		return true
	}
	return *g.iceCfg.Enabled
}

func (g *GridControlPlane) iceStaticCandidates(host string, port int) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.iceCfg == nil || len(g.iceCfg.StaticCandidates) == 0 {
		return nil
	}
	return expandGridICECandidateTemplates(g.iceCfg.StaticCandidates, host, port)
}

func (g *GridControlPlane) iceRelayCandidates() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.iceCfg == nil {
		return nil
	}
	candidates := make([]string, 0, len(g.iceCfg.STUNServers)+len(g.iceCfg.TURNServers)+len(g.iceCfg.StaticCandidates))
	candidates = append(candidates, g.iceCfg.STUNServers...)
	candidates = append(candidates, g.iceCfg.TURNServers...)
	candidates = append(candidates, g.iceCfg.StaticCandidates...)
	return normalizeICECandidates(candidates)
}

func (g *GridControlPlane) defaultICESessionTTLSeconds() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.iceCfg == nil || g.iceCfg.SessionTTLSeconds == nil || *g.iceCfg.SessionTTLSeconds <= 0 {
		return 300
	}
	return *g.iceCfg.SessionTTLSeconds
}

func randomHex(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("invalid random byte length")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func routeMetadataFloat(metadata map[string]string, keys ...string) float64 {
	if len(metadata) == 0 || len(keys) == 0 {
		return 0
	}
	for _, key := range keys {
		value := strings.TrimSpace(metadata[key])
		if value == "" {
			continue
		}
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f
		}
	}
	return 0
}

func routeContainsNode(route RouteDescriptor, nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(route.SourceNode), nodeID) || strings.EqualFold(strings.TrimSpace(route.DestinationNode), nodeID) {
		return true
	}
	for _, hop := range route.Hops {
		if strings.EqualFold(strings.TrimSpace(hop), nodeID) {
			return true
		}
	}
	return false
}

func (g *GridControlPlane) onlineNodeIDs(ctx context.Context) []string {
	if g == nil || g.stateStore == nil || g.leaseStore == nil {
		return nil
	}
	nodes, err := g.stateStore.ListNodes(ctx)
	if err != nil {
		return nil
	}
	now := time.Now().UTC().Unix()
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		nodeID := strings.TrimSpace(node.NodeID)
		if nodeID == "" {
			continue
		}
		lease, leaseErr := g.leaseStore.GetLease(ctx, nodeID)
		if leaseErr != nil || lease == nil || lease.ExpiresAt <= now {
			continue
		}
		out = append(out, nodeID)
	}
	return out
}

func (g *GridControlPlane) enqueueEvent(event GridEvent, recipients []string) int64 {
	if g == nil {
		return 0
	}
	if event.GeneratedAt <= 0 {
		event.GeneratedAt = time.Now().UTC().Unix()
	}
	if event.ExpiresAt <= 0 {
		event.ExpiresAt = event.GeneratedAt + 600
	}
	recipientSet := make(map[string]struct{}, len(recipients))
	for _, recipient := range recipients {
		nodeID := strings.TrimSpace(recipient)
		if nodeID == "" {
			continue
		}
		recipientSet[nodeID] = struct{}{}
	}
	g.eventMu.Lock()
	defer g.eventMu.Unlock()
	g.eventSeq++
	event.Seq = g.eventSeq
	g.eventLog = append(g.eventLog, gridEventEnvelope{
		event:      event,
		recipients: recipientSet,
	})
	cutoff := time.Now().UTC().Unix()
	trimmed := g.eventLog[:0]
	for _, item := range g.eventLog {
		if item.event.ExpiresAt > 0 && item.event.ExpiresAt < cutoff {
			continue
		}
		trimmed = append(trimmed, item)
	}
	if len(trimmed) > 2048 {
		trimmed = trimmed[len(trimmed)-2048:]
	}
	g.eventLog = trimmed
	return event.Seq
}

func (g *GridControlPlane) pullEventsForNode(nodeID string, cursor int64, limit int) ([]GridEvent, int64) {
	nodeID = strings.TrimSpace(nodeID)
	if g == nil || nodeID == "" {
		return nil, cursor
	}
	now := time.Now().UTC().Unix()
	g.eventMu.Lock()
	defer g.eventMu.Unlock()
	out := make([]GridEvent, 0, minInt(limit, 16))
	nextCursor := cursor
	for _, item := range g.eventLog {
		if item.event.Seq <= cursor {
			continue
		}
		if item.event.ExpiresAt > 0 && item.event.ExpiresAt < now {
			continue
		}
		if len(item.recipients) > 0 {
			if _, exists := item.recipients[nodeID]; !exists {
				continue
			}
		}
		out = append(out, item.event)
		nextCursor = item.event.Seq
		if len(out) >= limit {
			break
		}
	}
	if nextCursor < cursor {
		nextCursor = cursor
	}
	return out, nextCursor
}

func routeQualityCost(route RouteDescriptor) float64 {
	hopCount := float64(maxInt(1, len(route.Hops)))
	latency := float64(route.LatencyMs)
	if latency <= 0 {
		latency = hopCount * 15
	}
	jitterMs := routeMetadataFloat(route.Metadata, "jitter_ms", "jitter")
	lossPct := routeMetadataFloat(route.Metadata, "loss_pct", "packet_loss_pct", "loss")
	if lossPct < 0 {
		lossPct = 0
	}
	reliability := route.ReliabilityScore
	if reliability <= 0 {
		reliability = 0.01
	}
	// Dijkstra-compatible weighted edge cost approximation:
	// lower is better; combines hop count, latency, jitter and loss.
	return hopCount*1.0 + latency*0.02 + jitterMs*0.05 + lossPct*2.0 + (1.0/reliability)*0.5
}

func routeToCandidateScore(route RouteDescriptor) float64 {
	cost := routeQualityCost(route)
	if cost <= 0 {
		cost = 0.001
	}
	return 1.0 / cost
}

func assignTopCandidatePriorities(candidates []PathCandidate) {
	if len(candidates) == 0 {
		return
	}
	priority := 0
	priorityByRoute := make(map[string]int, 8)
	for i := range candidates {
		if candidates[i].IsRelay {
			continue
		}
		routeKey := routePriorityKey(candidates[i])
		if routeKey == "" || routeKey == "relay" {
			continue
		}
		p, exists := priorityByRoute[routeKey]
		if !exists {
			priority++
			if priority > 3 {
				continue
			}
			p = priority
			priorityByRoute[routeKey] = p
		}
		candidates[i].Priority = p
		if p == 1 {
			candidates[i].Role = "primary"
		} else {
			candidates[i].Role = "standby"
		}
	}
}

func normalizeICECandidates(candidates []string) []string {
	if len(candidates) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(candidates))
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		c := strings.TrimSpace(candidate)
		if c == "" {
			continue
		}
		if _, exists := seen[c]; exists {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
		if len(out) >= 128 {
			break
		}
	}
	return out
}

func copyStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		dst[key] = strings.TrimSpace(v)
	}
	if len(dst) == 0 {
		return nil
	}
	return dst
}

func gridTokenScopeAllows(scopeRaw string, requiredScopes []string) bool {
	if len(requiredScopes) == 0 {
		return true
	}
	required := normalizeGridScopeList(requiredScopes)
	if len(required) == 0 {
		return true
	}
	granted := normalizeGridScopeList([]string{scopeRaw})
	if len(granted) == 0 {
		// Empty scope means full access for backward compatibility.
		return true
	}
	for _, req := range required {
		for _, allow := range granted {
			if gridScopeMatch(allow, req) {
				return true
			}
		}
	}
	return false
}

func normalizeGridScopeList(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		for _, token := range strings.FieldsFunc(strings.TrimSpace(item), func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		}) {
			scope := strings.ToLower(strings.TrimSpace(token))
			if scope == "" {
				continue
			}
			if _, exists := seen[scope]; exists {
				continue
			}
			seen[scope] = struct{}{}
			out = append(out, scope)
		}
	}
	return out
}

func gridScopeMatch(granted, required string) bool {
	granted = strings.ToLower(strings.TrimSpace(granted))
	required = strings.ToLower(strings.TrimSpace(required))
	if granted == "" || required == "" {
		return false
	}
	if granted == GridScopeAll || granted == "grid:*" {
		return true
	}
	if granted == required {
		return true
	}
	if strings.HasSuffix(granted, "*") {
		prefix := strings.TrimSuffix(granted, "*")
		return strings.HasPrefix(required, prefix)
	}
	return false
}

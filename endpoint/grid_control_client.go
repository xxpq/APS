package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	endpointGridICEPublishInterval = 20 * time.Second
	endpointGridICESessionMinTTL   = 45 * time.Second
	endpointGridLeaseTTL           = 90 * time.Second
	endpointGridHeartbeatInterval  = 25 * time.Second
	endpointGridRouteAnnounceEvery = 45 * time.Second
	endpointGridSessionRefreshLead = 120 * time.Second
	endpointGridSessionRefreshGap  = 15 * time.Second
)

type endpointGridICEPublishRequest struct {
	NodeID      string   `json:"node_id"`
	Candidates  []string `json:"candidates,omitempty"`
	TTLSeconds  int      `json:"ttl_seconds,omitempty"`
	PublishedBy string   `json:"published_by,omitempty"`
}

type endpointGridICEPublishResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type endpointGridICESessionRequest struct {
	NodeID      string `json:"node_id"`
	TTLSeconds  int    `json:"ttl_seconds,omitempty"`
	PublishedBy string `json:"published_by,omitempty"`
}

type endpointGridICESessionDescriptor struct {
	NodeID     string   `json:"node_id"`
	SessionID  string   `json:"session_id"`
	Username   string   `json:"username,omitempty"`
	Password   string   `json:"password,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	IssuedAt   int64    `json:"issued_at"`
	ExpiresAt  int64    `json:"expires_at"`
}

type endpointGridICESessionResponse struct {
	Success bool                              `json:"success"`
	Session *endpointGridICESessionDescriptor `json:"session,omitempty"`
	Error   string                            `json:"error,omitempty"`
}

var endpointGridICEState = struct {
	mu              sync.Mutex
	running         bool
	lastPublishedAt time.Time
	lastIssuedAt    time.Time
	session         *endpointGridICESessionDescriptor
}{}

var endpointGridControlAuth = struct {
	mu       sync.Mutex
	nodeID   string
	token    string
	expires  int64
	issuedAt time.Time
}{}

var endpointGridControlState = struct {
	mu                sync.Mutex
	lastRegisterAt    time.Time
	lastHeartbeatAt   time.Time
	lastRouteAnnounce time.Time
	lastSessionRotate time.Time
	lastEventPullAt   time.Time
	eventCursor       int64
}{}

var endpointGridRuntimeContextState = struct {
	mu     sync.Mutex
	ctx    ImmutableConnectionContext
	loaded bool
}{}

func setEndpointGridRuntimeContext(connCtx ImmutableConnectionContext) {
	endpointGridRuntimeContextState.mu.Lock()
	defer endpointGridRuntimeContextState.mu.Unlock()
	endpointGridRuntimeContextState.ctx = ImmutableConnectionContext{
		ServerAddress:       normalizeServerAddressForSession(connCtx.ServerAddress),
		ConfigID:            strings.TrimSpace(connCtx.ConfigID),
		ServerName:          strings.TrimSpace(connCtx.ServerName),
		TunnelName:          strings.TrimSpace(connCtx.TunnelName),
		EndpointName:        strings.TrimSpace(connCtx.EndpointName),
		SessionCredential:   strings.TrimSpace(connCtx.SessionCredential),
		SessionExpiresAt:    connCtx.SessionExpiresAt,
		KDFVersion:          strings.TrimSpace(connCtx.KDFVersion),
		KDFSalt:             strings.TrimSpace(connCtx.KDFSalt),
		PortMappings:        clonePortMappingsForContext(connCtx.PortMappings),
		GatewayListen:       strings.TrimSpace(connCtx.GatewayListen),
		GatewayAddress:      strings.TrimSpace(connCtx.GatewayAddress),
		GatewayDiscovery:    connCtx.GatewayDiscovery,
		GatewayDiscoverPort: connCtx.GatewayDiscoverPort,
		SSH:                 cloneEndpointSSHConfigForContext(connCtx.SSH),
		MTLSCertFile:        strings.TrimSpace(connCtx.MTLSCertFile),
		MTLSKeyFile:         strings.TrimSpace(connCtx.MTLSKeyFile),
		MTLSCAFile:          strings.TrimSpace(connCtx.MTLSCAFile),
	}
	endpointGridRuntimeContextState.loaded = true
}

func currentEndpointGridRuntimeContext() (ImmutableConnectionContext, bool) {
	endpointGridRuntimeContextState.mu.Lock()
	defer endpointGridRuntimeContextState.mu.Unlock()
	if !endpointGridRuntimeContextState.loaded {
		return ImmutableConnectionContext{}, false
	}
	return endpointGridRuntimeContextState.ctx, true
}

func setEndpointGridControlSession(nodeID, token string, expiresAt int64) {
	nodeID = strings.TrimSpace(nodeID)
	token = strings.TrimSpace(token)
	endpointGridControlAuth.mu.Lock()
	defer endpointGridControlAuth.mu.Unlock()
	if nodeID != "" {
		endpointGridControlAuth.nodeID = nodeID
	}
	endpointGridControlAuth.token = token
	endpointGridControlAuth.expires = expiresAt
	endpointGridControlAuth.issuedAt = time.Now().UTC()
}

func currentEndpointGridControlSession() (string, string, int64) {
	endpointGridControlAuth.mu.Lock()
	defer endpointGridControlAuth.mu.Unlock()
	return endpointGridControlAuth.nodeID, endpointGridControlAuth.token, endpointGridControlAuth.expires
}

func triggerEndpointGridControlMaintenance(serverAddress string, connCtx ImmutableConnectionContext, force bool) {
	serverAddress = normalizeServerAddressForSession(serverAddress)
	if serverAddress == "" {
		return
	}
	setEndpointGridRuntimeContext(connCtx)
	nodeID := endpointGridNodeID(connCtx)
	if nodeID == "" {
		return
	}
	authNodeID, token, expiresAt := currentEndpointGridControlSession()
	if strings.TrimSpace(authNodeID) == "" || strings.TrimSpace(token) == "" {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(authNodeID), strings.TrimSpace(nodeID)) {
		return
	}
	if expiresAt > 0 && time.Now().UTC().Unix() >= expiresAt {
		return
	}
	go runEndpointGridControlMaintenance(serverAddress, connCtx, force)
}

func runEndpointGridControlMaintenance(serverAddress string, connCtx ImmutableConnectionContext, force bool) {
	now := time.Now().UTC()
	needRegister := force
	needHeartbeat := force
	needAnnounce := force
	needPullEvents := force

	endpointGridControlState.mu.Lock()
	if !needRegister && endpointGridControlState.lastRegisterAt.IsZero() {
		needRegister = true
	}
	if !needHeartbeat && now.Sub(endpointGridControlState.lastHeartbeatAt) >= endpointGridHeartbeatInterval {
		needHeartbeat = true
	}
	if !needAnnounce && now.Sub(endpointGridControlState.lastRouteAnnounce) >= endpointGridRouteAnnounceEvery {
		needAnnounce = true
	}
	if !needPullEvents && now.Sub(endpointGridControlState.lastEventPullAt) >= 8*time.Second {
		needPullEvents = true
	}
	endpointGridControlState.mu.Unlock()

	nodeID := endpointGridNodeID(connCtx)
	if nodeID == "" {
		return
	}
	if !ensureEndpointGridControlSessionActive(serverAddress, nodeID, force) {
		return
	}
	if needRegister {
		if err := endpointGridRegisterNode(serverAddress, connCtx, nodeID); err == nil {
			endpointGridControlState.mu.Lock()
			endpointGridControlState.lastRegisterAt = now
			endpointGridControlState.mu.Unlock()
		}
	}
	if needHeartbeat {
		if err := endpointGridHeartbeatNode(serverAddress, nodeID); err == nil {
			endpointGridControlState.mu.Lock()
			endpointGridControlState.lastHeartbeatAt = now
			endpointGridControlState.mu.Unlock()
		}
	}
	if needAnnounce {
		if err := endpointGridAnnounceRoutes(serverAddress, connCtx, nodeID); err == nil {
			endpointGridControlState.mu.Lock()
			endpointGridControlState.lastRouteAnnounce = now
			endpointGridControlState.mu.Unlock()
		}
	}
	if needPullEvents {
		if err := endpointGridPullEvents(serverAddress, nodeID); err == nil {
			endpointGridControlState.mu.Lock()
			endpointGridControlState.lastEventPullAt = now
			endpointGridControlState.mu.Unlock()
		}
	}
}

func ensureEndpointGridControlSessionActive(serverAddress, nodeID string, force bool) bool {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return false
	}
	authNodeID, token, expiresAt := currentEndpointGridControlSession()
	authNodeID = strings.TrimSpace(authNodeID)
	token = strings.TrimSpace(token)
	if authNodeID == "" || token == "" {
		return false
	}
	if !strings.EqualFold(authNodeID, nodeID) {
		return false
	}
	now := time.Now().UTC()
	if expiresAt > 0 && now.Unix() >= expiresAt {
		return false
	}

	remaining := time.Duration(0)
	if expiresAt > 0 {
		remaining = time.Until(time.Unix(expiresAt, 0))
	}
	if expiresAt > 0 && remaining > endpointGridSessionRefreshLead {
		return true
	}

	endpointGridControlState.mu.Lock()
	if !force && now.Sub(endpointGridControlState.lastSessionRotate) < endpointGridSessionRefreshGap {
		endpointGridControlState.mu.Unlock()
		return true
	}
	endpointGridControlState.lastSessionRotate = now
	endpointGridControlState.mu.Unlock()

	if err := endpointGridRefreshSessionToken(serverAddress, nodeID); err != nil {
		DebugLog("[GRID] session refresh skipped/failed: %v", err)
		return remaining > endpointGridSessionRefreshGap
	}
	return true
}

func endpointGridRegisterNode(serverAddress string, connCtx ImmutableConnectionContext, nodeID string) error {
	req := endpointGridRegisterRequest{
		LeaseTTLSeconds: int(endpointGridLeaseTTL.Seconds()),
	}
	req.Node.NodeID = nodeID
	req.Node.TunnelName = strings.TrimSpace(connCtx.TunnelName)
	req.Node.EndpointName = strings.TrimSpace(connCtx.EndpointName)
	req.Node.Capabilities = []string{"grid", "gateway", "quic", "tcp", "ice"}
	req.Node.Metadata = map[string]string{
		"gateway_listen": strings.TrimSpace(connCtx.GatewayListen),
		"gateway_mode":   boolToText(strings.TrimSpace(connCtx.GatewayListen) != ""),
	}
	var resp endpointGridRegisterResponse
	if err := doPinnedAPSJSONPost(serverAddress, "/.grid/register", &req, &resp); err != nil {
		return err
	}
	if !resp.Success {
		if strings.TrimSpace(resp.Error) == "" {
			return errors.New("grid register failed")
		}
		return errors.New(resp.Error)
	}
	return nil
}

func endpointGridHeartbeatNode(serverAddress, nodeID string) error {
	req := endpointGridHeartbeatRequest{
		NodeID:          nodeID,
		LeaseTTLSeconds: int(endpointGridLeaseTTL.Seconds()),
	}
	var resp endpointGridHeartbeatResponse
	if err := doPinnedAPSJSONPost(serverAddress, "/.grid/heartbeat", &req, &resp); err != nil {
		return err
	}
	if !resp.Success {
		if strings.TrimSpace(resp.Error) == "" {
			return errors.New("grid heartbeat failed")
		}
		return errors.New(resp.Error)
	}
	return nil
}

func endpointGridAnnounceRoutes(serverAddress string, connCtx ImmutableConnectionContext, nodeID string) error {
	serverName := strings.TrimSpace(connCtx.ServerName)
	if serverName == "" {
		return nil
	}
	sourceNode := "aps:" + serverName
	now := time.Now().UTC()
	req := endpointGridRouteAnnounceRequest{}
	req.Route.RouteID = "auto:" + sourceNode + "->" + nodeID
	req.Route.SourceNode = sourceNode
	req.Route.DestinationNode = nodeID
	req.Route.Hops = []string{sourceNode, nodeID}
	req.Route.ReliabilityScore = 0.99
	req.Route.LatencyMs = 12
	req.Route.Epoch = now.UnixNano()
	req.Route.ExpiresAt = now.Add(2 * endpointGridRouteAnnounceEvery).Unix()
	req.Route.Metadata = map[string]string{
		"auto":   "true",
		"origin": "endpoint",
	}
	var resp endpointGridRouteAnnounceResponse
	if err := doPinnedAPSJSONPost(serverAddress, "/.grid/route/announce", &req, &resp); err != nil {
		return err
	}
	if !resp.Success {
		if strings.TrimSpace(resp.Error) == "" {
			return errors.New("grid route announce failed")
		}
		return errors.New(resp.Error)
	}
	return nil
}

func boolToText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func endpointGridPullEvents(serverAddress, nodeID string) error {
	endpointGridControlState.mu.Lock()
	cursor := endpointGridControlState.eventCursor
	endpointGridControlState.mu.Unlock()

	req := endpointGridEventsPullRequest{
		NodeID: strings.TrimSpace(nodeID),
		Cursor: cursor,
		Limit:  64,
	}
	var resp endpointGridEventsPullResponse
	if err := doPinnedAPSJSONPost(serverAddress, "/.grid/events/pull", &req, &resp); err != nil {
		return err
	}
	if !resp.Success {
		if strings.TrimSpace(resp.Error) == "" {
			return errors.New("grid events pull failed")
		}
		return errors.New(resp.Error)
	}
	for _, event := range resp.Events {
		handleEndpointGridEvent(event)
	}
	if resp.Cursor > cursor {
		endpointGridControlState.mu.Lock()
		if resp.Cursor > endpointGridControlState.eventCursor {
			endpointGridControlState.eventCursor = resp.Cursor
		}
		endpointGridControlState.mu.Unlock()
	}
	return nil
}

func handleEndpointGridEvent(event endpointGridEvent) {
	eventType := strings.ToLower(strings.TrimSpace(event.Type))
	switch eventType {
	case "node_offline":
		offlineNode := strings.TrimSpace(event.OfflineNodeID)
		if offlineNode == "" {
			offlineNode = strings.TrimSpace(event.NodeID)
		}
		if offlineNode == "" {
			return
		}
		removed := invalidateGatewayNodeAndRoutes(offlineNode)
		if removed > 0 {
			DebugLog("[GRID] applied offline event node=%s removed_gateway_entries=%d reason=%s", offlineNode, removed, strings.TrimSpace(event.Reason))
		}
	}
}

func endpointGridRefreshSessionToken(serverAddress, nodeID string) error {
	req := endpointGridSessionRefreshRequest{
		NodeID: strings.TrimSpace(nodeID),
	}
	var resp endpointGridSessionRefreshResponse
	if err := doPinnedAPSJSONPost(serverAddress, "/.grid/session/refresh", &req, &resp); err != nil {
		return err
	}
	if !resp.Success || resp.Token == nil || strings.TrimSpace(resp.Token.Token) == "" {
		if strings.TrimSpace(resp.Error) != "" {
			return errors.New(resp.Error)
		}
		return errors.New("grid session refresh failed")
	}
	refreshNodeID := strings.TrimSpace(resp.Token.NodeID)
	if refreshNodeID == "" {
		refreshNodeID = strings.TrimSpace(nodeID)
	}
	setEndpointGridControlSession(refreshNodeID, strings.TrimSpace(resp.Token.Token), resp.Token.ExpiresAt)
	return nil
}

type endpointGridRegisterRequest struct {
	Node struct {
		NodeID       string            `json:"node_id"`
		TunnelName   string            `json:"tunnel_name,omitempty"`
		EndpointName string            `json:"endpoint_name,omitempty"`
		Capabilities []string          `json:"capabilities,omitempty"`
		Metadata     map[string]string `json:"metadata,omitempty"`
	} `json:"node"`
	LeaseTTLSeconds int `json:"lease_ttl_seconds,omitempty"`
}

type endpointGridRegisterResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type endpointGridHeartbeatRequest struct {
	NodeID          string `json:"node_id"`
	LeaseTTLSeconds int    `json:"lease_ttl_seconds,omitempty"`
}

type endpointGridHeartbeatResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type endpointGridRouteAnnounceRequest struct {
	Route struct {
		RouteID          string            `json:"route_id"`
		SourceNode       string            `json:"source_node"`
		DestinationNode  string            `json:"destination_node"`
		Hops             []string          `json:"hops"`
		ReliabilityScore float64           `json:"reliability_score"`
		LatencyMs        int64             `json:"latency_ms"`
		Epoch            int64             `json:"epoch"`
		ExpiresAt        int64             `json:"expires_at"`
		Metadata         map[string]string `json:"metadata,omitempty"`
	} `json:"route"`
}

type endpointGridRouteAnnounceResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type endpointGridSessionRefreshRequest struct {
	NodeID     string `json:"node_id,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

type endpointGridSessionToken struct {
	Token     string `json:"token"`
	NodeID    string `json:"node_id"`
	ExpiresAt int64  `json:"expires_at"`
}

type endpointGridSessionRefreshResponse struct {
	Success bool                      `json:"success"`
	Token   *endpointGridSessionToken `json:"token,omitempty"`
	Error   string                    `json:"error,omitempty"`
}

type endpointGridEvent struct {
	Seq            int64    `json:"seq"`
	Type           string   `json:"type"`
	NodeID         string   `json:"node_id,omitempty"`
	OfflineNodeID  string   `json:"offline_node_id,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	AffectedRoutes []string `json:"affected_routes,omitempty"`
	GeneratedAt    int64    `json:"generated_at,omitempty"`
	ExpiresAt      int64    `json:"expires_at,omitempty"`
}

type endpointGridEventsPullRequest struct {
	NodeID string `json:"node_id"`
	Cursor int64  `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type endpointGridEventsPullResponse struct {
	Success bool                `json:"success"`
	Cursor  int64               `json:"cursor,omitempty"`
	Events  []endpointGridEvent `json:"events,omitempty"`
	Error   string              `json:"error,omitempty"`
}

func triggerEndpointGridICEMaintenance(serverAddress string, connCtx ImmutableConnectionContext, force bool) {
	serverAddress = normalizeServerAddressForSession(serverAddress)
	if serverAddress == "" {
		return
	}
	setEndpointGridRuntimeContext(connCtx)
	if strings.TrimSpace(connCtx.EndpointName) == "" {
		return
	}

	endpointGridICEState.mu.Lock()
	if endpointGridICEState.running {
		endpointGridICEState.mu.Unlock()
		return
	}
	endpointGridICEState.running = true
	endpointGridICEState.mu.Unlock()

	go func() {
		defer func() {
			endpointGridICEState.mu.Lock()
			endpointGridICEState.running = false
			endpointGridICEState.mu.Unlock()
		}()
		runEndpointGridICEMaintenance(serverAddress, connCtx, force)
	}()
}

func runEndpointGridICEMaintenance(serverAddress string, connCtx ImmutableConnectionContext, force bool) {
	nodeID := endpointGridNodeID(connCtx)
	if nodeID == "" {
		return
	}

	now := time.Now()
	shouldPublish, shouldIssue := false, false
	endpointGridICEState.mu.Lock()
	if force || now.Sub(endpointGridICEState.lastPublishedAt) >= endpointGridICEPublishInterval {
		shouldPublish = true
	}
	if force || endpointGridICEState.session == nil || time.Unix(endpointGridICEState.session.ExpiresAt, 0).Before(now.Add(endpointGridICESessionMinTTL)) {
		shouldIssue = true
	}
	endpointGridICEState.mu.Unlock()

	if shouldPublish {
		if err := publishEndpointGridICECandidates(serverAddress, nodeID, connCtx); err != nil {
			markEndpointGridICEError(err)
		} else {
			endpointGridICEState.mu.Lock()
			endpointGridICEState.lastPublishedAt = now
			endpointGridICEState.mu.Unlock()
		}
	}

	if shouldIssue {
		session, err := issueEndpointGridICESession(serverAddress, nodeID)
		if err != nil {
			markEndpointGridICEError(err)
			return
		}
		if session != nil {
			session.Candidates = normalizeEndpointGridCandidates(session.Candidates)
			endpointGridICEState.mu.Lock()
			endpointGridICEState.session = session
			endpointGridICEState.lastIssuedAt = now
			endpointGridICEState.mu.Unlock()
		}
	}
}

func markEndpointGridICEError(err error) {
	if err == nil {
		return
	}
	DebugLog("[GRID-ICE] maintenance error: %v", err)
}

func publishEndpointGridICECandidates(serverAddress, nodeID string, connCtx ImmutableConnectionContext) error {
	candidates := collectEndpointGridICECandidates(connCtx)
	if len(candidates) == 0 {
		return nil
	}

	req := endpointGridICEPublishRequest{
		NodeID:      nodeID,
		Candidates:  candidates,
		TTLSeconds:  int((endpointGridICEPublishInterval + 40*time.Second).Seconds()),
		PublishedBy: nodeID,
	}
	var resp endpointGridICEPublishResponse
	if err := doPinnedAPSJSONPost(serverAddress, "/.grid/ice/publish", &req, &resp); err != nil {
		return err
	}
	if !resp.Success {
		if strings.TrimSpace(resp.Error) == "" {
			return errors.New("grid ice publish failed")
		}
		return errors.New(resp.Error)
	}
	return nil
}

func issueEndpointGridICESession(serverAddress, nodeID string) (*endpointGridICESessionDescriptor, error) {
	req := endpointGridICESessionRequest{
		NodeID:      nodeID,
		TTLSeconds:  300,
		PublishedBy: nodeID,
	}
	var resp endpointGridICESessionResponse
	if err := doPinnedAPSJSONPost(serverAddress, "/.grid/ice/session/issue", &req, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		if strings.TrimSpace(resp.Error) == "" {
			return nil, errors.New("grid ice session issue failed")
		}
		return nil, errors.New(resp.Error)
	}
	if resp.Session == nil {
		return nil, errors.New("empty grid ice session")
	}
	return resp.Session, nil
}

func currentEndpointGridICESessionCandidates() []string {
	session := currentEndpointGridICESessionSnapshot()
	if session == nil {
		return nil
	}
	return append([]string(nil), session.Candidates...)
}

func currentEndpointGridICESessionAuth() (string, string) {
	session := currentEndpointGridICESessionSnapshot()
	if session == nil {
		return "", ""
	}
	return strings.TrimSpace(session.Username), strings.TrimSpace(session.Password)
}

func currentEndpointGridICESessionSnapshot() *endpointGridICESessionDescriptor {
	endpointGridICEState.mu.Lock()
	defer endpointGridICEState.mu.Unlock()
	if endpointGridICEState.session == nil {
		return nil
	}
	if endpointGridICEState.session.ExpiresAt > 0 && endpointGridICEState.session.ExpiresAt <= time.Now().UTC().Unix() {
		endpointGridICEState.session = nil
		return nil
	}
	s := *endpointGridICEState.session
	s.Candidates = append([]string(nil), endpointGridICEState.session.Candidates...)
	return &s
}

func endpointGridNodeID(connCtx ImmutableConnectionContext) string {
	nodeID := strings.TrimSpace(connCtx.EndpointName)
	if nodeID != "" {
		return nodeID
	}
	return strings.TrimSpace(connCtx.ConfigID)
}

func collectEndpointGridICECandidates(connCtx ImmutableConnectionContext) []string {
	listenPort := endpointGridListenPort(connCtx)
	ports := make([]int, 0, 8)
	if listenPort > 0 {
		ports = append(ports, listenPort)
	}
	ports = append(ports, parseGridPortList(os.Getenv("APS_GRID_ICE_LISTEN_PORTS"))...)
	ports = normalizeGridCandidatePorts(ports)

	hosts := collectEndpointGridLocalHosts()
	if host := endpointGridListenHost(connCtx); host != "" {
		hosts = append(hosts, host)
	}
	hosts = normalizeEndpointGridHosts(hosts)

	candidates := make([]string, 0, len(hosts)*len(ports)+len(ports)+8)
	for _, host := range hosts {
		for _, port := range ports {
			candidates = append(candidates, net.JoinHostPort(host, strconv.Itoa(port)))
		}
	}
	candidates = append(candidates, gridUPnPCandidatesForPorts(ports)...)
	envCandidates := parseEndpointGridCandidateEnv(os.Getenv("APS_GRID_ICE_CANDIDATES"))
	candidates = append(candidates, envCandidates...)
	stunSeeds := append([]string(nil), parseEndpointGridCandidateEnv(os.Getenv("APS_GRID_ICE_STUN_SERVERS"))...)
	stunSeeds = append(stunSeeds, envCandidates...)
	stunSeeds = append(stunSeeds, currentEndpointGridICESessionCandidates()...)
	candidates = append(candidates, discoverEndpointGridSTUNCandidates(stunSeeds, ports, gridICEProbeTimeout())...)
	sessionUser, sessionPass := currentEndpointGridICESessionAuth()
	turnSeeds := append([]string(nil), parseEndpointGridCandidateEnv(os.Getenv("APS_GRID_ICE_TURN_SERVERS"))...)
	turnSeeds = append(turnSeeds, envCandidates...)
	turnSeeds = append(turnSeeds, currentEndpointGridICESessionCandidates()...)
	candidates = append(candidates, discoverEndpointGridTURNCandidates(turnSeeds, sessionUser, sessionPass, ports, 1500*time.Millisecond)...)
	return normalizeEndpointGridCandidates(candidates)
}

func endpointGridListenPort(connCtx ImmutableConnectionContext) int {
	if addr := strings.TrimSpace(connCtx.GatewayListen); addr != "" {
		if _, portText, err := net.SplitHostPort(addr); err == nil {
			if port, convErr := strconv.Atoi(strings.TrimSpace(portText)); convErr == nil && port > 0 && port <= 65535 {
				return port
			}
		}
	}
	return 0
}

func endpointGridListenHost(connCtx ImmutableConnectionContext) string {
	addr := strings.TrimSpace(connCtx.GatewayListen)
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || host == "0.0.0.0" || host == "::" || strings.EqualFold(host, "localhost") {
		return ""
	}
	return host
}

func collectEndpointGridLocalHosts() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]string, 0, 12)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, raw := range addrs {
			var ip net.IP
			switch addr := raw.(type) {
			case *net.IPNet:
				ip = addr.IP
			case *net.IPAddr:
				ip = addr.IP
			default:
				continue
			}
			if ip == nil || ip.IsLoopback() || !ip.IsGlobalUnicast() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out
}

func normalizeEndpointGridHosts(hosts []string) []string {
	if len(hosts) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, raw := range hosts {
		host := strings.Trim(strings.TrimSpace(raw), "[]")
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func normalizeEndpointGridCandidates(candidates []string) []string {
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
	}
	sort.Strings(out)
	if len(out) > 128 {
		out = out[:128]
	}
	return out
}

func parseEndpointGridCandidateEnv(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		candidate := strings.TrimSpace(part)
		if candidate == "" {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

func buildEndpointGridGatewayPinnedClient(pin *endpointTLSPin, serverAddress string) (*http.Client, string) {
	if pin == nil {
		return nil, ""
	}
	connCtx, loaded := currentEndpointGridRuntimeContext()
	if !loaded {
		return nil, ""
	}
	if strings.TrimSpace(connCtx.ServerAddress) == "" {
		connCtx.ServerAddress = normalizeServerAddressForSession(serverAddress)
	}
	connCtx.ServerAddress = normalizeServerAddressForSession(connCtx.ServerAddress)
	if connCtx.ServerAddress == "" {
		return nil, ""
	}
	gatewayAddress := resolveGatewayAddress(connCtx)
	if gatewayAddress == "" {
		return nil, ""
	}
	targetAddress := normalizeServerAddressForSession(pin.serverAddress)
	if targetAddress == "" {
		targetAddress = normalizeServerAddressForSession(serverAddress)
	}
	if targetAddress == "" {
		return nil, ""
	}
	originNode := strings.TrimSpace(connCtx.ConfigID)
	dialViaGateway := func(ctx context.Context, network, addr string) (net.Conn, error) {
		type dialResult struct {
			conn net.Conn
			err  error
		}
		done := make(chan dialResult, 1)
		go func() {
			conn, err := dialTunnelServerViaGateway(gatewayAddress, targetAddress, originNode)
			done <- dialResult{conn: conn, err: err}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-done:
			return result.conn, result.err
		}
	}
	return newPinnedHTTPClientWithDialContext(pin, dialViaGateway), gatewayAddress
}

func doPinnedAPSJSONPost(serverAddress, requestPath string, reqBody any, respBody any) error {
	pin, err := ensureEndpointTLSPin(serverAddress)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	send := func(client *http.Client, p *endpointTLSPin) (*http.Response, error) {
		req, reqErr := http.NewRequest(http.MethodPost, "https://"+p.serverAddress+requestPath, bytes.NewReader(payload))
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("Content-Type", "application/json")
		if strings.HasPrefix(strings.TrimSpace(requestPath), "/.grid/") {
			_, token, expiresAt := currentEndpointGridControlSession()
			if strings.TrimSpace(token) != "" && (expiresAt <= 0 || time.Now().UTC().Unix() < expiresAt) {
				req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
			}
		}
		return client.Do(req)
	}

	trySendWithGatewayFallback := func(p *endpointTLSPin) (*http.Response, error) {
		resp, directErr := send(p.client, p)
		if directErr == nil {
			return resp, nil
		}
		gatewayClient, gatewayAddress := buildEndpointGridGatewayPinnedClient(p, serverAddress)
		if gatewayClient == nil {
			return nil, directErr
		}
		gatewayResp, gatewayErr := send(gatewayClient, p)
		if gatewayErr == nil {
			DebugLog("[GRID] control api %s via gateway=%s target=%s", strings.TrimSpace(requestPath), gatewayAddress, p.serverAddress)
			return gatewayResp, nil
		}
		return nil, directErr
	}

	resp, err := trySendWithGatewayFallback(pin)
	if err != nil {
		if !shouldRefreshPinAfterError(err) {
			return err
		}
		refreshedPin, refreshErr := refreshEndpointTLSPin(serverAddress)
		if refreshErr != nil {
			return fmt.Errorf("tls pin request failed: %w (refresh failed: %v)", err, refreshErr)
		}
		resp, err = trySendWithGatewayFallback(refreshedPin)
		if err != nil {
			return err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		return fmt.Errorf("grid api %s status=%d body=%s", requestPath, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if respBody == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
		return err
	}
	return nil
}

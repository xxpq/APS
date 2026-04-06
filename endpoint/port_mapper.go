package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// PortMapper manages local port listeners that forward traffic to remote endpoints
type PortMapper struct {
	mappings   []PortMappingConfig
	listeners  map[string]net.Listener
	tunnelConn *TunnelConn // Connection to APS for forwarding
	mu         sync.RWMutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// PortForwardConnection represents an active port forwarding connection
type PortForwardConnection struct {
	LocalConn    net.Conn
	ConnectionID string
	Mapping      PortMappingConfig
	RouteChain   string
	Done         chan struct{}
}

// NewPortMapper creates a new port mapper instance
func NewPortMapper(mappings []PortMappingConfig) *PortMapper {
	return &PortMapper{
		mappings:  mappings,
		listeners: make(map[string]net.Listener),
		stopCh:    make(chan struct{}),
	}
}

// SetTunnelConn sets the tunnel connection for forwarding traffic
func (pm *PortMapper) SetTunnelConn(tc *TunnelConn) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.tunnelConn = tc
}

// Start starts all port listeners based on the configured mappings
func (pm *PortMapper) Start() error {
	for _, mapping := range pm.mappings {
		if err := pm.startListener(mapping); err != nil {
			log.Printf("[PORT-MAP] Failed to start listener on %s: %v", mapping.LocalListen, err)
			// Continue with other mappings even if one fails
		}
	}
	return nil
}

// startListener starts a listener for a specific port mapping
func (pm *PortMapper) startListener(mapping PortMappingConfig) error {
	addr := strings.TrimSpace(mapping.LocalListen)
	if addr == "" {
		return fmt.Errorf("localListen is required")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	pm.mu.Lock()
	pm.listeners[addr] = listener
	pm.mu.Unlock()

	log.Printf("[PORT-MAP] Listening on %s -> %s via endpoint %s",
		addr, mapping.RemoteTarget, mapping.TargetEndpoint)

	pm.wg.Add(1)
	go pm.acceptLoop(listener, mapping)

	return nil
}

// acceptLoop accepts connections and forwards them
func (pm *PortMapper) acceptLoop(listener net.Listener, mapping PortMappingConfig) {
	defer pm.wg.Done()

	for {
		select {
		case <-pm.stopCh:
			return
		default:
		}

		// Set accept deadline to allow checking stopCh
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Check if we're shutting down
			select {
			case <-pm.stopCh:
				return
			default:
				log.Printf("[PORT-MAP] Accept error on %s: %v", mapping.LocalListen, err)
				continue
			}
		}

		go pm.handleConnection(conn, mapping)
	}
}

// handleConnection handles a single forwarded connection
func (pm *PortMapper) handleConnection(conn net.Conn, mapping PortMappingConfig) {
	defer conn.Close()

	pm.mu.RLock()
	tc := pm.tunnelConn
	pm.mu.RUnlock()

	if tc == nil {
		log.Printf("[PORT-MAP] No tunnel connection available for forwarding")
		return
	}

	clientAddr := conn.RemoteAddr().String()
	DebugLog("[PORT-MAP] New connection from %s on %s -> %s via endpoint %s",
		clientAddr, mapping.LocalListen, mapping.RemoteTarget, mapping.TargetEndpoint)
	pm.handleTunnelStreamForward(conn, tc, mapping, clientAddr)
}

// handleTunnelStreamForward forwards connection via APS tunnel SMUX stream
func (pm *PortMapper) handleTunnelStreamForward(localConn net.Conn, tc *TunnelConn, mapping PortMappingConfig, clientIP string) {
	// Get access to the tunnel's SMUX session
	// This requires the tunnel connection to also have a Session field
	// For now, we'll fall back to message-based forwarding
	// TODO: Implement tunnel stream forwarding after refactoring TunnelConn

	// Generate connection ID
	connectionID := generateConnectionID()

	// P2P-first path: dial target endpoint gateway peer and run direct stream forwarding.
	p2pConn, p2pChain, p2pErr := pm.tryPortForwardP2P(connectionID, mapping, clientIP)
	if p2pErr == nil && p2pConn != nil {
		defer p2pConn.Close()
		DebugLog("[PORT-MAP] Route chain conn=%s transport=p2p-grid: %s", connectionID, p2pChain)
		pm.pipePortForwardRaw(connectionID, localConn, p2pConn)
		return
	}
	if p2pErr != nil {
		DebugLog("[PORT-MAP] P2P route unavailable conn=%s target=%s err=%v; fallback=aps-relay",
			connectionID, strings.TrimSpace(mapping.TargetEndpoint), p2pErr)
	}

	routeChain := buildPortForwardRouteChain(tc, mapping)

	// Store the connection for data forwarding
	storePortForwardConnection(connectionID, localConn, mapping, routeChain)
	defer removePortForwardConnection(connectionID)

	DebugLog("[PORT-MAP] Route chain conn=%s transport=aps-relay: %s", connectionID, routeChain)

	// Request proxy connection through APS to the target endpoint
	if err := pm.requestPortForward(tc, connectionID, mapping, clientIP); err != nil {
		log.Printf("[PORT-MAP] Failed to request port forward conn=%s route=\"%s\": %v", connectionID, routeChain, err)
		return
	}

	// Wait for connection acknowledgment and handle data transfer
	<-getPortForwardDoneChan(connectionID)
}

func (pm *PortMapper) tryPortForwardP2P(connectionID string, mapping PortMappingConfig, clientIP string) (net.Conn, string, error) {
	targetEndpoint := strings.TrimSpace(mapping.TargetEndpoint)
	remoteTarget := strings.TrimSpace(mapping.RemoteTarget)
	if targetEndpoint == "" {
		return nil, "", fmt.Errorf("empty target endpoint")
	}
	if remoteTarget == "" {
		return nil, "", fmt.Errorf("empty remote target")
	}
	if isLocalGatewayNodeID(targetEndpoint) {
		return nil, "", fmt.Errorf("target endpoint is self")
	}

	candidates := buildPortForwardPeerCandidates(targetEndpoint, nil)
	peerConn, selectedNode, err := dialPortForwardPeerCandidates(candidates)
	if err != nil {
		return nil, "", err
	}

	peerTC := NewTunnelConn(peerConn)
	req := PortForwardRequestPayload{
		ConnectionID:   connectionID,
		TargetEndpoint: targetEndpoint,
		RemoteTarget:   remoteTarget,
		ClientIP:       clientIP,
		HopCount:       0,
	}
	if !strings.EqualFold(strings.TrimSpace(selectedNode), targetEndpoint) {
		req.GridNextHop = targetEndpoint
		req.GridHops = buildPortForwardTransitBackups(targetEndpoint, candidates, selectedNode)
	}
	if err := peerTC.SendJSON(MsgTypePortForwardRequest, req); err != nil {
		_ = peerConn.Close()
		return nil, "", fmt.Errorf("send p2p port-forward request failed: %w", err)
	}

	_ = peerConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	respMsg, err := peerTC.ReadMessage()
	_ = peerConn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = peerConn.Close()
		return nil, "", fmt.Errorf("read p2p port-forward response failed: %w", err)
	}
	if respMsg.Type != MsgTypePortForwardResponse {
		_ = peerConn.Close()
		return nil, "", fmt.Errorf("unexpected p2p response type %d", respMsg.Type)
	}

	var resp PortForwardResponsePayload
	if err := respMsg.ParseJSON(&resp); err != nil {
		_ = peerConn.Close()
		return nil, "", fmt.Errorf("parse p2p port-forward response failed: %w", err)
	}
	if !resp.Success {
		_ = peerConn.Close()
		msg := strings.TrimSpace(resp.Error)
		if msg == "" {
			msg = "target endpoint rejected p2p request"
		}
		return nil, "", errors.New(msg)
	}

	return peerConn, buildPortForwardP2PRouteChain(mapping, selectedNode, req.GridNextHop, req.GridHops), nil
}

func buildPortForwardP2PRouteChain(mapping PortMappingConfig, selectedNode, nextHop string, hops []string) string {
	source := strings.TrimSpace(GetEffectiveEndpointName())
	if source == "" {
		source = "local-endpoint"
	}
	selectedNode = strings.TrimSpace(selectedNode)
	target := strings.TrimSpace(mapping.TargetEndpoint)
	if target == "" {
		target = "unknown-endpoint"
	}
	if selectedNode == "" {
		selectedNode = target
	}
	remoteTarget := strings.TrimSpace(mapping.RemoteTarget)
	if remoteTarget == "" {
		remoteTarget = "unknown-target"
	}
	nextHop = strings.TrimSpace(nextHop)
	if nextHop == "" || strings.EqualFold(selectedNode, target) {
		return fmt.Sprintf("%s -> P2P[%s] -> %s", source, selectedNode, remoteTarget)
	}
	if len(hops) > 0 {
		return fmt.Sprintf("%s -> P2P[first=%s next=%s backups=%s] -> %s",
			source, selectedNode, nextHop, strings.Join(hops, ","), remoteTarget)
	}
	return fmt.Sprintf("%s -> P2P[first=%s next=%s] -> %s", source, selectedNode, nextHop, remoteTarget)
}

func buildPortForwardPeerCandidates(targetEndpoint string, extra []string) []string {
	targetEndpoint = normalizeGatewayNodeID(targetEndpoint)
	self := localPrimaryGatewayNodeID()
	seen := make(map[string]struct{}, gatewayRouteBundleMaxAddrs+len(extra)+1)
	out := make([]string, 0, gatewayRouteBundleMaxAddrs+len(extra)+1)
	add := func(nodeID string) {
		nodeID = normalizeGatewayNodeID(nodeID)
		if nodeID == "" {
			return
		}
		if self != "" && nodeID == self {
			return
		}
		if _, exists := seen[nodeID]; exists {
			return
		}
		seen[nodeID] = struct{}{}
		out = append(out, nodeID)
	}
	add(targetEndpoint)
	for _, nodeID := range extra {
		add(nodeID)
	}
	for _, nodeID := range selectGatewayPeerDialCandidates(targetEndpoint, nil, gatewayRouteBundleMaxAddrs) {
		add(nodeID)
	}
	if len(out) > gatewayRouteBundleMaxAddrs {
		out = out[:gatewayRouteBundleMaxAddrs]
	}
	return out
}

func buildPortForwardTransitBackups(targetEndpoint string, candidates []string, selectedNode string) []string {
	targetEndpoint = normalizeGatewayNodeID(targetEndpoint)
	selectedNode = normalizeGatewayNodeID(selectedNode)
	seen := make(map[string]struct{}, len(candidates))
	out := make([]string, 0, gatewayRouteBundleMaxAddrs-1)
	for _, nodeID := range candidates {
		nodeID = normalizeGatewayNodeID(nodeID)
		if nodeID == "" || nodeID == targetEndpoint || nodeID == selectedNode {
			continue
		}
		if _, exists := seen[nodeID]; exists {
			continue
		}
		seen[nodeID] = struct{}{}
		out = append(out, nodeID)
		if len(out) >= gatewayRouteBundleMaxAddrs-1 {
			break
		}
	}
	return out
}

func dialPortForwardPeerCandidates(candidates []string) (net.Conn, string, error) {
	var lastErr error
	for _, nodeID := range candidates {
		nodeID = normalizeGatewayNodeID(nodeID)
		if nodeID == "" {
			continue
		}
		conn, err := dialGatewayPeerGrid(nodeID)
		if err == nil && conn != nil {
			return conn, nodeID, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no p2p peer candidate")
	}
	return nil, "", lastErr
}

func (pm *PortMapper) pipePortForwardRaw(connectionID string, localConn net.Conn, remoteConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(remoteConn, localConn)
		_ = remoteConn.SetReadDeadline(time.Now())
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, remoteConn)
		_ = localConn.SetReadDeadline(time.Now())
	}()

	wg.Wait()
	DebugLog("[PORT-MAP] P2P stream finished conn=%s", connectionID)
}

// requestPortForward sends a port forward request through the tunnel
func (pm *PortMapper) requestPortForward(tc *TunnelConn, connectionID string, mapping PortMappingConfig, clientIP string) error {
	payload := PortForwardRequestPayload{
		ConnectionID:   connectionID,
		TargetEndpoint: mapping.TargetEndpoint,
		RemoteTarget:   mapping.RemoteTarget,
		ClientIP:       clientIP,
	}

	return tc.SendJSON(MsgTypePortForwardRequest, payload)
}

func buildPortForwardRouteChain(tc *TunnelConn, mapping PortMappingConfig) string {
	source := strings.TrimSpace(GetEffectiveEndpointName())
	if source == "" {
		source = "local-endpoint"
	}

	target := strings.TrimSpace(mapping.TargetEndpoint)
	if target == "" {
		target = "unknown-endpoint"
	}

	remoteTarget := strings.TrimSpace(mapping.RemoteTarget)
	if remoteTarget == "" {
		remoteTarget = "unknown-target"
	}

	apsHop := resolvePortForwardAPSHop(tc)
	return fmt.Sprintf("%s -> APS[%s] -> %s -> %s", source, apsHop, target, remoteTarget)
}

func resolvePortForwardAPSHop(tc *TunnelConn) string {
	serverHint := ""
	if serverAddr != nil {
		serverHint = strings.TrimSpace(*serverAddr)
		if idx := strings.Index(serverHint, ","); idx >= 0 {
			serverHint = strings.TrimSpace(serverHint[:idx])
		}
	}

	remoteHop := ""
	if tc != nil && tc.conn != nil && tc.conn.RemoteAddr() != nil {
		remoteHop = strings.TrimSpace(tc.conn.RemoteAddr().String())
	}

	switch {
	case serverHint != "":
		return serverHint
	case remoteHop != "":
		return remoteHop
	default:
		return "unknown"
	}
}

// Stop stops all port listeners
func (pm *PortMapper) Stop() {
	close(pm.stopCh)

	pm.mu.Lock()
	for listenAddr, listener := range pm.listeners {
		listener.Close()
		DebugLog("[PORT-MAP] Stopped listener on %s", listenAddr)
	}
	pm.listeners = make(map[string]net.Listener)
	pm.mu.Unlock()

	pm.wg.Wait()
}

// UpdateMappings updates the port mappings (hot reload support)
func (pm *PortMapper) UpdateMappings(newMappings []PortMappingConfig) {
	pm.mu.Lock()

	// Find ports to remove
	newPorts := make(map[string]bool)
	for _, m := range newMappings {
		newPorts[strings.TrimSpace(m.LocalListen)] = true
	}

	// Stop listeners for removed ports
	for listenAddr, listener := range pm.listeners {
		if !newPorts[listenAddr] {
			listener.Close()
			delete(pm.listeners, listenAddr)
			DebugLog("[PORT-MAP] Removed listener on %s", listenAddr)
		}
	}
	pm.mu.Unlock()

	// Start listeners for new ports
	for _, mapping := range newMappings {
		listenAddr := strings.TrimSpace(mapping.LocalListen)
		pm.mu.RLock()
		_, exists := pm.listeners[listenAddr]
		pm.mu.RUnlock()

		if !exists {
			if err := pm.startListener(mapping); err != nil {
				log.Printf("[PORT-MAP] Failed to start new listener on %s: %v", listenAddr, err)
			}
		}
	}

	pm.mu.Lock()
	pm.mappings = newMappings
	pm.mu.Unlock()
}

// PortForwardRequestPayload is sent by endpoint to request port forwarding
type PortForwardRequestPayload struct {
	ConnectionID   string   `json:"connection_id"`
	TargetEndpoint string   `json:"target_endpoint"` // Which endpoint to forward to
	RemoteTarget   string   `json:"remote_target"`   // IP:Port on target endpoint's network
	ClientIP       string   `json:"client_ip"`       // Original client IP
	GridNextHop    string   `json:"grid_next_hop,omitempty"`
	GridHops       []string `json:"grid_hops,omitempty"`
	HopCount       int      `json:"hop_count,omitempty"`
}

// PortForwardResponsePayload is sent back with connection result
type PortForwardResponsePayload struct {
	ConnectionID string `json:"connection_id"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
}

// Port forward connection storage
var (
	portForwardConns   = make(map[string]*PortForwardConnection)
	portForwardConnsMu sync.RWMutex
)

func storePortForwardConnection(id string, conn net.Conn, mapping PortMappingConfig, routeChain string) {
	portForwardConnsMu.Lock()
	portForwardConns[id] = &PortForwardConnection{
		LocalConn:    conn,
		ConnectionID: id,
		Mapping:      mapping,
		RouteChain:   routeChain,
		Done:         make(chan struct{}),
	}
	portForwardConnsMu.Unlock()
}

func getPortForwardConnection(id string) (*PortForwardConnection, bool) {
	portForwardConnsMu.RLock()
	defer portForwardConnsMu.RUnlock()
	conn, ok := portForwardConns[id]
	return conn, ok
}

func removePortForwardConnection(id string) {
	portForwardConnsMu.Lock()
	if conn, ok := portForwardConns[id]; ok {
		if conn.LocalConn != nil {
			_ = conn.LocalConn.Close()
		}
		close(conn.Done)
		delete(portForwardConns, id)
	}
	portForwardConnsMu.Unlock()
}

func getPortForwardDoneChan(id string) <-chan struct{} {
	portForwardConnsMu.RLock()
	defer portForwardConnsMu.RUnlock()
	if conn, ok := portForwardConns[id]; ok {
		return conn.Done
	}
	// Return closed channel if not found
	ch := make(chan struct{})
	close(ch)
	return ch
}

// handlePortForwardData handles incoming data for port forwarded connections
func handlePortForwardData(connectionID string, data []byte) {
	pfc, ok := getPortForwardConnection(connectionID)
	if !ok {
		DebugLog("[PORT-MAP] Connection %s not found for data", connectionID)
		return
	}

	_, err := pfc.LocalConn.Write(data)
	if err != nil {
		log.Printf("[PORT-MAP] Write error for connection %s: %v", connectionID, err)
		removePortForwardConnection(connectionID)
	}
}

// handlePortForwardClose handles close of port forwarded connections
func handlePortForwardClose(connectionID string) {
	removePortForwardConnection(connectionID)
}

// handlePortForwardRequestMsg handles inbound port-forward request on the target endpoint.
func handlePortForwardRequestMsg(tc *TunnelConn, msg *TunnelMessage) {
	var payload PortForwardRequestPayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[PORT-MAP] Failed to parse inbound port forward request: %v", err)
		return
	}

	connectionID := strings.TrimSpace(payload.ConnectionID)
	remoteTarget := strings.TrimSpace(payload.RemoteTarget)
	targetEndpoint := strings.TrimSpace(payload.TargetEndpoint)
	sourceClient := strings.TrimSpace(payload.ClientIP)
	if connectionID == "" || remoteTarget == "" {
		errMsg := "invalid port forward request payload"
		log.Printf("[PORT-MAP] Inbound port forward rejected conn=%s: %s", connectionID, errMsg)
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        errMsg,
		})
		return
	}

	if targetEndpoint == "" {
		targetEndpoint = GetEffectiveEndpointName()
	}
	if sourceClient == "" {
		sourceClient = "unknown-source"
	}

	DebugLog("[PORT-MAP] Inbound port forward request conn=%s from=%s target_endpoint=%s remote_target=%s",
		connectionID, sourceClient, targetEndpoint, remoteTarget)

	backendConn, err := net.DialTimeout("tcp", remoteTarget, 8*time.Second)
	if err != nil {
		log.Printf("[PORT-MAP] Inbound connect failed conn=%s remote_target=%s: %v", connectionID, remoteTarget, err)
		_ = tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
			ConnectionID: connectionID,
			Success:      false,
			Error:        err.Error(),
		})
		return
	}

	storePortForwardConnection(connectionID, backendConn, PortMappingConfig{
		LocalListen:    "inbound",
		RemoteTarget:   remoteTarget,
		TargetEndpoint: targetEndpoint,
	}, fmt.Sprintf("APS -> %s -> %s", targetEndpoint, remoteTarget))

	if err := tc.SendJSON(MsgTypePortForwardResponse, PortForwardResponsePayload{
		ConnectionID: connectionID,
		Success:      true,
	}); err != nil {
		log.Printf("[PORT-MAP] Inbound response send failed conn=%s: %v", connectionID, err)
		removePortForwardConnection(connectionID)
		return
	}

	DebugLog("[PORT-MAP] Inbound port forward established conn=%s target_endpoint=%s remote_target=%s",
		connectionID, targetEndpoint, remoteTarget)

	// Start reading from backend and forwarding back to source endpoint.
	go startPortForwardReadLoop(tc, connectionID, backendConn)
}

// generateConnectionID generates a unique connection ID
func generateConnectionID() string {
	return fmt.Sprintf("pf-%d-%d", time.Now().UnixNano(), time.Now().Nanosecond())
}

// startPortForwardReadLoop starts reading from local connection and forwarding to tunnel
func startPortForwardReadLoop(tc *TunnelConn, connectionID string, localConn net.Conn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := localConn.Read(buf)
		if n > 0 {
			// Send data through tunnel
			if sendErr := tc.SendJSON(MsgTypePortForwardData, PortForwardDataPayload{
				ConnectionID: connectionID,
				Data:         buf[:n],
			}); sendErr != nil {
				log.Printf("[PORT-MAP] Failed to send data for %s: %v", connectionID, sendErr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[PORT-MAP] Read error for %s: %v", connectionID, err)
			}
			// Notify tunnel of close
			tc.SendJSON(MsgTypePortForwardClose, PortForwardClosePayload{
				ConnectionID: connectionID,
			})
			return
		}
	}
}

// PortForwardDataPayload carries port forward data
type PortForwardDataPayload struct {
	ConnectionID string `json:"connection_id"`
	Data         []byte `json:"data"`
}

// PortForwardClosePayload signals port forward close
type PortForwardClosePayload struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason,omitempty"`
}

// handlePortForwardResponse handles response to a port forward request
func handlePortForwardResponse(tc *TunnelConn, msg *TunnelMessage) {
	var payload PortForwardResponsePayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[PORT-MAP] Failed to parse port forward response: %v", err)
		return
	}

	pfc, ok := getPortForwardConnection(payload.ConnectionID)
	if !ok {
		DebugLog("[PORT-MAP] Connection %s not found for response", payload.ConnectionID)
		return
	}

	if !payload.Success {
		routeChain := strings.TrimSpace(pfc.RouteChain)
		if routeChain == "" {
			routeChain = buildPortForwardRouteChain(tc, pfc.Mapping)
		}
		log.Printf("[PORT-MAP] Port forward failed conn=%s route=\"%s\": %s", payload.ConnectionID, routeChain, payload.Error)
		removePortForwardConnection(payload.ConnectionID)
		return
	}

	routeChain := strings.TrimSpace(pfc.RouteChain)
	if routeChain == "" {
		routeChain = buildPortForwardRouteChain(tc, pfc.Mapping)
	}
	DebugLog("[PORT-MAP] Port forward established conn=%s route=\"%s\"", payload.ConnectionID, routeChain)

	// Start reading from local connection and forwarding to tunnel
	go startPortForwardReadLoop(tc, payload.ConnectionID, pfc.LocalConn)
}

// handlePortForwardDataMsg handles incoming data for port forwarded connections
func handlePortForwardDataMsg(msg *TunnelMessage) {
	var payload PortForwardDataPayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[PORT-MAP] Failed to parse port forward data: %v", err)
		return
	}

	handlePortForwardData(payload.ConnectionID, payload.Data)
}

// handlePortForwardCloseMsg handles close of port forwarded connections
func handlePortForwardCloseMsg(msg *TunnelMessage) {
	var payload PortForwardClosePayload
	if err := msg.ParseJSON(&payload); err != nil {
		log.Printf("[PORT-MAP] Failed to parse port forward close: %v", err)
		return
	}

	DebugLog("[PORT-MAP] Connection %s closed: %s", payload.ConnectionID, payload.Reason)
	handlePortForwardClose(payload.ConnectionID)
}
